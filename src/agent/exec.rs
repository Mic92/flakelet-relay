//! Run `flakelet update <name>` as a transient unit and follow its journal.
//!
//! The unit outlives the agent, so a run is split into `prepare` (journal
//! cursor and generation before), `start` and `finish` (follow the
//! journal from the cursor until the unit is gone, then derive the
//! result). A restarted agent calls `finish` again with the saved `Run`.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt as _, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

use crate::proto::{DoneBody, Line, Status};

#[derive(Debug, Deserialize, Default)]
struct FlakeletStatus {
    name: String,
    #[serde(default)]
    generation: Option<u64>,
    #[serde(default)]
    held: Option<String>,
    #[serde(default)]
    unit_states: Vec<UnitState>,
}

#[derive(Debug, Deserialize)]
struct UnitState {
    unit: String,
}

/// What `finish` needs to pick up a run, persisted by the job table.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Run {
    pub cursor: Option<String>,
    pub before: Option<u64>,
}

async fn status(flakelet_cmd: &Path, name: &str) -> Option<FlakeletStatus> {
    let out = Command::new(flakelet_cmd)
        .args(["status", "--json", name])
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .await
        .ok()?;
    let all: Vec<FlakeletStatus> = serde_json::from_slice(&out.stdout).ok()?;
    all.into_iter().find(|s| s.name == name)
}

async fn systemctl(args: &[&str]) -> String {
    match Command::new("systemctl")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .await
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_owned(),
        Err(_) => String::new(),
    }
}

#[must_use]
pub fn unit_name(flakelet: &str) -> String {
    format!("flakelet-relay-job-{flakelet}.service")
}

pub async fn unit_active(flakelet: &str) -> bool {
    let s = systemctl(&["is-active", &unit_name(flakelet)]).await;
    matches!(
        s.as_str(),
        "active" | "activating" | "deactivating" | "reloading"
    )
}

pub async fn prepare(flakelet_cmd: &Path, flakelet: &str) -> Run {
    let cursor = Command::new("journalctl")
        .args(["--lines=0", "--show-cursor", "--quiet", "--no-pager"])
        .stdin(Stdio::null())
        .output()
        .await
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .find_map(|l| l.strip_prefix("-- cursor: ").map(str::to_owned))
        });
    let before = status(flakelet_cmd, flakelet)
        .await
        .and_then(|s| s.generation);
    Run { cursor, before }
}

/// Start the unit. Returns once systemd has forked it.
pub async fn start(flakelet_cmd: &Path, flakelet: &str) -> Result<(), String> {
    let unit = unit_name(flakelet);
    // A failed earlier run stays loaded and would block the name.
    systemctl(&["reset-failed", &unit]).await;
    let out = Command::new("systemd-run")
        .args(["--quiet", "--service-type=exec"])
        .arg(format!("--unit={unit}"))
        .arg(format!(
            "--description=flakelet update {flakelet} (via relay)"
        ))
        .arg("--")
        .arg(flakelet_cmd)
        .args(["update", flakelet])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("cannot run systemd-run: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "systemd-run: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Follow the unit's journal from `run.cursor` into `log` until the unit
/// stopped, then derive the result.
pub async fn finish(
    flakelet_cmd: &Path,
    flakelet: &str,
    run: &Run,
    log: mpsc::UnboundedSender<String>,
) -> DoneBody {
    let unit = unit_name(flakelet);
    let mut journal = Command::new("journalctl");
    journal
        .args([
            "--unit",
            &unit,
            "--follow",
            "--output=cat",
            "--no-pager",
            "--quiet",
        ])
        .arg(match &run.cursor {
            Some(c) => format!("--after-cursor={c}"),
            None => "--lines=0".into(),
        })
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    let follower = match journal.spawn() {
        Ok(mut child) => {
            let stdout = child.stdout.take().expect("piped");
            Some((
                child,
                tokio::spawn(async move {
                    let mut lines = BufReader::new(stdout).lines();
                    while let Ok(Some(l)) = lines.next_line().await {
                        if log.send(l).is_err() {
                            break;
                        }
                    }
                }),
            ))
        }
        Err(e) => {
            let _ = log.send(format!("flakelet-agent: cannot follow journal: {e}"));
            None
        }
    };

    while unit_active(flakelet).await {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let unit_ok = systemctl(&["is-failed", &unit]).await != "failed";
    if let Some((mut child, task)) = follower {
        // Let journalctl catch up on the last lines before stopping it.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let _ = child.start_kill();
        let _ = child.wait().await;
        let _ = task.await;
    }

    let after = status(flakelet_cmd, flakelet).await;
    let generation = after.as_ref().and_then(|s| s.generation);
    let status = if unit_ok {
        if generation == run.before {
            Status::Unchanged
        } else {
            Status::Updated
        }
    } else if after.as_ref().is_some_and(|s| s.held.is_some()) {
        Status::RolledBack
    } else {
        Status::Failed
    };
    let tail = if status.ok() {
        None
    } else {
        let units: Vec<String> = after
            .map(|s| s.unit_states.into_iter().map(|u| u.unit).collect())
            .unwrap_or_default();
        journal_tail(&units).await
    };
    DoneBody {
        status,
        generation,
        tail,
    }
}

async fn journal_tail(units: &[String]) -> Option<Vec<Line>> {
    if units.is_empty() {
        return None;
    }
    let mut cmd = Command::new("journalctl");
    cmd.args(["--lines=50", "--output=cat", "--no-pager"]);
    for u in units {
        cmd.arg(format!("--unit={u}"));
    }
    let out = cmd
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .await
        .ok()?;
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| Line { line: l.to_owned() })
            .collect(),
    )
}
