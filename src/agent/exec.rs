//! Run `flakelet update <name>` as a transient unit and follow its journal.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use serde::Deserialize;
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

#[must_use]
pub fn unit_name(flakelet: &str) -> String {
    format!("flakelet-relay-job-{flakelet}.service")
}

/// Runs the update to completion, streaming output lines into `log`.
pub async fn update(
    flakelet_cmd: &Path,
    flakelet: &str,
    log: mpsc::UnboundedSender<String>,
) -> DoneBody {
    let before = status(flakelet_cmd, flakelet)
        .await
        .and_then(|s| s.generation);
    let unit = unit_name(flakelet);

    let mut journal = match Command::new("journalctl")
        .args([
            "--unit",
            &unit,
            "--follow",
            "--lines=0",
            "--output=cat",
            "--no-pager",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = log.send(format!("flakelet-agent: cannot follow journal: {e}"));
            return DoneBody {
                status: Status::Failed,
                ..Default::default()
            };
        }
    };
    let stdout = journal.stdout.take().expect("piped");
    let follower = tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(l)) = lines.next_line().await {
            if log.send(l).is_err() {
                break;
            }
        }
        log
    });
    // journalctl prints nothing until it is attached, so give it a moment
    // before the unit starts producing output.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let run = Command::new("systemd-run")
        .args(["--quiet", "--wait", "--collect", "--service-type=exec"])
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
        .await;

    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = journal.start_kill();
    let _ = journal.wait().await;
    let log = follower.await.expect("follower does not panic");

    let unit_ok = match run {
        Ok(o) if o.status.success() => true,
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            for l in err.lines().filter(|l| !l.is_empty()) {
                let _ = log.send(format!("systemd-run: {l}"));
            }
            false
        }
        Err(e) => {
            let _ = log.send(format!("flakelet-agent: cannot run systemd-run: {e}"));
            false
        }
    };

    let after = status(flakelet_cmd, flakelet).await;
    let generation = after.as_ref().and_then(|s| s.generation);
    let status = if unit_ok {
        if generation == before {
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
