//! Wire types shared by relay, agent and push. See docs/DESIGN.md
//! "Wire format rules": list elements are objects, unknown fields and
//! message types are ignored, enums fall back to a safe value.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    Updated,
    Unchanged,
    RolledBack,
    #[default]
    #[serde(other)]
    Failed,
}

impl Status {
    #[must_use]
    pub fn ok(self) -> bool {
        matches!(self, Status::Updated | Status::Unchanged)
    }

    /// Label for metrics, same spelling as on the wire.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Updated => "updated",
            Status::Unchanged => "unchanged",
            Status::RolledBack => "rolled-back",
            Status::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum JobState {
    Pending,
    Running,
    Done,
    #[default]
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Line {
    pub line: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Named {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRef {
    pub id: String,
    pub flakelet: String,
    pub state: JobState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayInfo {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DoneBody {
    pub status: Status,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tail: Option<Vec<Line>>,
}

/// Frames on `/v1/agent`, both directions in one enum keyed by `type`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Frame {
    Welcome {
        host: String,
        relay: RelayInfo,
    },
    Hello {
        version: String,
        #[serde(default)]
        capabilities: Vec<String>,
        flakelets: Vec<Named>,
        #[serde(default)]
        jobs: Vec<JobRef>,
    },
    Start {
        id: String,
        flakelet: String,
        rule: String,
        #[serde(default)]
        options: BTreeMap<String, Value>,
    },
    Ack {
        id: String,
        accepted: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    Log {
        id: String,
        seq: u64,
        line: String,
    },
    Progress {
        id: String,
    },
    Done {
        id: String,
        #[serde(flatten)]
        body: DoneBody,
    },
    Error {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        code: String,
        message: String,
    },
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Target {
    pub target: String,
}

impl Target {
    /// `host/flakelet`, validated at request time so later code can split
    /// without checking.
    #[must_use]
    pub fn split(&self) -> Option<(&str, &str)> {
        let (h, f) = self.target.split_once('/')?;
        (!h.is_empty() && !f.is_empty() && !f.contains('/')).then_some((h, f))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wave {
    pub targets: Vec<Target>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployRequest {
    pub id: String,
    pub waves: Vec<Wave>,
    #[serde(default)]
    pub options: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub host: String,
    pub version: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flakelets: Vec<Named>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetStatus {
    pub target: String,
    pub status: Status,
}

/// SSE events on `/v1/deploy` and `/v1/jobs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Event {
    Accepted {
        job: String,
        relay: RelayInfo,
        agents: Vec<AgentInfo>,
    },
    Wave {
        index: usize,
    },
    Log {
        target: String,
        seq: u64,
        line: String,
    },
    Progress {
        target: String,
    },
    Done {
        target: String,
        #[serde(flatten)]
        body: DoneBody,
    },
    Result {
        ok: bool,
        targets: Vec<TargetStatus>,
        skipped: Vec<Target>,
    },
    #[serde(other)]
    Unknown,
}

impl Event {
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Event::Accepted { .. } => "accepted",
            Event::Wave { .. } => "wave",
            Event::Log { .. } => "log",
            Event::Progress { .. } => "progress",
            Event::Done { .. } => "done",
            Event::Result { .. } => "result",
            Event::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<Target>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentsResponse {
    pub agents: Vec<AgentInfo>,
}

/// `hash(caller identity, client id)` so retries are idempotent and
/// other callers cannot attach to the job.
#[must_use]
pub fn job_id(caller: &str, client_id: &str) -> String {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(caller.as_bytes());
    ctx.update(b"\0");
    ctx.update(client_id.as_bytes());
    hex(&ctx.finish().as_ref()[..16])
}

#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[must_use]
pub fn random_id() -> String {
    let mut b = [0u8; 16];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b).expect("system rng");
    hex(&b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_frame_type_is_tolerated() {
        let f: Frame = serde_json::from_str(r#"{"type":"future","x":1}"#).unwrap();
        assert!(matches!(f, Frame::Unknown));
    }

    #[test]
    fn unknown_fields_and_status_are_tolerated() {
        let f: Frame =
            serde_json::from_str(r#"{"type":"done","id":"a","status":"exploded","extra":true}"#)
                .unwrap();
        let Frame::Done { body, .. } = f else {
            panic!()
        };
        assert_eq!(body.status, Status::Failed);
    }

    #[test]
    fn done_roundtrip_is_flat() {
        let s = serde_json::to_string(&Frame::Done {
            id: "j".into(),
            body: DoneBody {
                status: Status::RolledBack,
                generation: Some(3),
                tail: None,
            },
        })
        .unwrap();
        assert_eq!(
            s,
            r#"{"type":"done","id":"j","status":"rolled-back","generation":3}"#
        );
    }

    #[test]
    fn target_split_rejects_malformed() {
        for bad in ["", "a", "a/", "/b", "a/b/c"] {
            assert!(Target { target: bad.into() }.split().is_none(), "{bad}");
        }
        assert_eq!(
            Target {
                target: "eve/hub".into()
            }
            .split(),
            Some(("eve", "hub"))
        );
    }
}
