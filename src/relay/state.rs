use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::auth::issuers::Issuers;
use crate::proto::{AgentInfo, Frame};
use crate::relay::config::Config;

/// An agent is considered alive if anything was read from it this
/// recently. Agents ping every 20 s.
const ALIVE: Duration = Duration::from_secs(45);

/// What the relay knows about one connected agent. Dropping `tx` closes
/// the connection's writer.
pub struct Agent {
    pub conn: u64,
    pub info: AgentInfo,
    pub tx: mpsc::Sender<Outgoing>,
    pub last_seen: Instant,
}

pub enum Outgoing {
    Frame(Frame),
    Pong(Vec<u8>),
}

/// One target of a running deploy. Frames are tagged with its index in
/// the wave so all targets of a wave share one channel. `start` is kept
/// to re-send when the agent reconnects, which makes it replay.
pub struct Sub {
    pub index: usize,
    pub tx: mpsc::UnboundedSender<(usize, Frame)>,
    pub start: Frame,
}

pub struct Relay {
    pub cfg: Config,
    pub issuers: Issuers,
    agents: Mutex<HashMap<String, Agent>>,
    /// (host, agent job id) → subscriber. Lives here rather than on the
    /// connection so a reconnecting agent's late `done` still arrives.
    subs: Mutex<HashMap<(String, String), Sub>>,
    next_conn: AtomicU64,
    deploys: Mutex<BTreeMap<[String; 4], u64>>,
}

impl Relay {
    pub fn new(cfg: Config, issuers: Issuers) -> Self {
        Self {
            cfg,
            issuers,
            agents: Mutex::default(),
            subs: Mutex::default(),
            next_conn: AtomicU64::new(0),
            deploys: Mutex::default(),
        }
    }

    pub fn conn_id(&self) -> u64 {
        self.next_conn.fetch_add(1, Ordering::Relaxed)
    }

    /// Register unless a connection for `host` exists that was heard
    /// from recently. Returns false on conflict.
    pub fn register(&self, host: &str, agent: Agent) -> bool {
        let mut agents = self.agents.lock().expect("poisoned");
        if let Some(old) = agents.get(host) {
            if old.last_seen.elapsed() < ALIVE {
                return false;
            }
            tracing::warn!(host, "replacing silent agent connection");
        }
        agents.insert(host.to_owned(), agent);
        true
    }

    pub fn unregister(&self, host: &str, conn: u64) {
        let mut agents = self.agents.lock().expect("poisoned");
        if agents.get(host).is_some_and(|a| a.conn == conn) {
            agents.remove(host);
        }
    }

    pub fn seen(&self, host: &str, conn: u64) {
        if let Some(a) = self.agents.lock().expect("poisoned").get_mut(host)
            && a.conn == conn
        {
            a.last_seen = Instant::now();
        }
    }

    pub fn agent_tx(&self, host: &str) -> Option<mpsc::Sender<Outgoing>> {
        self.agents
            .lock()
            .expect("poisoned")
            .get(host)
            .map(|a| a.tx.clone())
    }

    pub fn agent_infos(&self) -> Vec<AgentInfo> {
        let mut v: Vec<_> = self
            .agents
            .lock()
            .expect("poisoned")
            .values()
            .map(|a| a.info.clone())
            .collect();
        v.sort_by(|a, b| a.host.cmp(&b.host));
        v
    }

    pub fn has_flakelet(&self, host: &str, flakelet: &str) -> bool {
        self.agents
            .lock()
            .expect("poisoned")
            .get(host)
            .is_some_and(|a| a.info.flakelets.iter().any(|n| n.name == flakelet))
    }

    pub fn subscribe(&self, host: &str, id: &str, sub: Sub) {
        self.subs
            .lock()
            .expect("poisoned")
            .insert((host.to_owned(), id.to_owned()), sub);
    }

    pub fn unsubscribe(&self, host: &str, id: &str) {
        self.subs
            .lock()
            .expect("poisoned")
            .remove(&(host.to_owned(), id.to_owned()));
    }

    /// `start` frames of deploys still waiting on `host`.
    pub fn pending_starts(&self, host: &str) -> Vec<Frame> {
        let subs = self.subs.lock().expect("poisoned");
        subs.iter()
            .filter(|((h, _), _)| h == host)
            .map(|(_, s)| s.start.clone())
            .collect()
    }

    /// Route a job-scoped frame from `host` to whoever waits for it.
    pub fn dispatch(&self, host: &str, id: &str, frame: Frame) {
        let key = (host.to_owned(), id.to_owned());
        let mut subs = self.subs.lock().expect("poisoned");
        if let Some(s) = subs.get(&key)
            && s.tx.send((s.index, frame)).is_err()
        {
            subs.remove(&key);
        }
    }

    pub fn count_deploy(&self, rule: &str, host: &str, flakelet: &str, status: &str) {
        *self
            .deploys
            .lock()
            .expect("poisoned")
            .entry([rule.into(), host.into(), flakelet.into(), status.into()])
            .or_default() += 1;
    }

    pub fn metrics(&self) -> String {
        let mut out = String::new();
        out.push_str("# TYPE flakelet_relay_agent_up gauge\n");
        for host in self.cfg.policy.agents.keys() {
            let up = u8::from(self.agents.lock().expect("poisoned").contains_key(host));
            let _ = writeln!(out, "flakelet_relay_agent_up{{host=\"{host}\"}} {up}");
        }
        out.push_str("# TYPE flakelet_relay_agent_info gauge\n");
        for a in self.agent_infos() {
            let _ = writeln!(
                out,
                "flakelet_relay_agent_info{{host=\"{}\",version=\"{}\"}} 1",
                a.host, a.version
            );
        }
        out.push_str("# TYPE flakelet_relay_deploys_total counter\n");
        for ([rule, host, flakelet, status], n) in self.deploys.lock().expect("poisoned").iter() {
            let _ = writeln!(
                out,
                "flakelet_relay_deploys_total{{rule=\"{rule}\",host=\"{host}\",flakelet=\"{flakelet}\",status=\"{status}\"}} {n}"
            );
        }
        out
    }
}
