use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, mpsc};

use crate::auth::issuers::Issuers;
use crate::proto::{AgentInfo, Frame, JobRef, JobState, JobSummary, JobTarget, Named};
use crate::relay::config::Config;
use crate::relay::session::Signer;

/// An agent is considered alive if anything was read from it this
/// recently. Agents ping every 20 s.
const ALIVE: Duration = Duration::from_secs(45);

/// What the relay knows about one connected agent. Dropping `tx` closes
/// the connection's writer.
pub struct Agent {
    pub conn: u64,
    pub info: AgentInfo,
    /// The agent's job table as of `hello`, kept current by `job` frames.
    pub jobs: HashMap<String, JobRef>,
    pub tx: mpsc::Sender<Outgoing>,
    pub last_seen: Instant,
}

pub enum Outgoing {
    Frame(Frame),
    Pong(bytes::Bytes),
}

/// One target of a running deploy. Frames are tagged with its index in
/// the wave so all targets of a wave share one channel. `start` is kept
/// to re-send when the agent reconnects, which makes it replay.
pub struct Sub {
    pub index: usize,
    pub tx: mpsc::UnboundedSender<(usize, Frame)>,
    pub start: Frame,
}

/// One flakelet on one connected host with its most recent job.
pub struct HostFlakelet {
    pub host: String,
    pub flakelet: String,
    pub generation: Option<u64>,
    pub revision: Option<String>,
    pub last: Option<JobRef>,
}

pub struct Relay {
    pub cfg: Config,
    pub issuers: Issuers,
    pub signer: Signer,
    /// Ticks whenever what the dashboard shows may have changed.
    pub changed: broadcast::Sender<()>,
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
            signer: Signer::default(),
            changed: broadcast::channel(16).0,
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
        let _ = self.changed.send(());
        true
    }

    pub fn unregister(&self, host: &str, conn: u64) {
        let mut agents = self.agents.lock().expect("poisoned");
        if agents.get(host).is_some_and(|a| a.conn == conn) {
            agents.remove(host);
            let _ = self.changed.send(());
        }
    }

    pub fn seen(&self, host: &str, conn: u64) {
        if let Some(a) = self.agents.lock().expect("poisoned").get_mut(host)
            && a.conn == conn
        {
            a.last_seen = Instant::now();
        }
    }

    pub fn record_flakelets(&self, host: &str, conn: u64, flakelets: Vec<Named>) {
        let mut agents = self.agents.lock().expect("poisoned");
        if let Some(a) = agents.get_mut(host).filter(|a| a.conn == conn) {
            a.info.flakelets = flakelets;
            let _ = self.changed.send(());
        }
    }

    /// Apply a `job` frame from `host`: remember the entry and, once done,
    /// what the flakelet now runs.
    pub fn record_job(&self, host: &str, conn: u64, job: JobRef) {
        let mut agents = self.agents.lock().expect("poisoned");
        let Some(a) = agents.get_mut(host).filter(|a| a.conn == conn) else {
            return;
        };
        if job.state == JobState::Done
            && let Some(f) = a.info.flakelets.iter_mut().find(|f| f.name == job.flakelet)
        {
            if job.generation.is_some() {
                f.generation = job.generation;
            }
            if job.revision.is_some() {
                f.revision.clone_from(&job.revision);
            }
        }
        a.jobs.insert(job.id.clone(), job);
        let _ = self.changed.send(());
    }

    /// Hosts with an `agents` entry that `principals` may see but that
    /// are not connected.
    pub fn missing_hosts(&self, principals: &[String]) -> Vec<String> {
        let agents = self.agents.lock().expect("poisoned");
        self.cfg
            .policy
            .agents
            .keys()
            .filter(|h| !agents.contains_key(*h) && self.cfg.policy.sees_host(principals, h))
            .cloned()
            .collect()
    }

    /// Connected agents reduced to the flakelets `principals` may read.
    pub fn visible_agents(&self, principals: &[String]) -> Vec<AgentInfo> {
        self.agent_infos()
            .into_iter()
            .filter_map(|mut a| {
                a.flakelets.retain(|f| {
                    self.cfg
                        .policy
                        .rule_for(principals, &a.host, &f.name)
                        .is_some()
                });
                (!a.flakelets.is_empty()).then_some(a)
            })
            .collect()
    }

    /// Every (host, flakelet) `principals` may read, with its latest job.
    pub fn host_flakelets(&self, principals: &[String]) -> Vec<HostFlakelet> {
        let agents = self.agents.lock().expect("poisoned");
        let mut out = Vec::new();
        for (host, a) in agents.iter() {
            for f in &a.info.flakelets {
                if self
                    .cfg
                    .policy
                    .rule_for(principals, host, &f.name)
                    .is_none()
                {
                    continue;
                }
                let last = a
                    .jobs
                    .values()
                    .filter(|j| j.flakelet == f.name)
                    .max_by_key(|j| j.created)
                    .cloned();
                out.push(HostFlakelet {
                    host: host.clone(),
                    flakelet: f.name.clone(),
                    generation: f.generation,
                    revision: f.revision.clone(),
                    last,
                });
            }
        }
        out.sort_by(|a, b| (&a.flakelet, &a.host).cmp(&(&b.flakelet, &b.host)));
        out
    }

    /// The caller the agents recorded for `client_id`, if `principals`
    /// may read a target of it.
    pub fn job_caller(&self, principals: &[String], client_id: &str) -> Option<String> {
        let agents = self.agents.lock().expect("poisoned");
        agents.iter().find_map(|(host, a)| {
            a.jobs.values().find_map(|j| {
                (j.client_id.as_deref() == Some(client_id)
                    && self
                        .cfg
                        .policy
                        .rule_for(principals, host, &j.flakelet)
                        .is_some())
                .then(|| j.caller.clone())
                .flatten()
            })
        })
    }

    /// Deploys visible to `principals`, newest first, grouped across
    /// hosts by caller and client id.
    pub fn job_summaries(&self, principals: &[String]) -> Vec<JobSummary> {
        let agents = self.agents.lock().expect("poisoned");
        let mut by: HashMap<(&str, &str), JobSummary> = HashMap::new();
        for (host, a) in agents.iter() {
            for j in a.jobs.values() {
                let (Some(caller), Some(cid)) = (&j.caller, &j.client_id) else {
                    continue;
                };
                if self
                    .cfg
                    .policy
                    .rule_for(principals, host, &j.flakelet)
                    .is_none()
                {
                    continue;
                }
                let s = by.entry((caller, cid)).or_insert_with(|| JobSummary {
                    id: cid.clone(),
                    caller: caller.clone(),
                    caller_name: j.caller_name.clone().unwrap_or_default(),
                    created: j.created,
                    finished: j.finished,
                    targets: Vec::new(),
                });
                s.created = s.created.min(j.created);
                s.finished = s.finished.zip(j.finished).map(|(a, b)| a.max(b));
                s.targets.push(JobTarget {
                    target: format!("{host}/{}", j.flakelet),
                    state: j.state,
                    status: j.status,
                    generation: j.generation,
                });
            }
        }
        let mut out: Vec<_> = by.into_values().collect();
        for s in &mut out {
            s.targets.sort_by(|a, b| a.target.cmp(&b.target));
        }
        out.sort_by(|a, b| b.created.cmp(&a.created).then_with(|| a.id.cmp(&b.id)));
        out
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

    /// Hosts for `pattern/flakelet` that `principals` may deploy:
    /// connected agents advertising `flakelet`, and configured agents
    /// that are not connected at all (a connected host without the
    /// flakelet simply does not run it).
    pub fn expand(
        &self,
        principals: &[String],
        pattern: &str,
        flakelet: &str,
    ) -> (Vec<String>, Vec<String>) {
        let policy = &self.cfg.policy;
        let agents = self.agents.lock().expect("poisoned");
        let (mut live, mut offline) = (Vec::new(), Vec::new());
        for h in policy.agents.keys() {
            if !policy.host_matches(pattern, h)
                || policy.rule_for(principals, h, flakelet).is_none()
            {
                continue;
            }
            match agents.get(h) {
                Some(a) if a.info.flakelets.iter().any(|n| n.name == flakelet) => {
                    live.push(h.clone());
                }
                Some(_) => {}
                None => offline.push(h.clone()),
            }
        }
        (live, offline)
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
