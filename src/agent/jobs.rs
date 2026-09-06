//! Job table, dedup by id, coalescing of concurrent starts per flakelet,
//! and persistence so a restarted agent picks running units back up and
//! relays can list past deploys.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};

use crate::agent::config::Retention;
use crate::agent::exec::{self, Run};
use crate::proto::{DoneBody, Frame, JobRef, JobState, Named, Status};

const LOG_CAP: usize = 1 << 20;
/// Per flakelet in `hello`, newest first. Bounds relay memory no matter
/// how long agents keep history.
const ADVERTISE: usize = 50;

/// One `<id>.json` in the state directory. Logs are only written once
/// the job is done. A running job's output is re-read from the journal.
#[derive(Default, Serialize, Deserialize)]
struct Job {
    flakelet: String,
    state: JobState,
    created: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    finished: Option<u64>,
    caller: String,
    caller_name: String,
    client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    run: Option<Run>,
    #[serde(default)]
    logs: Vec<(u64, String)>,
    #[serde(skip)]
    log_bytes: usize,
    #[serde(skip)]
    truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    done: Option<DoneBody>,
}

impl Job {
    fn summary(&self, id: &str) -> JobRef {
        JobRef {
            id: id.to_owned(),
            flakelet: self.flakelet.clone(),
            state: self.state,
            caller: self.caller.clone(),
            caller_name: self.caller_name.clone(),
            client_id: self.client_id.clone(),
            created: self.created,
            finished: self.finished,
            status: self.done.as_ref().map(|d| d.status),
            generation: self.done.as_ref().and_then(|d| d.generation),
            revision: self.done.as_ref().and_then(|d| d.revision.clone()),
        }
    }
}

#[derive(Default)]
struct Slot {
    running: bool,
    /// Ids that arrived during the current run and get the next one.
    followup: Vec<String>,
}

struct Inner {
    jobs: HashMap<String, Job>,
    slots: HashMap<String, Slot>,
}

pub struct Jobs {
    inner: Mutex<Inner>,
    /// Last `flakelet status`, refreshed by `watch_flakelets`.
    described: Mutex<Vec<Named>>,
    flakelets: Vec<String>,
    flakelet_cmd: PathBuf,
    dir: PathBuf,
    retention: Retention,
    /// Live frames for all connections. Each relay forwards what it has
    /// subscribers for.
    events: broadcast::Sender<Frame>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl Jobs {
    /// Load the table from `dir`, apply retention and resume what was
    /// pending or running.
    #[must_use]
    pub fn new(
        flakelets: Vec<String>,
        flakelet_cmd: PathBuf,
        dir: PathBuf,
        retention: Retention,
    ) -> Arc<Self> {
        let _ = std::fs::create_dir_all(&dir);
        let mut jobs = HashMap::new();
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "json") {
                continue;
            }
            let Some(id) = path.file_stem().and_then(|s| s.to_str()).map(str::to_owned) else {
                continue;
            };
            match std::fs::read(&path)
                .ok()
                .and_then(|d| serde_json::from_slice::<Job>(&d).ok())
            {
                Some(j) => {
                    jobs.insert(id, j);
                }
                None => {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
        let this = Arc::new(Self {
            inner: Mutex::new(Inner {
                jobs,
                slots: HashMap::new(),
            }),
            described: Mutex::new(Vec::new()),
            flakelets,
            flakelet_cmd,
            dir,
            retention,
            events: broadcast::channel(4096).0,
        });
        this.prune();
        this.resume();
        this
    }

    /// Drop finished jobs past `keepJobsDays` or beyond `maxJobs` (oldest
    /// first) and strip logs past `keepLogsDays`. Runs at start and after
    /// every update.
    fn prune(&self) {
        const DAY: u64 = 86400;
        let now = now();
        let r = &self.retention;
        let mut inner = self.inner.lock().expect("poisoned");
        let mut done: Vec<(u64, String)> = inner
            .jobs
            .iter()
            .filter(|(_, j)| j.state == JobState::Done)
            .map(|(id, j)| (j.created, id.clone()))
            .collect();
        done.sort_unstable();
        let excess = inner.jobs.len().saturating_sub(r.max_jobs);
        for (i, (created, id)) in done.iter().enumerate() {
            if i < excess || created + r.keep_jobs_days * DAY <= now {
                inner.jobs.remove(id);
                let _ = std::fs::remove_file(self.dir.join(format!("{id}.json")));
            } else if created + r.keep_logs_days * DAY <= now
                && let Some(j) = inner.jobs.get_mut(id)
                && !j.logs.is_empty()
            {
                j.logs.clear();
                j.truncated = true;
                self.save(&inner, id);
            }
        }
    }

    fn resume(self: &Arc<Self>) {
        let mut runs: HashMap<String, (Vec<String>, Option<Run>)> = HashMap::new();
        {
            let mut inner = self.inner.lock().expect("poisoned");
            let Inner { jobs, slots } = &mut *inner;
            for (id, j) in jobs.iter() {
                let slot = slots.entry(j.flakelet.clone()).or_default();
                match j.state {
                    JobState::Running => {
                        slot.running = true;
                        let r = runs.entry(j.flakelet.clone()).or_default();
                        r.0.push(id.clone());
                        r.1.clone_from(&j.run);
                    }
                    JobState::Pending => slot.followup.push(id.clone()),
                    _ => {}
                }
            }
            for (flakelet, slot) in slots.iter_mut() {
                if !slot.running && !slot.followup.is_empty() {
                    slot.running = true;
                    runs.insert(flakelet.clone(), (std::mem::take(&mut slot.followup), None));
                }
            }
        }
        for (flakelet, (ids, run)) in runs {
            self.spawn_run(flakelet, ids, run);
        }
    }

    /// Persist `id` and tell connected relays about its new state.
    fn save(&self, inner: &Inner, id: &str) {
        let Some(job) = inner.jobs.get(id) else {
            return;
        };
        let _ = self.events.send(Frame::Job {
            job: job.summary(id),
        });
        let data = serde_json::to_vec(job).expect("serializable");
        let path = self.dir.join(format!("{id}.json"));
        let tmp = path.with_extension("tmp");
        if let Err(e) = std::fs::write(&tmp, data).and_then(|()| std::fs::rename(&tmp, &path)) {
            tracing::warn!(id, "cannot persist job: {e}");
        }
    }

    /// Current generation and revision of every allowlisted flakelet,
    /// as of the last `refresh`.
    pub fn describe(&self) -> Vec<Named> {
        self.described.lock().expect("poisoned").clone()
    }

    /// Re-run `flakelet status`; broadcasts `flakelets` when it changed.
    pub async fn refresh(&self) -> bool {
        let mut out = Vec::with_capacity(self.flakelets.len());
        for f in &self.flakelets {
            out.push(exec::describe(&self.flakelet_cmd, f).await);
        }
        let mut d = self.described.lock().expect("poisoned");
        if *d == out {
            return false;
        }
        d.clone_from(&out);
        drop(d);
        let _ = self.events.send(Frame::Flakelets { flakelets: out });
        true
    }

    /// Poll `flakelet status` so relays see updates that did not go
    /// through them (auto-update timer, manual runs, host activation).
    pub async fn watch_flakelets(self: Arc<Self>, every: std::time::Duration) {
        let mut tick = tokio::time::interval(every);
        loop {
            tick.tick().await;
            self.refresh().await;
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Frame> {
        self.events.subscribe()
    }

    /// Newest `ADVERTISE` jobs per flakelet plus anything not done.
    pub fn refs(&self) -> Vec<JobRef> {
        let inner = self.inner.lock().expect("poisoned");
        let mut all: Vec<_> = inner.jobs.iter().collect();
        all.sort_unstable_by_key(|(_, j)| std::cmp::Reverse(j.created));
        let mut per: HashMap<&str, usize> = HashMap::new();
        all.into_iter()
            .filter(|(_, j)| {
                let n = per.entry(&j.flakelet).or_default();
                *n += 1;
                *n <= ADVERTISE || j.state != JobState::Done
            })
            .map(|(id, j)| j.summary(id))
            .collect()
    }

    /// Ack plus everything known so far for `id`, or `None` if unknown.
    pub fn replay(&self, id: &str) -> Option<Vec<Frame>> {
        let inner = self.inner.lock().expect("poisoned");
        inner.jobs.get(id).map(|j| Self::frames(id, j))
    }

    fn frames(id: &str, j: &Job) -> Vec<Frame> {
        let mut out = vec![Frame::Ack {
            id: id.to_owned(),
            accepted: true,
            reason: None,
        }];
        out.extend(j.logs.iter().map(|(seq, line)| Frame::Log {
            id: id.to_owned(),
            seq: *seq,
            line: line.clone(),
        }));
        if let Some(d) = &j.done {
            out.push(Frame::Done {
                id: id.to_owned(),
                body: d.clone(),
            });
        }
        out
    }

    /// Handle `start`, returning the frames to send on this connection.
    /// Known id: replay. Idle flakelet: run now. Busy: queue for one
    /// follow-up run.
    pub fn start(
        self: &Arc<Self>,
        id: &str,
        flakelet: &str,
        caller: String,
        caller_name: String,
        client_id: String,
    ) -> Vec<Frame> {
        let refuse = |reason: &str| {
            vec![Frame::Ack {
                id: id.to_owned(),
                accepted: false,
                reason: Some(reason.into()),
            }]
        };
        if !self.flakelets.iter().any(|f| f == flakelet) {
            return refuse("flakelet not in agent allowlist");
        }
        let mut inner = self.inner.lock().expect("poisoned");
        if let Some(j) = inner.jobs.get(id) {
            if j.flakelet != flakelet {
                return refuse("id already used for another flakelet");
            }
            return Self::frames(id, j);
        }
        inner.jobs.insert(
            id.to_owned(),
            Job {
                flakelet: flakelet.to_owned(),
                state: JobState::Pending,
                created: now(),
                caller,
                caller_name,
                client_id,
                ..Default::default()
            },
        );
        self.save(&inner, id);
        let slot = inner.slots.entry(flakelet.to_owned()).or_default();
        if slot.running {
            slot.followup.push(id.to_owned());
        } else {
            slot.running = true;
            drop(inner);
            self.spawn_run(flakelet.to_owned(), vec![id.to_owned()], None);
        }
        vec![Frame::Ack {
            id: id.to_owned(),
            accepted: true,
            reason: None,
        }]
    }

    fn spawn_run(self: &Arc<Self>, flakelet: String, ids: Vec<String>, reattach: Option<Run>) {
        let this = self.clone();
        tokio::spawn(async move { this.run(flakelet, ids, reattach).await });
    }

    async fn run(
        self: Arc<Self>,
        flakelet: String,
        mut ids: Vec<String>,
        mut reattach: Option<Run>,
    ) {
        loop {
            let (log_tx, mut log_rx) = mpsc::unbounded_channel::<String>();
            let started = if let Some(run) = reattach.take() {
                tracing::info!(flakelet, ?ids, "reattaching to running unit");
                Ok(run)
            } else {
                tracing::info!(flakelet, ?ids, "update starting");
                let run = exec::prepare(&self.flakelet_cmd, &flakelet).await;
                {
                    let mut inner = self.inner.lock().expect("poisoned");
                    for id in &ids {
                        if let Some(j) = inner.jobs.get_mut(id) {
                            j.state = JobState::Running;
                            j.run = Some(run.clone());
                        }
                        self.save(&inner, id);
                    }
                }
                exec::start(&self.flakelet_cmd, &flakelet)
                    .await
                    .map(|()| run)
            };
            let mut seq = 0u64;
            let done = match started {
                Err(e) => {
                    seq += 1;
                    self.record_log(&ids, seq, &format!("flakelet-agent: {e}"));
                    DoneBody {
                        status: Status::Failed,
                        ..Default::default()
                    }
                }
                Ok(run) => {
                    let finish = exec::finish(&self.flakelet_cmd, &flakelet, &run, log_tx);
                    tokio::pin!(finish);
                    let mut progress = tokio::time::interval(Duration::from_secs(30));
                    progress.tick().await;
                    loop {
                        tokio::select! {
                            d = &mut finish => break d,
                            Some(line) = log_rx.recv() => {
                                seq += 1;
                                self.record_log(&ids, seq, &line);
                            }
                            _ = progress.tick() => {
                                for id in &ids {
                                    let _ = self.events.send(Frame::Progress { id: id.clone() });
                                }
                            }
                        }
                    }
                }
            };
            while let Ok(line) = log_rx.try_recv() {
                seq += 1;
                self.record_log(&ids, seq, &line);
            }
            tracing::info!(flakelet, status = ?done.status, generation = ?done.generation, "update finished");
            let next = {
                let mut inner = self.inner.lock().expect("poisoned");
                for id in &ids {
                    if let Some(j) = inner.jobs.get_mut(id) {
                        j.state = JobState::Done;
                        j.finished = Some(now());
                        j.done = Some(done.clone());
                    }
                    let _ = self.events.send(Frame::Done {
                        id: id.clone(),
                        body: done.clone(),
                    });
                    self.save(&inner, id);
                }
                let slot = inner
                    .slots
                    .get_mut(&flakelet)
                    .expect("slot exists while running");
                let next = std::mem::take(&mut slot.followup);
                if next.is_empty() {
                    slot.running = false;
                }
                next
            };
            if next.is_empty() {
                self.prune();
                self.refresh().await;
                return;
            }
            ids = next;
        }
    }

    fn record_log(&self, ids: &[String], seq: u64, line: &str) {
        let mut inner = self.inner.lock().expect("poisoned");
        for id in ids {
            let Some(j) = inner.jobs.get_mut(id) else {
                continue;
            };
            if j.truncated {
                continue;
            }
            let line = if j.log_bytes + line.len() > LOG_CAP {
                j.truncated = true;
                "[flakelet-agent: log limit reached, further output dropped]".to_owned()
            } else {
                j.log_bytes += line.len();
                line.to_owned()
            };
            j.logs.push((seq, line.clone()));
            let _ = self.events.send(Frame::Log {
                id: id.clone(),
                seq,
                line,
            });
        }
    }
}
