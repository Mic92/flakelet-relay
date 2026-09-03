//! Job table, dedup by id, coalescing of concurrent starts per flakelet,
//! and persistence so a restarted agent picks running units back up.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};

use crate::agent::exec::{self, Run};
use crate::proto::{DoneBody, Frame, JobRef, JobState, Status};

const LOG_CAP: usize = 1 << 20;
const KEEP: Duration = Duration::from_hours(24);

/// One `<id>.json` in the state directory. Logs are only written once
/// the job is done. A running job's output is re-read from the journal.
#[derive(Default, Serialize, Deserialize)]
struct Job {
    flakelet: String,
    state: JobState,
    created: u64,
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
    flakelets: Vec<String>,
    flakelet_cmd: PathBuf,
    dir: PathBuf,
    /// Live frames for all connections; each relay forwards what it has
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
    /// Load the table from `dir`, drop entries older than 24 h and resume
    /// what was pending or running.
    #[must_use]
    pub fn new(flakelets: Vec<String>, flakelet_cmd: PathBuf, dir: PathBuf) -> Arc<Self> {
        let _ = std::fs::create_dir_all(&dir);
        let mut jobs = HashMap::new();
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            let Some(id) = path.file_stem().and_then(|s| s.to_str()).map(str::to_owned) else {
                continue;
            };
            let job: Option<Job> = std::fs::read(&path)
                .ok()
                .and_then(|d| serde_json::from_slice(&d).ok());
            match job {
                Some(j) if j.created + KEEP.as_secs() > now() => {
                    jobs.insert(id, j);
                }
                _ => {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
        let this = Arc::new(Self {
            inner: Mutex::new(Inner {
                jobs,
                slots: HashMap::new(),
            }),
            flakelets,
            flakelet_cmd,
            dir,
            events: broadcast::channel(4096).0,
        });
        this.resume();
        this
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

    fn save(&self, inner: &Inner, id: &str) {
        let Some(job) = inner.jobs.get(id) else {
            return;
        };
        let data = serde_json::to_vec(job).expect("serializable");
        let path = self.dir.join(format!("{id}.json"));
        let tmp = path.with_extension("tmp");
        if let Err(e) = std::fs::write(&tmp, data).and_then(|()| std::fs::rename(&tmp, &path)) {
            tracing::warn!(id, "cannot persist job: {e}");
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Frame> {
        self.events.subscribe()
    }

    pub fn refs(&self) -> Vec<JobRef> {
        self.inner
            .lock()
            .expect("poisoned")
            .jobs
            .iter()
            .map(|(id, j)| JobRef {
                id: id.clone(),
                flakelet: j.flakelet.clone(),
                state: j.state,
            })
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
    pub fn start(self: &Arc<Self>, id: &str, flakelet: &str) -> Vec<Frame> {
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
                        j.done = Some(done.clone());
                    }
                    self.save(&inner, id);
                    let _ = self.events.send(Frame::Done {
                        id: id.clone(),
                        body: done.clone(),
                    });
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
