//! Job table, dedup by id, and coalescing of concurrent starts per flakelet.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{broadcast, mpsc};

use crate::agent::exec;
use crate::proto::{DoneBody, Frame, JobRef, JobState};

const LOG_CAP: usize = 1 << 20;

#[derive(Default)]
struct Job {
    flakelet: String,
    state: JobState,
    logs: Vec<(u64, String)>,
    log_bytes: usize,
    truncated: bool,
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
    /// Live frames for all connections; each relay forwards what it has
    /// subscribers for.
    events: broadcast::Sender<Frame>,
}

impl Jobs {
    #[must_use]
    pub fn new(flakelets: Vec<String>, flakelet_cmd: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                jobs: HashMap::new(),
                slots: HashMap::new(),
            }),
            flakelets,
            flakelet_cmd,
            events: broadcast::channel(4096).0,
        })
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

    /// Handle `start`, returning the ack and, for a known id, the replay
    /// to send on this connection. Idle flakelet: run now. Busy: queue
    /// for one follow-up run.
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
        let ack = Frame::Ack {
            id: id.to_owned(),
            accepted: true,
            reason: None,
        };
        let mut inner = self.inner.lock().expect("poisoned");
        if let Some(j) = inner.jobs.get(id) {
            if j.flakelet != flakelet {
                return refuse("id already used for another flakelet");
            }
            let mut out = vec![ack];
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
            return out;
        }
        inner.jobs.insert(
            id.to_owned(),
            Job {
                flakelet: flakelet.to_owned(),
                state: JobState::Pending,
                ..Default::default()
            },
        );
        let slot = inner.slots.entry(flakelet.to_owned()).or_default();
        if slot.running {
            slot.followup.push(id.to_owned());
        } else {
            slot.running = true;
            drop(inner);
            self.spawn_run(flakelet.to_owned(), vec![id.to_owned()]);
        }
        vec![ack]
    }

    fn spawn_run(self: &Arc<Self>, flakelet: String, ids: Vec<String>) {
        let this = self.clone();
        tokio::spawn(async move { this.run(flakelet, ids).await });
    }

    async fn run(self: Arc<Self>, flakelet: String, mut ids: Vec<String>) {
        loop {
            tracing::info!(flakelet, ?ids, "update starting");
            {
                let mut inner = self.inner.lock().expect("poisoned");
                for id in &ids {
                    if let Some(j) = inner.jobs.get_mut(id) {
                        j.state = JobState::Running;
                    }
                }
            }
            let (log_tx, mut log_rx) = mpsc::unbounded_channel::<String>();
            let exec = exec::update(&self.flakelet_cmd, &flakelet, log_tx);
            tokio::pin!(exec);
            let mut progress = tokio::time::interval(Duration::from_secs(30));
            progress.tick().await;
            let mut seq = 0u64;
            let done = loop {
                tokio::select! {
                    d = &mut exec => break d,
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
