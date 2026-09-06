//! Client-facing endpoints: deploy, agents, metrics.

use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use tokio::sync::mpsc;

use crate::auth::issuers::Identity;
use crate::auth::x509;
use crate::http::{self, Body, Resp};
use crate::proto::{
    AgentsResponse, ApiError, DeployRequest, DoneBody, Event, Frame, JobsResponse, RelayInfo,
    Status, Target, TargetStatus, job_id,
};
use crate::relay::state::{Outgoing, Relay, Sub};
use crate::relay::{agent_conn, login, ui};
use crate::{proto, sse};

/// `peer` are the principals proven by the transport (client cert SANs).
pub async fn handle(relay: Arc<Relay>, peer: Vec<String>, req: Request<Incoming>) -> Resp {
    let r = match (req.method(), req.uri().path()) {
        (&Method::GET, "/v1/agent") => agent_conn::upgrade(relay, peer, req).await,
        (&Method::POST, "/v1/deploy") => deploy(relay, peer, req).await,
        (&Method::GET, "/v1/agents") => agents(&relay, peer, &req).await,
        (&Method::GET, "/v1/jobs") => job_list(&relay, peer, &req).await,
        (&Method::GET, p) if p.starts_with("/v1/jobs/") => {
            jobs(relay.clone(), peer, &req, &p["/v1/jobs/".len()..]).await
        }
        (&Method::GET, "/metrics") => Ok(http::text(StatusCode::OK, relay.metrics())),
        (&Method::GET, "/health") => Ok(http::text(StatusCode::OK, String::from("ok\n"))),
        (_, p) if p.starts_with("/ui/") => Ok(ui::handle(relay, req).await),
        (&Method::GET, "/" | "/ui") => Ok(Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(hyper::header::LOCATION, "/ui/")
            .body(Body::empty())
            .expect("static headers")),
        _ => Err(http::error(
            StatusCode::NOT_FOUND,
            "not_found",
            "no such endpoint",
        )),
    };
    r.unwrap_or_else(|e| e)
}

/// Transport principals plus those from a bearer token or dashboard
/// session. Empty is 401.
pub async fn identify(
    relay: &Relay,
    peer: Vec<String>,
    req: &Request<Incoming>,
) -> Result<Identity, Resp> {
    let mut id = x509::identity(peer);
    let mut reason = String::from("no credentials");
    if let Some(s) = login::current(relay, req) {
        id.merge(s.who);
    }
    if let Some(tok) = http::bearer(req) {
        match relay.issuers.identify(tok).await {
            Ok(i) => id.merge(i),
            Err(e) => {
                tracing::info!("bearer rejected: {e}");
                reason = e;
            }
        }
    }
    if id.principals.is_empty() {
        return Err(http::error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            reason,
        ));
    }
    id.principals.sort();
    id.principals.dedup();
    Ok(id)
}

pub async fn authenticate(
    relay: &Relay,
    peer: Vec<String>,
    req: &Request<Incoming>,
) -> Result<Vec<String>, Resp> {
    identify(relay, peer, req).await.map(|i| i.principals)
}

async fn agents(relay: &Relay, peer: Vec<String>, req: &Request<Incoming>) -> Result<Resp, Resp> {
    let principals = authenticate(relay, peer, req).await?;
    let agents = relay.visible_agents(&principals);
    Ok(http::json(StatusCode::OK, &AgentsResponse { agents }))
}

async fn job_list(relay: &Relay, peer: Vec<String>, req: &Request<Incoming>) -> Result<Resp, Resp> {
    let principals = authenticate(relay, peer, req).await?;
    let jobs = relay.job_summaries(&principals);
    Ok(http::json(StatusCode::OK, &JobsResponse { jobs }))
}

#[derive(Clone)]
struct Planned {
    target: String,
    host: String,
    flakelet: String,
    rule: String,
    /// Came from a host pattern and the agent is not connected. Reported
    /// in the result instead of rejecting the request.
    offline: bool,
}

fn is_pattern(host: &str) -> bool {
    host.contains('*') || host.starts_with('@')
}

/// Turn `pattern/flakelet` targets into one `Planned` per matching host
/// and drop targets an earlier wave already covers, so `eve/x --wave
/// '*/x'` means eve first, then the rest.
fn expand(relay: &Relay, principals: &[String], dr: &DeployRequest) -> Vec<Vec<Planned>> {
    let mut seen = std::collections::HashSet::new();
    dr.waves
        .iter()
        .map(|w| {
            let mut out = Vec::new();
            for t in &w.targets {
                let (host, flakelet) = t.split().unwrap_or(("", ""));
                let hosts = if is_pattern(host) {
                    let (live, offline) = relay.expand(principals, host, flakelet);
                    live.into_iter()
                        .map(|h| (h, false))
                        .chain(offline.into_iter().map(|h| (h, true)))
                        .collect()
                } else {
                    vec![(host.to_owned(), false)]
                };
                for (h, offline) in hosts {
                    let target = if is_pattern(host) {
                        format!("{h}/{flakelet}")
                    } else {
                        t.target.clone()
                    };
                    if !seen.insert(target.clone()) {
                        continue;
                    }
                    let rule = relay
                        .cfg
                        .policy
                        .rule_for(principals, &h, flakelet)
                        .unwrap_or("");
                    out.push(Planned {
                        target,
                        host: h,
                        flakelet: flakelet.into(),
                        rule: rule.into(),
                        offline,
                    });
                }
            }
            out
        })
        .collect()
}

fn api_error(code: &str, message: &str, targets: &[&Planned]) -> ApiError {
    let targets = targets
        .iter()
        .map(|p| Target {
            target: p.target.clone(),
        })
        .collect();
    ApiError {
        code: code.into(),
        message: message.into(),
        targets,
    }
}

type Check = (
    StatusCode,
    &'static str,
    &'static str,
    Option<&'static str>,
    fn(&Relay, &Planned) -> bool,
);

/// Per-target checks in order. The first one any target fails rejects
/// the whole request with that class. Policy comes before existence so
/// callers cannot probe for host names.
const CHECKS: [Check; 4] = [
    (
        StatusCode::BAD_REQUEST,
        "bad_target",
        "targets must be host/flakelet",
        None,
        |_, p| p.host.is_empty(),
    ),
    (
        StatusCode::FORBIDDEN,
        "target_denied",
        "not allowed by policy",
        Some("denied"),
        |_, p| p.rule.is_empty(),
    ),
    (
        StatusCode::NOT_FOUND,
        "unknown_host",
        "no such host in relay configuration",
        None,
        |r, p| !r.cfg.policy.agents.contains_key(&p.host),
    ),
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "agent_unavailable",
        "agent not connected or flakelet not advertised",
        Some("unavailable"),
        |r, p| !p.offline && !r.has_flakelet(&p.host, &p.flakelet),
    ),
];

fn plan(
    relay: &Relay,
    principals: &[String],
    dr: &DeployRequest,
) -> Result<Vec<Vec<Planned>>, (StatusCode, ApiError)> {
    if dr.id.is_empty() || dr.waves.iter().all(|w| w.targets.is_empty()) {
        return Err((
            StatusCode::BAD_REQUEST,
            api_error("bad_request", "id and targets required", &[]),
        ));
    }
    if let Some(k) = dr.options.keys().next() {
        let msg = format!("no agent supports option {k}");
        return Err((
            StatusCode::BAD_REQUEST,
            api_error("unsupported_option", &msg, &[]),
        ));
    }
    let waves = expand(relay, principals, dr);
    if waves.iter().all(Vec::is_empty) {
        return Err((
            StatusCode::NOT_FOUND,
            api_error("no_targets", "pattern matched no host you may deploy", &[]),
        ));
    }
    for (status, code, message, metric, failed) in CHECKS {
        let hit: Vec<_> = waves
            .iter()
            .flatten()
            .filter(|p| failed(relay, p))
            .collect();
        if hit.is_empty() {
            continue;
        }
        if let Some(m) = metric {
            for p in &hit {
                relay.count_deploy(&p.rule, &p.host, &p.flakelet, m);
            }
        }
        return Err((status, api_error(code, message, &hit)));
    }
    Ok(waves)
}

async fn deploy(
    relay: Arc<Relay>,
    peer: Vec<String>,
    req: Request<Incoming>,
) -> Result<Resp, Resp> {
    let id = identify(&relay, peer, &req).await?;
    let body = http::read_body(req.into_body(), 64 << 10).await?;
    let dr: DeployRequest = serde_json::from_slice(&body)
        .map_err(|e| http::error(StatusCode::BAD_REQUEST, "bad_request", e.to_string()))?;
    let rx = start_deploy(relay, &id, dr).map_err(|(s, e)| http::json(s, &e))?;
    Ok(sse_response(rx, sse::encode))
}

/// Check policy and availability, then run the deploy in the
/// background. The receiver yields its events. Dropping it does not
/// stop targets that already started.
pub fn start_deploy(
    relay: Arc<Relay>,
    id: &Identity,
    dr: DeployRequest,
) -> Result<mpsc::Receiver<Event>, (StatusCode, ApiError)> {
    let waves = plan(&relay, &id.principals, &dr)?;
    let caller = id.principals.join("\n");
    let job = job_id(&caller, &dr.id);
    tracing::info!(job, caller = id.name, targets = ?waves.iter().flatten().map(|p| &p.target).collect::<Vec<_>>(), "deploy accepted");
    let (tx, rx) = mpsc::channel(64);
    tokio::spawn(run_job(
        relay,
        job,
        caller,
        id.name.clone(),
        dr.id,
        waves,
        tx,
    ));
    Ok(rx)
}

/// Stream `events` through `encode` as a `text/event-stream` body.
pub fn sse_response(
    mut events: mpsc::Receiver<Event>,
    encode: impl Fn(&Event) -> String + Send + 'static,
) -> Resp {
    let (tx, body) = Body::channel(64);
    tokio::spawn(async move {
        while let Some(ev) = events.recv().await {
            if tx.send(Bytes::from(encode(&ev))).await.is_err() {
                return;
            }
        }
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "text/event-stream")
        .header(hyper::header::CACHE_CONTROL, "no-cache")
        .header("X-Accel-Buffering", "no")
        .body(body)
        .expect("static headers")
}

fn accepted_event(relay: &Relay, job: &str, targets: &[Planned]) -> Event {
    let mut agents = relay.agent_infos();
    agents.retain(|a| targets.iter().any(|p| p.host == a.host));
    for a in &mut agents {
        a.flakelets.clear();
    }
    Event::Accepted {
        job: job.to_owned(),
        relay: RelayInfo {
            name: relay.cfg.name.clone(),
            version: proto::VERSION.into(),
            capabilities: Vec::new(),
        },
        agents,
    }
}

type Out = mpsc::Sender<Event>;

async fn emit(tx: &Out, ev: &Event) -> bool {
    tx.send(ev.clone()).await.is_ok()
}

async fn run_job(
    relay: Arc<Relay>,
    job: String,
    caller: String,
    caller_name: String,
    client_id: String,
    waves: Vec<Vec<Planned>>,
    tx: Out,
) {
    let all: Vec<Planned> = waves.iter().flatten().cloned().collect();
    if !emit(&tx, &accepted_event(&relay, &job, &all)).await {
        return;
    }
    let mut results: Vec<TargetStatus> = Vec::new();
    let mut skipped: Vec<Target> = Vec::new();
    let mut ok = true;
    for (index, wave) in waves.into_iter().enumerate() {
        if !ok {
            skipped.extend(wave.into_iter().map(|p| Target { target: p.target }));
            continue;
        }
        if !emit(&tx, &Event::Wave { index }).await {
            return;
        }
        let (offline, wave): (Vec<_>, Vec<_>) = wave.into_iter().partition(|p| p.offline);
        for p in offline {
            relay.count_deploy(&p.rule, &p.host, &p.flakelet, "offline");
            ok = false;
            results.push(TargetStatus {
                target: p.target,
                status: Status::Offline,
            });
        }
        let w = Wave::open(&relay, &job, wave, |id, p| Frame::Start {
            id,
            flakelet: p.flakelet.clone(),
            rule: p.rule.clone(),
            caller: caller.clone(),
            caller_name: caller_name.clone(),
            client_id: client_id.clone(),
            options: BTreeMap::default(),
        })
        .await;
        let Some(statuses) = w.stream(&tx, true).await else {
            return;
        };
        ok &= statuses.iter().all(|t| t.status.ok());
        results.extend(statuses);
    }
    tracing::info!(job, ok, "deploy finished");
    let _ = emit(
        &tx,
        &Event::Result {
            ok,
            targets: results,
            skipped,
        },
    )
    .await;
}

/// Targets of one wave subscribed on a shared channel, unsubscribed on
/// drop. The per-target agent id is `job_id(job, target)` so `/v1/jobs`
/// can recompute it and two flakelets on one host stay distinct.
struct Wave {
    relay: Arc<Relay>,
    job: String,
    targets: Vec<Planned>,
    rx: mpsc::UnboundedReceiver<(usize, Frame)>,
    finished: Vec<bool>,
    /// Frames read during `probe` that `stream` still has to handle.
    backlog: Vec<(usize, Frame)>,
    _tx: mpsc::UnboundedSender<(usize, Frame)>,
}

impl Wave {
    /// Subscribe every target and send it `first(id, target)`.
    async fn open(
        relay: &Arc<Relay>,
        job: &str,
        targets: Vec<Planned>,
        first: impl Fn(String, &Planned) -> Frame,
    ) -> Self {
        let (tx, rx) = mpsc::unbounded_channel::<(usize, Frame)>();
        for (i, p) in targets.iter().enumerate() {
            let id = job_id(job, &p.target);
            let frame = first(id.clone(), p);
            relay.subscribe(
                &p.host,
                &id,
                Sub {
                    index: i,
                    tx: tx.clone(),
                    start: frame.clone(),
                },
            );
            let sent = match relay.agent_tx(&p.host) {
                Some(a) => a.send(Outgoing::Frame(frame)).await.is_ok(),
                None => false,
            };
            if !sent {
                let ack = Frame::Ack {
                    id,
                    accepted: false,
                    reason: Some("agent connection lost".into()),
                };
                let _ = tx.send((i, ack));
            }
        }
        let finished = vec![false; targets.len()];
        Self {
            relay: relay.clone(),
            job: job.to_owned(),
            targets,
            finished,
            rx,
            backlog: Vec::new(),
            _tx: tx,
        }
    }

    /// After a `query`, drop targets whose agent does not know the id
    /// or did not answer within `wait`.
    async fn probe(mut self, wait: std::time::Duration) -> Self {
        let mut known = vec![None::<bool>; self.targets.len()];
        let deadline = tokio::time::Instant::now() + wait;
        while known.iter().any(Option::is_none) {
            let Ok(Some((i, frame))) = tokio::time::timeout_at(deadline, self.rx.recv()).await
            else {
                break;
            };
            match &frame {
                Frame::Error { .. } => known[i] = Some(false),
                Frame::Ack { accepted: true, .. } => known[i] = Some(true),
                _ => {
                    known[i].get_or_insert(true);
                    self.backlog.push((i, frame));
                }
            }
        }
        for (i, k) in known.into_iter().enumerate() {
            self.finished[i] = k != Some(true);
        }
        self
    }

    fn live(&self) -> Vec<Planned> {
        self.targets
            .iter()
            .zip(&self.finished)
            .filter(|(_, f)| !**f)
            .map(|(p, _)| p.clone())
            .collect()
    }

    /// Forward frames as events until each target has a result. `None`
    /// if the client went away. `count` feeds the deploy metrics.
    async fn stream(mut self, out: &Out, count: bool) -> Option<Vec<TargetStatus>> {
        let mut statuses = Vec::new();
        // Highest seq forwarded per target. A reconnecting agent replays
        // from the beginning and the client should not see lines twice.
        let mut seen = vec![0u64; self.targets.len()];
        let mut backlog = std::mem::take(&mut self.backlog).into_iter();
        while self.finished.iter().any(|f| !f) {
            let (i, frame) = match backlog.next() {
                Some(f) => f,
                None => self.rx.recv().await.expect("we hold a sender"),
            };
            if self.finished[i] {
                continue;
            }
            let p = self.targets[i].clone();
            let target = p.target.clone();
            let mut events = Vec::new();
            let done = match frame {
                Frame::Log { seq, line, .. } => {
                    if seq > seen[i] {
                        seen[i] = seq;
                        events.push(Event::Log { target, seq, line });
                    }
                    None
                }
                Frame::Progress { .. } => {
                    events.push(Event::Progress { target });
                    None
                }
                Frame::Done { body, .. } => Some(body),
                Frame::Ack {
                    accepted: false,
                    reason,
                    ..
                } => {
                    let line = format!("agent refused: {}", reason.unwrap_or_default());
                    events.push(Event::Log {
                        target,
                        seq: 0,
                        line,
                    });
                    Some(DoneBody {
                        status: Status::Failed,
                        ..Default::default()
                    })
                }
                _ => None,
            };
            if let Some(body) = done {
                self.finished[i] = true;
                if count {
                    self.relay
                        .count_deploy(&p.rule, &p.host, &p.flakelet, body.status.as_str());
                }
                statuses.push(TargetStatus {
                    target: p.target.clone(),
                    status: body.status,
                });
                events.push(Event::Done {
                    target: p.target.clone(),
                    body,
                });
            }
            for ev in &events {
                if !emit(out, ev).await {
                    return None;
                }
            }
        }
        Some(statuses)
    }
}

impl Drop for Wave {
    fn drop(&mut self) {
        for p in &self.targets {
            self.relay
                .unsubscribe(&p.host, &job_id(&self.job, &p.target));
        }
    }
}

/// `GET /v1/jobs/<client id>`: find the job's targets by asking every
/// readable agent flakelet whether it knows the derived id, then stream
/// what they have. Waves are not reconstructed.
async fn jobs(
    relay: Arc<Relay>,
    peer: Vec<String>,
    req: &Request<Incoming>,
    client_id: &str,
) -> Result<Resp, Resp> {
    let principals = authenticate(&relay, peer, req).await?;
    Ok(sse_response(
        open_job(relay, &principals, client_id).await?,
        sse::encode,
    ))
}

/// Attach to a running or finished deploy by client id. The caller is
/// whoever the agents recorded for that id, falling back to the
/// requester, so a dashboard user can follow a CI deploy it may read.
pub async fn open_job(
    relay: Arc<Relay>,
    principals: &[String],
    client_id: &str,
) -> Result<mpsc::Receiver<Event>, Resp> {
    let caller = relay
        .job_caller(principals, client_id)
        .unwrap_or_else(|| principals.join("\n"));
    let job = job_id(&caller, client_id);
    let policy = &relay.cfg.policy;
    let mut candidates = Vec::new();
    for a in relay.agent_infos() {
        for f in a.flakelets {
            if let Some(rule) = policy.rule_for(principals, &a.host, &f.name) {
                candidates.push(Planned {
                    target: format!("{}/{}", a.host, f.name),
                    host: a.host.clone(),
                    flakelet: f.name,
                    rule: rule.to_owned(),
                    offline: false,
                });
            }
        }
    }
    let wave = Wave::open(&relay, &job, candidates, |id, _| Frame::Query { id })
        .await
        .probe(std::time::Duration::from_secs(3))
        .await;
    let live = wave.live();
    if live.is_empty() {
        return Err(http::error(
            StatusCode::NOT_FOUND,
            "unknown_job",
            "no connected agent knows this job",
        ));
    }
    tracing::info!(job, targets = ?live.iter().map(|p| &p.target).collect::<Vec<_>>(), "job reattached");
    let (tx, rx) = mpsc::channel(64);
    let accepted = accepted_event(&relay, &job, &live);
    tokio::spawn(async move {
        if !emit(&tx, &accepted).await || !emit(&tx, &Event::Wave { index: 0 }).await {
            return;
        }
        let Some(targets) = wave.stream(&tx, false).await else {
            return;
        };
        let ok = targets.iter().all(|t| t.status.ok());
        let _ = emit(
            &tx,
            &Event::Result {
                ok,
                targets,
                skipped: Vec::new(),
            },
        )
        .await;
    });
    Ok(rx)
}
