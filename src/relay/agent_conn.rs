//! `/v1/agent`: WebSocket upgrade, identity, registration, frame routing.

use std::sync::Arc;
use std::time::{Duration, Instant};

use hyper::body::Incoming;
use hyper::header::{
    CONNECTION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_VERSION, UPGRADE,
};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::http::{self, Body, Resp};
use crate::proto::{self, AgentInfo, Frame, RelayInfo};
use crate::relay::api::authenticate;
use crate::relay::state::{Agent, Outgoing, Relay};
use crate::ws::{self, Message, Role};

pub async fn upgrade(
    relay: Arc<Relay>,
    principals: Vec<String>,
    mut req: Request<Incoming>,
) -> Result<Resp, Resp> {
    let principals = authenticate(&relay, principals, &req).await?;
    let host = relay
        .cfg
        .policy
        .host_for(&principals)
        .map(str::to_owned)
        .map_err(|e| {
            tracing::info!(?principals, "agent rejected: {e}");
            http::error(StatusCode::FORBIDDEN, "unknown_agent", e.to_string())
        })?;
    let is_upgrade = req
        .headers()
        .get(SEC_WEBSOCKET_VERSION)
        .is_some_and(|v| v == "13")
        && header_has(&req, UPGRADE, "websocket")
        && header_has(&req, CONNECTION, "upgrade");
    let Some(key) = req.headers().get(SEC_WEBSOCKET_KEY).filter(|_| is_upgrade) else {
        return Err(http::error(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "expected websocket upgrade",
        ));
    };
    let accept = ws::accept_key(key.to_str().unwrap_or_default());
    let on_upgrade = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => run(relay, host, TokioIo::new(upgraded)).await,
            Err(e) => tracing::warn!(host, "upgrade failed: {e}"),
        }
    });
    Ok(Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(UPGRADE, "websocket")
        .header(CONNECTION, "Upgrade")
        .header(SEC_WEBSOCKET_ACCEPT, accept)
        .body(Body::empty())
        .expect("static headers"))
}

fn header_has(req: &Request<Incoming>, name: hyper::header::HeaderName, want: &str) -> bool {
    req.headers()
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case(want))
}

async fn run<S>(relay: Arc<Relay>, host: String, io: S)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = ws::split(io, Role::Server).await;

    let welcome = Frame::Welcome {
        host: host.clone(),
        relay: RelayInfo {
            name: relay.cfg.name.clone(),
            version: proto::VERSION.into(),
            capabilities: Vec::new(),
        },
    };
    if writer.frame(&welcome).await.is_err() {
        return;
    }
    let hello = tokio::time::timeout(Duration::from_secs(10), reader.read()).await;
    let (info, jobs) = match hello {
        Ok(Ok(Message::Text(t))) => match serde_json::from_str(&t) {
            Ok(Frame::Hello {
                version,
                capabilities,
                flakelets,
                jobs,
            }) => (
                AgentInfo {
                    host: host.clone(),
                    version,
                    capabilities,
                    flakelets,
                },
                jobs.into_iter().map(|j| (j.id.clone(), j)).collect(),
            ),
            _ => return tracing::warn!(host, "first frame was not hello"),
        },
        _ => return tracing::warn!(host, "no hello within 10s"),
    };

    let (tx, mut rx) = mpsc::channel::<Outgoing>(256);
    let conn = relay.conn_id();
    let agent = Agent {
        conn,
        info: info.clone(),
        jobs,
        tx: tx.clone(),
        last_seen: Instant::now(),
    };
    if !relay.register(&host, agent) {
        tracing::warn!(host, "duplicate agent rejected");
        let err = Frame::Error {
            id: None,
            code: "conflict".into(),
            message: "another connection for this host is active".into(),
        };
        let _ = writer.frame(&err).await;
        let _ = writer.send(Message::Close(None)).await;
        return;
    }
    tracing::info!(host, version = info.version, flakelets = ?info.flakelets, "agent connected");
    for start in relay.pending_starts(&host) {
        let _ = tx.send(Outgoing::Frame(start)).await;
    }

    let writer_task = tokio::spawn(async move {
        while let Some(out) = rx.recv().await {
            let r = match out {
                Outgoing::Frame(f) => writer.frame(&f).await,
                Outgoing::Pong(d) => writer.send(Message::Pong(d)).await,
            };
            if r.is_err() {
                break;
            }
        }
        let _ = writer.send(Message::Close(None)).await;
    });
    let reason = read_loop(&relay, &host, conn, &mut reader, &tx).await;
    relay.unregister(&host, conn);
    writer_task.abort();
    tracing::info!(host, "agent disconnected: {reason}");
}

/// Route incoming frames until the connection ends and return why. The
/// agent pings every 20 s, so a minute of silence means it is gone.
async fn read_loop<S: AsyncRead + AsyncWrite + Unpin>(
    relay: &Relay,
    host: &str,
    conn: u64,
    reader: &mut ws::Reader<S>,
    tx: &mpsc::Sender<Outgoing>,
) -> String {
    loop {
        let msg = match tokio::time::timeout(Duration::from_mins(1), reader.read()).await {
            Ok(Ok(m)) => m,
            Ok(Err(e)) => return e.to_string(),
            Err(_) => return "read timeout".into(),
        };
        relay.seen(host, conn);
        match msg {
            Message::Text(t) => {
                let Ok(frame) = serde_json::from_str::<Frame>(&t) else {
                    tracing::debug!(host, "unparseable frame");
                    continue;
                };
                match &frame {
                    Frame::Job { job } => relay.record_job(host, conn, job.clone()),
                    Frame::Flakelets { flakelets } => {
                        relay.record_flakelets(host, conn, flakelets.clone());
                    }
                    Frame::Ack { id, .. }
                    | Frame::Log { id, .. }
                    | Frame::Progress { id }
                    | Frame::Done { id, .. }
                    | Frame::Error { id: Some(id), .. } => {
                        let id = id.clone();
                        relay.dispatch(host, &id, frame);
                    }
                    Frame::Error {
                        id: None,
                        code,
                        message,
                    } => {
                        tracing::warn!(host, code, "agent error: {message}");
                    }
                    _ => {}
                }
            }
            Message::Ping(d) => {
                let _ = tx.send(Outgoing::Pong(d)).await;
            }
            Message::Close(_) => return "closed by agent".into(),
            _ => {}
        }
    }
}
