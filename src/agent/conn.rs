//! One WebSocket to one relay, reconnecting forever.

use std::sync::Arc;
use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::Duration;

use hyper::Request;
use hyper::StatusCode;
use hyper::header::{AUTHORIZATION, CONNECTION, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_VERSION, UPGRADE};
use hyper_util::rt::TokioIo;
use tokio::sync::broadcast;

use crate::agent::jobs::Jobs;
use crate::client::{Client, Url, token_command};
use crate::http::Body;
use crate::proto::{self, Frame};
use crate::ws::{self, Message, Role};

/// Connection count published as systemd status text.
#[derive(Default)]
pub struct Connected {
    total: AtomicIsize,
    n: AtomicIsize,
}

impl Connected {
    pub fn set_total(&self, total: usize) {
        self.total.store(
            isize::try_from(total).unwrap_or(isize::MAX),
            Ordering::Relaxed,
        );
        self.add(0);
    }

    fn add(&self, d: isize) {
        let n = self.n.fetch_add(d, Ordering::Relaxed) + d;
        let s = format!(
            "connected to {n}/{} relays",
            self.total.load(Ordering::Relaxed)
        );
        let _ = sd_notify::notify(&[sd_notify::NotifyState::Status(&s)]);
    }
}

pub struct Conn {
    pub url: Url,
    pub client: Arc<Client>,
    pub token_command: Option<Vec<String>>,
    pub jobs: Arc<Jobs>,
    /// Established relay connections, for `STATUS=`.
    pub connected: Arc<Connected>,
}

impl Conn {
    pub async fn run(self) {
        let mut backoff = Duration::from_secs(1);
        loop {
            match self.once().await {
                Ok(reason) => {
                    tracing::info!(relay = %self.url, "disconnected: {reason}");
                    self.connected.add(-1);
                    backoff = Duration::from_secs(1);
                }
                Err(e) => {
                    tracing::warn!(relay = %self.url, "connect failed: {e}");
                    backoff = (backoff * 2).min(Duration::from_mins(1));
                }
            }
            tokio::time::sleep(backoff).await;
        }
    }

    /// One connection lifetime. `Ok` means it was established and later
    /// ended, `Err` that it never got going.
    async fn once(&self) -> Result<String, String> {
        let key = ws::new_key();
        let mut req = Request::get(format!("{}/v1/agent", self.url.path))
            .header(UPGRADE, "websocket")
            .header(CONNECTION, "Upgrade")
            .header(SEC_WEBSOCKET_KEY, &key)
            .header(SEC_WEBSOCKET_VERSION, "13");
        if let Some(cmd) = &self.token_command {
            req = req.header(AUTHORIZATION, format!("Bearer {}", token_command(cmd)?));
        }
        let req = req.body(Body::empty()).map_err(|e| e.to_string())?;
        let resp = self
            .client
            .send(&self.url, req)
            .await
            .map_err(|e| e.to_string())?;
        if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
            let status = resp.status();
            let body = crate::http::read_body(resp.into_body(), 4096)
                .await
                .unwrap_or_default();
            return Err(format!(
                "{status}: {}",
                String::from_utf8_lossy(&body).trim()
            ));
        }
        if resp
            .headers()
            .get("sec-websocket-accept")
            .and_then(|v| v.to_str().ok())
            != Some(ws::accept_key(&key).as_str())
        {
            return Err("bad sec-websocket-accept".into());
        }
        let upgraded = hyper::upgrade::on(resp).await.map_err(|e| e.to_string())?;
        let (r, w) = tokio::io::split(TokioIo::new(upgraded));
        let mut reader = ws::Reader::new(r);
        let mut writer = ws::Writer::new(w, Role::Client);

        let Ok(Ok(Message::Text(t))) =
            tokio::time::timeout(Duration::from_secs(10), reader.read()).await
        else {
            return Err("no welcome".into());
        };
        let Ok(Frame::Welcome { host, relay }) = serde_json::from_str::<Frame>(&t) else {
            return Err("first frame was not welcome".into());
        };
        writer
            .send(&Frame::Hello {
                version: proto::VERSION.into(),
                capabilities: Vec::new(),
                flakelets: self.jobs.describe(),
                jobs: self.jobs.refs(),
            })
            .await
            .map_err(|e| e.to_string())?;
        tracing::info!(relay = %self.url, relay_name = relay.name, relay_version = relay.version, host, "connected");
        self.connected.add(1);

        let mut events = self.jobs.subscribe();
        let mut ping = tokio::time::interval(Duration::from_secs(20));
        ping.tick().await;
        loop {
            let send: Result<(), ws::Error> = tokio::select! {
                msg = tokio::time::timeout(Duration::from_mins(1), reader.read()) => {
                    let msg = match msg {
                        Ok(Ok(m)) => m,
                        Ok(Err(e)) => return Ok(e.to_string()),
                        Err(_) => return Ok("read timeout".into()),
                    };
                    match msg {
                        Message::Text(t) => match self.on_frame(&t, &relay.name, &mut writer).await {
                            Ok(None) => Ok(()),
                            Ok(Some(reason)) => return Ok(reason),
                            Err(e) => Err(e),
                        },
                        Message::Ping(d) => writer.pong(&d).await,
                        Message::Pong(_) => Ok(()),
                        Message::Close => return Ok("closed by relay".into()),
                    }
                }
                ev = events.recv() => match ev {
                    Ok(f) => writer.send(&f).await,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(relay = relay.name, "dropped {n} frames to slow relay");
                        Ok(())
                    }
                    Err(broadcast::error::RecvError::Closed) => return Ok("shutting down".into()),
                },
                _ = ping.tick() => writer.ping().await,
            };
            if let Err(e) = send {
                return Ok(format!("write: {e}"));
            }
        }
    }

    /// Handle one text frame. `Ok(Some(reason))` ends the connection.
    async fn on_frame<W: tokio::io::AsyncWrite + Unpin>(
        &self,
        text: &str,
        relay: &str,
        writer: &mut ws::Writer<W>,
    ) -> Result<Option<String>, ws::Error> {
        match serde_json::from_str::<Frame>(text) {
            Ok(Frame::Start {
                id,
                flakelet,
                rule,
                caller,
                client_id,
                options: _,
            }) => {
                tracing::info!(id, flakelet, rule, relay, ?caller, "start");
                for f in self.jobs.start(&id, &flakelet, caller, client_id) {
                    writer.send(&f).await?;
                }
            }
            Ok(Frame::Query { id }) => {
                let frames = self.jobs.replay(&id).unwrap_or_else(|| {
                    vec![Frame::Error {
                        id: Some(id),
                        code: "unknown_job".into(),
                        message: "no such job on this agent".into(),
                    }]
                });
                for f in frames {
                    writer.send(&f).await?;
                }
            }
            Ok(Frame::Error { code, message, .. }) => {
                if code == "conflict" {
                    return Ok(Some(format!("relay reports conflict: {message}")));
                }
                tracing::warn!(relay, code, "relay error: {message}");
            }
            Ok(_) => {}
            Err(e) => tracing::debug!("unparseable frame: {e}"),
        }
        Ok(None)
    }
}
