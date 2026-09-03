//! HTTP/1.1 client over tokio-rustls for the handful of requests agent
//! and push make. HTTPS only, one connection per request, upgrades supported.

use std::io;
use std::sync::Arc;

use hyper::Request;
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;

use crate::http::Body;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("bad url {0}")]
    Url(String),
    #[error("connect {0}: {1}")]
    Connect(String, #[source] io::Error),
    #[error("tls with {0}: {1}")]
    Tls(String, #[source] io::Error),
    #[error(transparent)]
    Hyper(#[from] hyper::Error),
    #[error(transparent)]
    Http(#[from] hyper::http::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Url {
    pub fn parse(s: &str) -> Result<Url, Error> {
        let bad = || Error::Url(s.to_owned());
        let rest = s.strip_prefix("https://").ok_or_else(bad)?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, port) = if let Some(h) = authority.strip_prefix('[') {
            let (h, p) = h.split_once(']').ok_or_else(bad)?;
            (h, p.strip_prefix(':'))
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (authority, None),
            }
        };
        let port = match port {
            Some(p) => p.parse().map_err(|_| bad())?,
            None => 443,
        };
        if host.is_empty() {
            return Err(bad());
        }
        Ok(Url {
            host: host.to_owned(),
            port,
            path: path.trim_end_matches('/').to_owned(),
        })
    }

    #[must_use]
    pub fn join(&self, path: &str) -> Url {
        Url {
            path: format!("{}{path}", self.path),
            ..self.clone()
        }
    }

    #[must_use]
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "https://{}{}", self.authority(), self.path)
    }
}

pub struct Client {
    tls: Arc<ClientConfig>,
}

impl Client {
    #[must_use]
    pub fn new(tls: ClientConfig) -> Self {
        Self { tls: Arc::new(tls) }
    }

    async fn connect(
        &self,
        url: &Url,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Error> {
        let tcp = TcpStream::connect((url.host.as_str(), url.port))
            .await
            .map_err(|e| Error::Connect(url.authority(), e))?;
        let _ = tcp.set_nodelay(true);
        let name =
            ServerName::try_from(url.host.clone()).map_err(|_| Error::Url(url.to_string()))?;
        let tls = tokio_rustls::TlsConnector::from(self.tls.clone())
            .connect(name, tcp)
            .await
            .map_err(|e| Error::Tls(url.authority(), e))?;
        Ok(tls)
    }

    /// Send one request on a fresh connection. The connection task is
    /// spawned with upgrades enabled so the caller can `hyper::upgrade::on`.
    pub async fn send(
        &self,
        url: &Url,
        mut req: Request<Body>,
    ) -> Result<hyper::Response<Incoming>, Error> {
        let io = TokioIo::new(self.connect(url).await?);
        let (mut sender, conn) = http1::handshake(io).await?;
        tokio::spawn(async move {
            if let Err(e) = conn.with_upgrades().await {
                tracing::debug!("client connection: {e}");
            }
        });
        req.headers_mut()
            .entry(hyper::header::HOST)
            .or_insert_with(|| {
                url.authority()
                    .parse()
                    .expect("authority is a valid header")
            });
        Ok(sender.send_request(req).await?)
    }
}

/// Run a command that prints a bearer token.
pub fn token_command(cmd: &[String]) -> Result<String, String> {
    let (prog, args) = cmd.split_first().ok_or("empty token command")?;
    let out = std::process::Command::new(prog)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .output()
        .map_err(|e| format!("{prog}: {e}"))?;
    if !out.status.success() {
        return Err(format!("{prog} exited with {}", out.status));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let u = Url::parse("https://relay.thalheim.io/api/").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.path.as_str()),
            ("relay.thalheim.io", 443, "/api")
        );
        assert_eq!(
            u.join("/v1/agent").to_string(),
            "https://relay.thalheim.io:443/api/v1/agent"
        );
        let u = Url::parse("https://[::1]:8080").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.path.as_str()),
            ("::1", 8080, "")
        );
        assert_eq!(u.authority(), "[::1]:8080");
        assert!(Url::parse("http://x").is_err());
        assert!(Url::parse("https://:1").is_err());
    }
}
