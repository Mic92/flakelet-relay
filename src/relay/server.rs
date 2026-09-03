//! Accept loops for the plain and TLS listeners.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::auth::x509;
use crate::relay::api;
use crate::relay::state::Relay;

async fn bind(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let l = TcpListener::bind(addr).await?;
    tracing::info!("listening on {}", l.local_addr()?);
    Ok(l)
}

fn serve<S>(relay: Arc<Relay>, peer: Vec<String>, io: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let svc = service_fn(move |req| {
            let relay = relay.clone();
            let peer = peer.clone();
            async move { Ok::<_, Infallible>(api::handle(relay, peer, req).await) }
        });
        if let Err(e) = http1::Builder::new()
            .keep_alive(true)
            .serve_connection(TokioIo::new(io), svc)
            .with_upgrades()
            .await
        {
            tracing::debug!("connection: {e}");
        }
    });
}

pub async fn run_http(relay: Arc<Relay>, addr: SocketAddr) -> std::io::Result<()> {
    let listener = bind(addr).await?;
    loop {
        let (tcp, _) = listener.accept().await?;
        let _ = tcp.set_nodelay(true);
        serve(relay.clone(), Vec::new(), tcp);
    }
}

pub async fn run_tls(
    relay: Arc<Relay>,
    addr: SocketAddr,
    cfg: rustls::ServerConfig,
) -> std::io::Result<()> {
    let listener = bind(addr).await?;
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    loop {
        let (tcp, remote) = listener.accept().await?;
        let _ = tcp.set_nodelay(true);
        let acceptor = acceptor.clone();
        let relay = relay.clone();
        tokio::spawn(async move {
            let tls =
                match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await {
                    Ok(Ok(t)) => t,
                    Ok(Err(e)) => {
                        tracing::debug!(%remote, "tls handshake: {e}");
                        return;
                    }
                    Err(_) => return,
                };
            let principals = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
                .map(|leaf| x509::principals(leaf.as_ref()))
                .unwrap_or_default();
            serve(relay, principals, tls);
        });
    }
}
