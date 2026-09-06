//! JSON text messages over an already upgraded stream. The HTTP
//! handshake stays with hyper on both sides (client certs, bearer
//! tokens, SRV). Framing is tokio-tungstenite's.

use base64::Engine as _;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt as _, StreamExt as _};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::proto::Frame;

pub use tokio_tungstenite::tungstenite::protocol::Role;
pub use tokio_tungstenite::tungstenite::{Error, Message};

pub const MAX_MESSAGE: usize = 4 << 20;

#[must_use]
pub fn accept_key(key: &str) -> String {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
    ctx.update(key.as_bytes());
    ctx.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::engine::general_purpose::STANDARD.encode(ctx.finish())
}

#[must_use]
pub fn new_key() -> String {
    let mut k = [0u8; 16];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut k).expect("system rng");
    base64::engine::general_purpose::STANDARD.encode(k)
}

pub struct Reader<S>(SplitStream<WebSocketStream<S>>);
pub struct Writer<S>(SplitSink<WebSocketStream<S>, Message>);

pub async fn split<S>(io: S, role: Role) -> (Reader<S>, Writer<S>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let cfg = WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE))
        .max_frame_size(Some(MAX_MESSAGE));
    let (w, r) = WebSocketStream::from_raw_socket(io, role, Some(cfg))
        .await
        .split();
    (Reader(r), Writer(w))
}

impl<S: AsyncRead + AsyncWrite + Unpin> Reader<S> {
    pub async fn read(&mut self) -> Result<Message, Error> {
        self.0.next().await.unwrap_or(Err(Error::ConnectionClosed))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Writer<S> {
    pub async fn send(&mut self, m: Message) -> Result<(), Error> {
        self.0.send(m).await
    }

    pub async fn frame(&mut self, f: &Frame) -> Result<(), Error> {
        let s = serde_json::to_string(f).expect("frames serialize");
        self.send(Message::text(s)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_example_accept_key() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[tokio::test]
    async fn roundtrip_masked_large() {
        let (client, server) = tokio::io::duplex(1 << 16);
        let line = "x".repeat(70_000);
        let frame = Frame::Log {
            id: "j".into(),
            seq: 1,
            line: line.clone(),
        };
        let send = async {
            let (_, mut writer) = split(client, Role::Client).await;
            writer.frame(&frame).await.unwrap();
            writer.send(Message::Ping(Vec::new().into())).await.unwrap();
        };
        let recv = async {
            let (mut reader, _) = split(server, Role::Server).await;
            let Message::Text(text) = reader.read().await.unwrap() else {
                panic!()
            };
            let Frame::Log { line: got, .. } = serde_json::from_str(&text).unwrap() else {
                panic!()
            };
            assert_eq!(got, line);
            assert!(matches!(reader.read().await.unwrap(), Message::Ping(_)));
        };
        tokio::join!(send, recv);
    }
}
