//! Minimal RFC 6455 framing for JSON text messages over an already
//! upgraded stream. Only what relay and agent need: text, ping, pong,
//! close, client-side masking, no extensions, no fragmentation.

use std::io;

use base64::Engine as _;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::proto::Frame;

pub const MAX_MESSAGE: usize = 4 << 20;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("websocket closed")]
    Closed,
    #[error("websocket protocol: {0}")]
    Protocol(&'static str),
    #[error("invalid json in text frame: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug)]
pub enum Message {
    Text(String),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close,
}

#[derive(Clone, Copy)]
pub enum Role {
    /// Masks outgoing frames.
    Client,
    Server,
}

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

pub struct Reader<R> {
    inner: R,
}

impl<R: AsyncRead + Unpin> Reader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner }
    }

    /// Next message. Neither side fragments, so continuation frames are
    /// a protocol error.
    pub async fn read(&mut self) -> Result<Message, Error> {
        {
            let mut hdr = [0u8; 2];
            match self.inner.read_exact(&mut hdr).await {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Err(Error::Closed),
                Err(e) => return Err(e.into()),
            }
            let fin = hdr[0] & 0x80 != 0;
            let opcode = hdr[0] & 0x0f;
            let masked = hdr[1] & 0x80 != 0;
            let mut len = u64::from(hdr[1] & 0x7f);
            if len == 126 {
                len = u64::from(self.inner.read_u16().await?);
            } else if len == 127 {
                len = self.inner.read_u64().await?;
            }
            if len > MAX_MESSAGE as u64 {
                return Err(Error::Protocol("frame too large"));
            }
            let mask = if masked {
                let mut m = [0u8; 4];
                self.inner.read_exact(&mut m).await?;
                Some(m)
            } else {
                None
            };
            #[allow(clippy::cast_possible_truncation)]
            let mut payload = vec![0u8; len as usize];
            self.inner.read_exact(&mut payload).await?;
            if let Some(m) = mask {
                for (i, b) in payload.iter_mut().enumerate() {
                    *b ^= m[i % 4];
                }
            }
            if !fin {
                return Err(Error::Protocol("fragmented message"));
            }
            match opcode {
                0x1 => String::from_utf8(payload)
                    .map(Message::Text)
                    .map_err(|_| Error::Protocol("invalid utf-8")),
                0x8 => Ok(Message::Close),
                0x9 => Ok(Message::Ping(payload)),
                0xA => Ok(Message::Pong(payload)),
                _ => Err(Error::Protocol("unsupported opcode")),
            }
        }
    }
}

pub struct Writer<W> {
    inner: W,
    role: Role,
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    pub fn new(inner: W, role: Role) -> Self {
        Self { inner, role }
    }

    async fn frame(&mut self, opcode: u8, payload: &[u8]) -> Result<(), Error> {
        let mut out = Vec::with_capacity(payload.len() + 14);
        out.push(0x80 | opcode);
        let mask_bit = if matches!(self.role, Role::Client) {
            0x80
        } else {
            0
        };
        let len = payload.len();
        if len < 126 {
            #[allow(clippy::cast_possible_truncation)]
            out.push(mask_bit | len as u8);
        } else if let Ok(l) = u16::try_from(len) {
            out.push(mask_bit | 0x7e);
            out.extend_from_slice(&l.to_be_bytes());
        } else {
            out.push(mask_bit | 0x7f);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
        if matches!(self.role, Role::Client) {
            let mut m = [0u8; 4];
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut m)
                .expect("system rng");
            out.extend_from_slice(&m);
            out.extend(payload.iter().enumerate().map(|(i, b)| b ^ m[i % 4]));
        } else {
            out.extend_from_slice(payload);
        }
        self.inner.write_all(&out).await?;
        self.inner.flush().await?;
        Ok(())
    }

    pub async fn send(&mut self, f: &Frame) -> Result<(), Error> {
        let s = serde_json::to_string(f)?;
        self.frame(0x1, s.as_bytes()).await
    }

    pub async fn ping(&mut self) -> Result<(), Error> {
        self.frame(0x9, b"").await
    }

    pub async fn pong(&mut self, data: &[u8]) -> Result<(), Error> {
        self.frame(0xA, data).await
    }

    pub async fn close(&mut self) -> Result<(), Error> {
        self.frame(0x8, b"").await
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
        let mut writer = Writer::new(client, Role::Client);
        let mut reader = Reader::new(server);
        let line = "x".repeat(70_000);
        let frame = Frame::Log {
            id: "j".into(),
            seq: 1,
            line: line.clone(),
        };
        let send = async {
            writer.send(&frame).await.unwrap();
            writer.ping().await.unwrap();
        };
        let recv = async {
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
