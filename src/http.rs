//! A response/request body that is either a fixed buffer or a channel
//! of chunks (SSE), plus small helpers shared by the servers.

use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::BodyExt as _;
use hyper::body::{Frame, Incoming};
use hyper::{Response, StatusCode};
use serde::Serialize;
use tokio::sync::mpsc;

use crate::proto::ApiError;

pub enum Body {
    Full(Option<Bytes>),
    Stream(mpsc::Receiver<Bytes>),
}

impl Body {
    #[must_use]
    pub fn empty() -> Self {
        Body::Full(None)
    }

    #[must_use]
    pub fn channel(cap: usize) -> (mpsc::Sender<Bytes>, Self) {
        let (tx, rx) = mpsc::channel(cap);
        (tx, Body::Stream(rx))
    }
}

impl From<String> for Body {
    fn from(s: String) -> Self {
        Body::Full(Some(Bytes::from(s)))
    }
}

impl hyper::body::Body for Body {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        match self.get_mut() {
            Body::Full(b) => Poll::Ready(b.take().map(|b| Ok(Frame::data(b)))),
            Body::Stream(rx) => rx.poll_recv(cx).map(|o| o.map(|b| Ok(Frame::data(b)))),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Body::Full(b) => b.is_none(),
            Body::Stream(_) => false,
        }
    }
}

pub type Resp = Response<Body>;

pub fn json<T: Serialize>(status: StatusCode, v: &T) -> Resp {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(serde_json::to_string(v).expect("serializable").into())
        .expect("static headers")
}

pub fn error(status: StatusCode, code: &str, message: impl Into<String>) -> Resp {
    json(
        status,
        &ApiError {
            code: code.into(),
            message: message.into(),
            targets: Vec::new(),
        },
    )
}

pub fn text(status: StatusCode, body: impl Into<Body>) -> Resp {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(body.into())
        .expect("static headers")
}

/// Collect a request body up to `limit` bytes.
pub async fn read_body(body: Incoming, limit: usize) -> Result<Bytes, Resp> {
    let limited = http_body_util::Limited::new(body, limit);
    match limited.collect().await {
        Ok(c) => Ok(c.to_bytes()),
        Err(_) => Err(error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_large",
            "request body too large",
        )),
    }
}

#[must_use]
pub fn bearer(req: &hyper::Request<Incoming>) -> Option<&str> {
    req.headers()
        .get(hyper::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
}
