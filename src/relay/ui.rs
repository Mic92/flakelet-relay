//! Server-rendered dashboard under `/ui/`: routing, layout, actions and
//! the event streams htmx subscribes to. Page bodies are in `pages`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use maud::{DOCTYPE, Markup, html};

use crate::http::{Body, Resp};
use crate::proto::{self, DeployRequest, Event, JobState, Target, Wave};
use crate::relay::api;
use crate::relay::login::{self, Session};
use crate::relay::pages::{self, Filter};
use crate::relay::state::Relay;

/// htmx 4.0.0 and its SSE extension, vendored (0BSD).
const STATIC: &[(&str, &str, &[u8])] = &[
    ("app.css", "text/css", include_bytes!("static/app.css")),
    (
        "htmx.min.js",
        "text/javascript",
        include_bytes!("static/htmx.min.js"),
    ),
    (
        "hx-sse.min.js",
        "text/javascript",
        include_bytes!("static/hx-sse.min.js"),
    ),
];

pub(crate) fn redirect(to: &str) -> Resp {
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(hyper::header::LOCATION, to)
        .body(Body::empty())
        .expect("static headers")
}

fn hx_redirect(to: &str) -> Resp {
    Response::builder()
        .status(StatusCode::OK)
        .header("HX-Redirect", to)
        .body(Body::empty())
        .expect("static headers")
}

pub(crate) fn with_cookie(mut r: Resp, cookie: &str) -> Resp {
    r.headers_mut().append(
        hyper::header::SET_COOKIE,
        cookie.parse().expect("cookie is ascii"),
    );
    r
}

fn page(status: StatusCode, m: &Markup) -> Resp {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        )
        .header("Referrer-Policy", "same-origin")
        .body(m.clone().into_string().into())
        .expect("static headers")
}

pub(crate) fn fail(status: StatusCode, msg: &str) -> Resp {
    page(
        status,
        &layout(
            "",
            None,
            "",
            None,
            &html! { main { p.notice { (msg) } p { a href="/ui/login" { "Log in again" } } } },
        ),
    )
}

/// Query parameter, percent-decoded.
pub(crate) fn query(req: &Request<Incoming>, key: &str) -> Option<String> {
    req.uri().query()?.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then(|| percent_decode(v))
    })
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(v);
                    i += 2;
                } else {
                    out.push(b'%');
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub async fn handle(relay: Arc<Relay>, req: Request<Incoming>) -> Resp {
    let path = req.uri().path()["/ui/".len()..].to_owned();
    let seg: Vec<&str> = path.split('/').collect();
    match (req.method(), seg.as_slice()) {
        (&Method::GET, ["static", f]) => match STATIC.iter().find(|(n, ..)| n == f) {
            Some((_, mime, data)) => Response::builder()
                .header(hyper::header::CONTENT_TYPE, *mime)
                .header(hyper::header::CACHE_CONTROL, "max-age=3600")
                .body(Body::Full(Some(bytes::Bytes::from_static(data))))
                .expect("static headers"),
            None => fail(StatusCode::NOT_FOUND, "no such file"),
        },
        (&Method::GET, ["login"]) => login::start(&relay, &req).await,
        (&Method::GET, ["callback"]) => login::callback(&relay, &req).await,
        (&Method::POST, ["logout"]) => login::logout(),
        (&Method::POST, ["deploy"]) => action(relay, &req, deploy_targets),
        (&Method::POST, ["retry"]) => action(relay, &req, retry_targets),
        (&Method::GET, rest) => {
            let Some(sess) = login::current(&relay, &req) else {
                return redirect("/ui/login");
            };
            let p = &sess.who.principals;
            let q = query(&req, "q").unwrap_or_default();
            let f = Filter::parse(&q);
            let mut status = StatusCode::OK;
            let (tab, live, body) = match rest {
                [""] => ("", true, pages::flakelets(&relay, p, &f)),
                ["flakelets"] | ["flakelets", ""] => return redirect("/ui/"),
                ["flakelets", name] => ("", true, pages::flakelet(&relay, p, name)),
                ["hosts"] => ("hosts", true, pages::hosts(&relay, p, &f)),
                ["jobs"] => ("jobs", true, pages::jobs(&relay, p, &f)),
                ["jobs", id] => ("jobs", false, pages::job(&relay, p, id)),
                ["jobs", id, "events"] => return job_events(relay.clone(), p, id).await,
                ["events"] => return page_events(relay.clone(), sess, &req),
                _ => {
                    status = StatusCode::NOT_FOUND;
                    ("", false, html! { main { p.notice { "No such page." } } })
                }
            };
            // List pages re-render `#main` whenever the relay's view changes.
            let events = live.then(|| format!("/ui/events?path={}&q={}", path, oidc_enc(&q)));
            page(
                status,
                &layout(&relay.cfg.name, Some(&sess), tab, events.as_deref(), &body),
            )
        }
        _ => fail(StatusCode::NOT_FOUND, "no such page"),
    }
}

fn oidc_enc(s: &str) -> String {
    crate::oidc::form_encode(&[("", s)])[1..].to_owned()
}

fn layout(
    name: &str,
    sess: Option<&Session>,
    tab: &str,
    events: Option<&str>,
    body: &Markup,
) -> Markup {
    let nav = [("", "Flakelets"), ("hosts", "Hosts"), ("jobs", "Jobs")];
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "flakelet-relay" }
                link rel="stylesheet" href="/ui/static/app.css";
                script src="/ui/static/htmx.min.js" defer {}
                script src="/ui/static/hx-sse.min.js" defer {}
            }
            body {
                a.skip href="#main" { "Skip to content" }
                header.top {
                    h1 { "flakelet-relay " span { (name) } }
                    @if let Some(s) = sess {
                        nav aria-label="Sections" {
                            @for (p, label) in nav {
                                a href={"/ui/" (p)} .on[p == tab] aria-current=[(p == tab).then_some("page")] { (label) }
                            }
                        }
                        form.me method="post" action="/ui/logout" {
                            "Signed in as " b { (s.who.name) } " "
                            button { "Log out" }
                        }
                    }
                }
                div #main tabindex="-1" hx-sse:connect=[events] hx-swap="innerMorph" { (body) }
            }
        }
    }
}

type Targets = fn(&Relay, &[String], &str) -> Vec<String>;

/// "Update now": every host the user may see `flakelet` on.
fn deploy_targets(relay: &Relay, principals: &[String], flakelet: &str) -> Vec<String> {
    relay
        .host_flakelets(principals)
        .into_iter()
        .filter(|h| h.flakelet == flakelet)
        .map(|h| format!("{}/{}", h.host, h.flakelet))
        .collect()
}

/// "Retry failed": the targets of deploy `id` that did not end ok.
fn retry_targets(relay: &Relay, principals: &[String], id: &str) -> Vec<String> {
    relay
        .job_summaries(principals)
        .into_iter()
        .find(|j| j.id == id)
        .into_iter()
        .flat_map(|j| j.targets)
        .filter(|t| t.state == JobState::Done && !t.status.is_some_and(proto::Status::ok))
        .map(|t| t.target)
        .collect()
}

/// Run a one-wave deploy of whatever `targets` selects for `?arg=` and
/// send the browser to its job page. htmx always sends `HX-Request`,
/// which a cross-site form cannot, so together with `SameSite=Lax` that
/// is the CSRF check.
fn action(relay: Arc<Relay>, req: &Request<Incoming>, targets: Targets) -> Resp {
    let Some(sess) = login::current(&relay, req) else {
        return hx_redirect("/ui/login");
    };
    if req.headers().get("HX-Request").is_none() {
        return fail(StatusCode::FORBIDDEN, "not an htmx request");
    }
    let arg = query(req, "arg").unwrap_or_default();
    let targets: Vec<Target> = targets(&relay, &sess.who.principals, &arg)
        .into_iter()
        .map(|target| Target { target })
        .collect();
    if targets.is_empty() {
        return fail(StatusCode::BAD_REQUEST, "nothing to deploy");
    }
    let id = proto::random_id();
    let dr = DeployRequest {
        id: id.clone(),
        waves: vec![Wave { targets }],
        options: BTreeMap::default(),
    };
    match api::start_deploy(relay, &sess.who, dr) {
        Ok(mut rx) => {
            // Keep consuming so later waves run. The job page attaches
            // through /ui/jobs/<id>/events.
            tokio::spawn(async move { while rx.recv().await.is_some() {} });
            hx_redirect(&format!("/ui/jobs/{id}"))
        }
        Err((status, e)) => fail(status, &format!("{}: {}", e.code, e.message)),
    }
}

/// The job's event stream as HTML fragments: unnamed messages are
/// appended to the log, target state and the action bar ride along as
/// `<hx-partial>`, and `result` closes the stream.
async fn job_events(relay: Arc<Relay>, principals: &[String], id: &str) -> Resp {
    let rx = match api::open_job(relay, principals, id).await {
        Ok(rx) => rx,
        Err(resp) => return resp,
    };
    let id = id.to_owned();
    api::sse_response(rx, move |ev| match ev {
        Event::Log { target, line, .. } => sse_html(&html! { span.t { (target) } " " (line) "\n" }),
        Event::Done { target, body } => sse_html(&html! {
            hx-partial hx-target={"#" (pages::target_id(target))} hx-swap="outerHTML" {
                (pages::target_row(target, JobState::Done, Some(body.status)))
            }
            @for l in body.tail.iter().flatten() { span.tail { (target) " │ " (l.line) "\n" } }
        }),
        Event::Result { ok, .. } => format!(
            "{}event: result\ndata: {ok}\n\n",
            sse_html(
                &html! { hx-partial hx-target="#actions" hx-swap="outerHTML" { (pages::job_actions(&id, Some(*ok))) } }
            )
        ),
        _ => String::from(":\n\n"),
    })
}

/// Re-rendered page body whenever agents connect, disconnect or report
/// a job, at most twice a second, plus a comment every 30 s so proxies
/// keep the stream open.
fn page_events(relay: Arc<Relay>, sess: Session, req: &Request<Incoming>) -> Resp {
    let path = query(req, "path").unwrap_or_default();
    let f = Filter::parse(&query(req, "q").unwrap_or_default());
    let (tx, body) = Body::channel(4);
    let mut changed = relay.changed.subscribe();
    tokio::spawn(async move {
        loop {
            let tick = tokio::time::timeout(Duration::from_secs(30), changed.recv()).await;
            let chunk = if tick.is_ok() {
                tokio::time::sleep(Duration::from_millis(500)).await;
                changed = changed.resubscribe();
                let p = &sess.who.principals;
                let seg: Vec<&str> = path.split('/').collect();
                let body = match seg.as_slice() {
                    ["hosts"] => pages::hosts(&relay, p, &f),
                    ["jobs"] => pages::jobs(&relay, p, &f),
                    ["flakelets", name] => pages::flakelet(&relay, p, name),
                    _ => pages::flakelets(&relay, p, &f),
                };
                sse_html(&body)
            } else {
                String::from(":\n\n")
            };
            if tx.send(bytes::Bytes::from(chunk)).await.is_err() {
                return;
            }
        }
    });
    Response::builder()
        .header(hyper::header::CONTENT_TYPE, "text/event-stream")
        .header(hyper::header::CACHE_CONTROL, "no-cache")
        .header("X-Accel-Buffering", "no")
        .body(body)
        .expect("static headers")
}

/// One unnamed SSE message, a `data:` line per line of markup. `split`,
/// not `lines`: the client rejoins with LF and drops the last one, so a
/// trailing newline in `<pre>` content needs its own empty `data:`.
fn sse_html(m: &Markup) -> String {
    let mut out = String::new();
    for line in m.0.split('\n') {
        out.push_str("data: ");
        out.push_str(line);
        out.push('\n');
    }
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_keeps_trailing_newline() {
        let ev = sse_html(&html! { span { "a" } " b\n" });
        assert_eq!(ev, "data: <span>a</span> b\ndata: \n\n");
    }
}
