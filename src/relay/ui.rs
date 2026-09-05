//! Server-rendered dashboard under `/ui/`: routing, pages and the job
//! event stream as HTML fragments for htmx.

use std::collections::BTreeMap;
use std::sync::Arc;

use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use maud::{DOCTYPE, Markup, html};

use crate::http::{self, Resp};
use crate::proto::{self, DeployRequest, Event, JobState, Status, Target, Wave};
use crate::relay::api;
use crate::relay::login::{self, Session, now};
use crate::relay::state::{HostFlakelet, Relay};

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
        .body(http::Body::empty())
        .expect("static headers")
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
            &html! { main { p.notice { (msg) } p { a href="/ui/login" { "Log in again" } } } },
        ),
    )
}

/// Raw query parameter. All values handled here are URL-safe tokens.
pub(crate) fn query<'a>(req: &'a Request<Incoming>, key: &str) -> Option<&'a str> {
    req.uri().query()?.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then_some(v)
    })
}

pub(crate) fn with_cookie(mut r: Resp, cookie: &str) -> Resp {
    r.headers_mut().append(
        hyper::header::SET_COOKIE,
        cookie.parse().expect("cookie is ascii"),
    );
    r
}

pub async fn handle(relay: Arc<Relay>, req: Request<Incoming>) -> Resp {
    let path = req.uri().path()["/ui/".len()..].to_owned();
    let seg: Vec<&str> = path.split('/').collect();
    match (req.method(), seg.as_slice()) {
        (&Method::GET, ["static", f]) => match STATIC.iter().find(|(n, ..)| n == f) {
            Some((_, mime, data)) => Response::builder()
                .header(hyper::header::CONTENT_TYPE, *mime)
                .header(hyper::header::CACHE_CONTROL, "max-age=3600")
                .body(http::Body::Full(Some(bytes::Bytes::from_static(data))))
                .expect("static headers"),
            None => fail(StatusCode::NOT_FOUND, "no such file"),
        },
        (&Method::GET, ["login"]) => login::start(&relay, &req).await,
        (&Method::GET, ["callback"]) => login::callback(&relay, &req).await,
        (&Method::POST, ["logout"]) => login::logout(),
        (&Method::POST, ["deploy"]) => deploy(relay, &req),
        (&Method::GET, rest) => {
            let Some(sess) = login::current(&relay, &req) else {
                return redirect("/ui/login");
            };
            let p = &sess.principals;
            let (tab, body) = match rest {
                [""] => ("", flakelets_page(&relay, p)),
                ["hosts"] => ("hosts", hosts_page(&relay, p)),
                ["jobs"] => ("jobs", jobs_page(&relay, p)),
                ["jobs", id] => ("jobs", job_page(&relay, p, id)),
                ["jobs", id, "events"] => return job_events(relay.clone(), p, id).await,
                _ => return fail(StatusCode::NOT_FOUND, "no such page"),
            };
            page(
                StatusCode::OK,
                &layout(&relay.cfg.name, Some(&sess), tab, &body),
            )
        }
        _ => fail(StatusCode::NOT_FOUND, "no such page"),
    }
}

fn layout(name: &str, sess: Option<&Session>, tab: &str, body: &Markup) -> Markup {
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
                            "Signed in as " b { (s.name) } " "
                            button { "Log out" }
                        }
                    }
                }
                div #main tabindex="-1" { (body) }
            }
        }
    }
}

fn ago(ts: u64) -> String {
    let d = now().saturating_sub(ts);
    match d {
        0..60 => format!("{d}s ago"),
        60..3600 => format!("{}m ago", d / 60),
        3600..86_400 => format!("{}h ago", d / 3600),
        _ => format!("{}d ago", d / 86_400),
    }
}

/// CSS class and label for one target's state.
fn state_of(state: JobState, status: Option<Status>) -> (&'static str, &'static str) {
    match (state, status) {
        (JobState::Pending, _) => ("running", "pending"),
        (JobState::Running, _) => ("running", "updating"),
        (JobState::Done, Some(s)) => (if s.ok() { "ok" } else { "failed" }, s.as_str()),
        (JobState::Done | JobState::Unknown, _) => ("failed", "unknown"),
    }
}

fn last_state(h: &HostFlakelet) -> (&'static str, &'static str) {
    h.last
        .as_ref()
        .map_or(("never", "never deployed"), |j| state_of(j.state, j.status))
}

fn short_rev(r: &str) -> &str {
    let tail = r.rsplit(['/', ':', '=']).next().unwrap_or(r);
    &tail[..tail.len().min(12)]
}

fn flakelets_page(relay: &Relay, principals: &[String]) -> Markup {
    let rows = relay.host_flakelets(principals);
    let mut by: BTreeMap<&str, Vec<&HostFlakelet>> = BTreeMap::new();
    for r in &rows {
        by.entry(&r.flakelet).or_default().push(r);
    }
    html! { main {
        table {
            caption.sr { "Flakelets across connected hosts" }
            thead { tr {
                th scope="col" { "Flakelet" }
                th scope="col" { "Hosts" }
                th scope="col" { "Revision" }
                th scope="col" { "Last deploy" }
                th scope="col" { "Status" }
                th scope="col" { span.sr { "Actions" } }
            } }
            tbody {
                @if by.is_empty() { tr { td colspan="6" .dim { "No connected host runs a flakelet you may see." } } }
                @for (name, hosts) in &by {
                    @let last = hosts.iter().filter_map(|h| h.last.as_ref()).max_by_key(|j| j.created);
                    @let revs: std::collections::BTreeSet<_> = hosts.iter().filter_map(|h| h.revision.as_deref()).collect();
                    @let bad = hosts.iter().filter(|h| last_state(h).0 == "failed").count();
                    @let running = hosts.iter().any(|h| last_state(h).0 == "running");
                    @let (cls, label) = if running { ("updating", "updating") }
                        else if bad > 0 { ("degraded", "degraded") }
                        else if revs.len() > 1 { ("drift", "drift") }
                        else { ("healthy", "healthy") };
                    tr {
                        th scope="row" .name { (name) }
                        td {
                            span.sq aria-hidden="true" {
                                @for h in hosts { span class=(last_state(h).0) title={(h.host) ": " (last_state(h).1)} {} }
                            }
                            (hosts.len() - bad) "/" (hosts.len())
                            span.sr { " hosts ok" }
                        }
                        td.mono {
                            @match revs.len() {
                                0 => span.faint { "–" },
                                1 => span title=(revs.first().unwrap()) { (short_rev(revs.first().unwrap())) },
                                n => span.st.drift { (n) " revisions" },
                            }
                        }
                        td {
                            @if let Some(j) = last {
                                (ago(j.created))
                                @if let Some(c) = &j.caller { span.dim title=(c) { " by " (short(c)) } }
                            } @else { span.faint { "–" } }
                        }
                        td { span class={"pill " (cls)} { (label) } }
                        td.act {
                            button hx-post={"/ui/deploy?flakelet=" (name)} hx-target="#main" hx-select="#main" hx-swap="outerHTML"
                                hx-confirm={"Run flakelet update " (name) " on " (hosts.len()) " host(s) now?"}
                                { "Update now" }
                        }
                    }
                }
            }
        }
    } }
}

fn hosts_page(relay: &Relay, principals: &[String]) -> Markup {
    let agents = relay.visible_agents(principals);
    html! { main {
        table {
            caption.sr { "Connected hosts" }
            thead { tr { th scope="col" { "Host" } th scope="col" { "Agent" } th scope="col" { "Flakelets" } } }
            tbody {
                @if agents.is_empty() { tr { td colspan="3" .dim { "No connected hosts." } } }
                @for a in &agents {
                    tr {
                        th scope="row" .name { (a.host) }
                        td.dim { (a.version) }
                        td {
                            @for f in &a.flakelets {
                                span.tag { (f.name) @if let Some(g) = f.generation { span.faint { "@" (g) } } } " "
                            }
                        }
                    }
                }
            }
        }
    } }
}

fn jobs_page(relay: &Relay, principals: &[String]) -> Markup {
    let jobs = relay.job_summaries(principals);
    html! { main {
        table {
            caption.sr { "Recent deploys, newest first" }
            thead { tr { th scope="col" { "When" } th scope="col" { "Caller" } th scope="col" { "Targets" } th scope="col" { "Id" } } }
            tbody {
                @if jobs.is_empty() { tr { td colspan="4" .dim { "No deploys recorded." } } }
                @for j in jobs.iter().take(200) {
                    tr {
                        td { (ago(j.created)) }
                        td.trunc title=(j.caller) { (short(&j.caller)) }
                        td.wrap {
                            @for t in &j.targets { (pill(&t.target, t.state, t.status)) " " }
                        }
                        td.mono { a href={"/ui/jobs/" (j.id)} { (j.id.get(..8).unwrap_or(&j.id)) } }
                    }
                }
            }
        }
    } }
}

/// "Update now": a one-wave deploy of `flakelet` on every host the user
/// may see it on. htmx always sends `HX-Request`, which a cross-site
/// form cannot, so together with `SameSite=Lax` that is the CSRF check.
fn deploy(relay: Arc<Relay>, req: &Request<Incoming>) -> Resp {
    let Some(sess) = login::current(&relay, req) else {
        return hx_redirect("/ui/login");
    };
    if req.headers().get("HX-Request").is_none() {
        return fail(StatusCode::FORBIDDEN, "not an htmx request");
    }
    let Some(flakelet) = query(req, "flakelet") else {
        return fail(StatusCode::BAD_REQUEST, "no flakelet");
    };
    let targets = relay
        .host_flakelets(&sess.principals)
        .into_iter()
        .filter(|h| h.flakelet == flakelet)
        .map(|h| Target {
            target: format!("{}/{}", h.host, h.flakelet),
        })
        .collect();
    let id = proto::random_id();
    let dr = DeployRequest {
        id: id.clone(),
        waves: vec![Wave { targets }],
        options: BTreeMap::default(),
    };
    match api::start_deploy(relay, &sess.principals, dr) {
        Ok(mut rx) => {
            // Keep consuming so later waves run. The job page attaches
            // through /ui/jobs/<id>/events.
            tokio::spawn(async move { while rx.recv().await.is_some() {} });
            hx_redirect(&format!("/ui/jobs/{id}"))
        }
        Err((status, e)) => fail(status, &format!("{}: {}", e.code, e.message)),
    }
}

fn hx_redirect(to: &str) -> Resp {
    Response::builder()
        .status(StatusCode::OK)
        .header("HX-Redirect", to)
        .body(http::Body::empty())
        .expect("static headers")
}

/// Element id for a target; hex because host and flakelet names may
/// contain characters that are awkward in CSS selectors.
fn target_id(target: &str) -> String {
    format!("t-{}", proto::hex(target.as_bytes()))
}

fn pill(target: &str, state: JobState, status: Option<Status>) -> Markup {
    let (cls, label) = state_of(state, status);
    html! { span class={"pill " (cls)} { (target) span.sr { ": " } " " span.l { (label) } } }
}

fn target_row(target: &str, state: JobState, status: Option<Status>) -> Markup {
    html! { li id=(target_id(target)) { (pill(target, state, status)) } }
}

/// First principal only; the full caller is in the title attribute.
fn short(caller: &str) -> &str {
    caller.lines().next().unwrap_or_default()
}

fn job_page(relay: &Relay, principals: &[String], id: &str) -> Markup {
    let summary = relay
        .job_summaries(principals)
        .into_iter()
        .find(|j| j.id == id);
    html! { main.job {
        h2 { "Deploy " span.mono { (id.get(..8).unwrap_or(id)) } }
        @if let Some(j) = &summary {
            p.dim { (ago(j.created)) " by " span title=(j.caller) { (short(&j.caller)) } }
        }
        ul.targets #targets aria-live="polite" {
            @if let Some(j) = &summary {
                @for t in &j.targets {
                    (target_row(&t.target, t.state, t.status))
                }
            }
        }
        h3 { "Log" }
        pre.log #log role="log" aria-live="off"
            hx-sse:connect={"/ui/jobs/" (id) "/events"} hx-swap="beforeend" hx-sse:close="result" {}
    } }
}

/// The job's event stream rendered as HTML fragments for the SSE
/// extension: unnamed messages are appended to the log, target state
/// changes ride along as `<hx-partial>`, and `result` closes the stream.
async fn job_events(relay: Arc<Relay>, principals: &[String], id: &str) -> Resp {
    let rx = match api::open_job(relay, principals, id).await {
        Ok(rx) => rx,
        Err(resp) => return resp,
    };
    api::sse_response(rx, encode_event)
}

fn encode_event(ev: &Event) -> String {
    let m: Markup = match ev {
        Event::Log { target, line, .. } => html! { span.t { (target) } " " (line) "\n" },
        Event::Done { target, body } => html! {
            hx-partial hx-target={"#" (target_id(target))} hx-swap="outerHTML" {
                (target_row(target, JobState::Done, Some(body.status)))
            }
            @for l in body.tail.iter().flatten() { span.tail { (target) " │ " (l.line) "\n" } }
        },
        Event::Accepted { .. } | Event::Wave { .. } | Event::Progress { .. } | Event::Unknown => {
            return String::from(":\n\n");
        }
        Event::Result { ok, .. } => {
            return format!("event: result\ndata: {ok}\n\n");
        }
    };
    let mut out = String::new();
    for line in m.into_string().lines() {
        out.push_str("data: ");
        out.push_str(line);
        out.push('\n');
    }
    out.push('\n');
    out
}
