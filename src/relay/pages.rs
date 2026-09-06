//! Dashboard page bodies and the `?q=` filter they share.

use std::collections::{BTreeMap, BTreeSet};

use maud::{Markup, html};

use crate::auth::policy::glob;
use crate::proto::{self, JobRef, JobState, JobSummary, Status};
use crate::relay::login::now;
use crate::relay::state::{HostFlakelet, Relay};

/// `key:value` tokens and bare words from the search box. Values are
/// globs; bare words match as substrings anywhere.
pub(crate) struct Filter {
    terms: Vec<(String, String)>,
    words: Vec<String>,
    pub raw: String,
}

impl Filter {
    pub(crate) fn parse(q: &str) -> Self {
        let mut f = Filter {
            terms: Vec::new(),
            words: Vec::new(),
            raw: q.to_owned(),
        };
        for tok in q.split_whitespace() {
            match tok.split_once(':') {
                Some((k, v)) if !v.is_empty() => f.terms.push((k.to_owned(), v.to_owned())),
                _ => f.words.push(tok.to_lowercase()),
            }
        }
        f
    }

    /// True if every `key:` term matches one of `values(key)` and every
    /// bare word is a substring of `text`.
    fn matches(&self, values: impl Fn(&str) -> Vec<String>, text: &str) -> bool {
        let text = text.to_lowercase();
        self.terms
            .iter()
            .all(|(k, v)| values(k).iter().any(|x| glob(v, x)))
            && self.words.iter().all(|w| text.contains(w.as_str()))
    }

    /// The query with `key:value` toggled, for facet links.
    fn toggle(&self, key: &str, value: &str) -> String {
        let mut parts: Vec<String> = self
            .terms
            .iter()
            .filter(|(k, v)| !(k == key && v == value))
            .map(|(k, v)| format!("{k}:{v}"))
            .collect();
        if parts.len() == self.terms.len() {
            parts.retain(|p| !p.starts_with(&format!("{key}:")));
            parts.push(format!("{key}:{value}"));
        }
        parts.extend(self.words.iter().cloned());
        parts.join(" ")
    }

    fn has(&self, key: &str, value: &str) -> bool {
        self.terms.iter().any(|(k, v)| k == key && v == value)
    }
}

pub(crate) fn ago(ts: u64) -> String {
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

fn last_state(j: Option<&JobRef>) -> (&'static str, &'static str) {
    j.map_or(("never", "never deployed"), |j| state_of(j.state, j.status))
}

fn short_rev(r: &str) -> &str {
    let (path, query) = r.split_once('?').unwrap_or((r, ""));
    let tail = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("rev="))
        .or_else(|| path.rsplit(['/', ':']).next())
        .unwrap_or(path);
    &tail[..tail.len().min(12)]
}

/// Element id for a target; hex because host and flakelet names may
/// contain characters that are awkward in CSS selectors.
pub(crate) fn target_id(target: &str) -> String {
    format!("t-{}", proto::hex(target.as_bytes()))
}

fn pill(target: &str, state: JobState, status: Option<Status>) -> Markup {
    let (cls, label) = state_of(state, status);
    html! { span class={"pill " (cls)} { (target) span.sr { ": " } " " span.l { (label) } } }
}

pub(crate) fn target_row(target: &str, state: JobState, status: Option<Status>) -> Markup {
    html! { li id=(target_id(target)) { (pill(target, state, status)) } }
}

fn search(f: &Filter, placeholder: &str) -> Markup {
    html! {
        form.search role="search" method="get" {
            label.sr for="q" { "Filter" }
            input #q type="search" name="q" value=(f.raw) placeholder=(placeholder);
        }
    }
}

/// A flakelet across the hosts it runs on, with the roll-up status the
/// list and the facets use.
struct Group<'a> {
    name: &'a str,
    hosts: Vec<&'a HostFlakelet>,
    status: &'static str,
    bad: usize,
    revs: BTreeSet<&'a str>,
    last: Option<&'a JobRef>,
}

fn group<'a>(name: &'a str, hosts: Vec<&'a HostFlakelet>) -> Group<'a> {
    let bad = hosts
        .iter()
        .filter(|h| last_state(h.last.as_ref()).0 == "failed")
        .count();
    let running = hosts
        .iter()
        .any(|h| last_state(h.last.as_ref()).0 == "running");
    let revs: BTreeSet<&str> = hosts.iter().filter_map(|h| h.revision.as_deref()).collect();
    let status = if running {
        "updating"
    } else if bad > 0 {
        "degraded"
    } else if revs.len() > 1 {
        "drift"
    } else {
        "healthy"
    };
    let last = hosts
        .iter()
        .filter_map(|h| h.last.as_ref())
        .max_by_key(|j| j.created);
    Group {
        name,
        hosts,
        status,
        bad,
        revs,
        last,
    }
}

fn groups(rows: &[HostFlakelet]) -> Vec<Group<'_>> {
    let mut by: BTreeMap<&str, Vec<&HostFlakelet>> = BTreeMap::new();
    for r in rows {
        by.entry(&r.flakelet).or_default().push(r);
    }
    by.into_iter().map(|(n, h)| group(n, h)).collect()
}

pub(crate) fn flakelets(relay: &Relay, principals: &[String], f: &Filter) -> Markup {
    let rows = relay.host_flakelets(principals);
    let all = groups(&rows);
    let count = |s: &str| all.iter().filter(|g| g.status == s).count();
    let shown: Vec<&Group> = all
        .iter()
        .filter(|g| {
            f.matches(
                |k| match k {
                    "status" => vec![g.status.to_owned()],
                    "host" => g.hosts.iter().map(|h| h.host.clone()).collect(),
                    "flakelet" => vec![g.name.to_owned()],
                    _ => Vec::new(),
                },
                g.name,
            )
        })
        .collect();
    html! { main {
        .bar {
            @for s in ["degraded", "updating", "drift", "healthy"] {
                a class={"chip " (s) @if f.has("status", s) { " on" }} href={"?q=" (f.toggle("status", s))}
                    aria-pressed=(f.has("status", s)) { b { (count(s)) } " " (s) }
            }
            .sep {}
            (search(f, "name, host:web* status:degraded"))
        }
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
                @if shown.is_empty() { tr { td colspan="6" .dim { "Nothing matches." } } }
                @for g in &shown { (flakelet_row(g)) }
            }
        }
    } }
}

fn flakelet_row(g: &Group) -> Markup {
    html! { tr {
        th scope="row" .name { a href={"/ui/flakelets/" (g.name)} { (g.name) } }
        td {
            span.sq aria-hidden="true" {
                @for h in &g.hosts { @let (c, l) = last_state(h.last.as_ref()); span class=(c) title={(h.host) ": " (l)} {} }
            }
            (g.hosts.len() - g.bad) "/" (g.hosts.len())
            span.sr { " hosts ok" }
        }
        td.mono {
            @match g.revs.len() {
                0 => span.faint { "–" },
                1 => { @let r = g.revs.first().copied().unwrap_or_default(); span title=(r) { (short_rev(r)) } },
                n => span.st.drift { (n) " revisions" },
            }
        }
        td {
            @if let Some(j) = g.last {
                (ago(j.created))
                @if let Some(c) = j.caller_name() { span.dim title=[j.caller.as_deref()] { " by " (c) } }
            } @else { span.faint { "–" } }
        }
        td { span class={"pill " (g.status)} { (g.status) } }
        td.act { (update_button(g.name, g.hosts.len())) }
    } }
}

fn update_button(name: &str, n: usize) -> Markup {
    html! {
        button hx-post={"/ui/deploy?arg=" (name)} hx-target="#main" hx-select="#main" hx-swap="outerHTML"
            hx-confirm={"Run flakelet update " (name) " on " (n) " host(s) now?"}
            { "Update now" }
    }
}

/// One flakelet: where it runs and its recent deploys.
pub(crate) fn flakelet(relay: &Relay, principals: &[String], name: &str) -> Markup {
    let rows = relay.host_flakelets(principals);
    let hosts: Vec<&HostFlakelet> = rows.iter().filter(|h| h.flakelet == name).collect();
    let g = group(name, hosts);
    let history: Vec<JobSummary> = relay
        .job_summaries(principals)
        .into_iter()
        .filter(|j| {
            j.targets
                .iter()
                .any(|t| t.target.ends_with(&format!("/{name}")))
        })
        .take(20)
        .collect();
    html! { main {
        .bar {
            h2 { (name) " " span class={"pill " (g.status)} { (g.status) } }
            .sep {}
            (update_button(name, g.hosts.len()))
        }
        h3 { "Hosts" }
        table {
            thead { tr { th scope="col" { "Host" } th scope="col" { "Generation" } th scope="col" { "Revision" } th scope="col" { "Last deploy" } th scope="col" { "State" } } }
            tbody {
                @if g.hosts.is_empty() { tr { td colspan="5" .dim { "No connected host runs this flakelet." } } }
                @for h in &g.hosts {
                    @let (c, l) = last_state(h.last.as_ref());
                    tr {
                        th scope="row" { (h.host) }
                        td { @if let Some(n) = h.generation { (n) } @else { span.faint { "–" } } }
                        td.mono { @if let Some(r) = &h.revision { span title=(r) { (short_rev(r)) } } @else { span.faint { "–" } } }
                        td { @if let Some(j) = &h.last { a href={"/ui/jobs/" (j.client_id.as_deref().unwrap_or_default())} { (ago(j.created)) } } @else { span.faint { "–" } } }
                        td { span class={"pill " (c)} { (l) } }
                    }
                }
            }
        }
        h3 { "History" }
        (job_table(&history))
    } }
}

pub(crate) fn hosts(relay: &Relay, principals: &[String], f: &Filter) -> Markup {
    let agents = relay.visible_agents(principals);
    let missing = relay.missing_hosts(principals);
    let keep = |host: &str, names: Vec<String>, state: &str| {
        f.matches(
            |k| match k {
                "host" => vec![host.to_owned()],
                "flakelet" => names.clone(),
                "status" => vec![state.to_owned()],
                _ => Vec::new(),
            },
            host,
        )
    };
    html! { main {
        .bar { .sep {} (search(f, "host, flakelet:app status:disconnected")) }
        table {
            caption.sr { "Hosts" }
            thead { tr { th scope="col" { "Host" } th scope="col" { "Agent" } th scope="col" { "Flakelets" } th scope="col" { "State" } } }
            tbody {
                @for a in &agents {
                    @if keep(&a.host, a.flakelets.iter().map(|f| f.name.clone()).collect(), "connected") {
                        tr {
                            th scope="row" .name { (a.host) }
                            td.dim { (a.version) }
                            td.wrap {
                                @for fl in &a.flakelets {
                                    a.tag href={"/ui/flakelets/" (fl.name)} { (fl.name) @if let Some(n) = fl.generation { span.faint { "@" (n) } } } " "
                                }
                            }
                            td { span.pill.ok { "connected" } }
                        }
                    }
                }
                @for h in &missing {
                    @if keep(h, Vec::new(), "disconnected") {
                        tr.off {
                            th scope="row" .name { (h) }
                            td.faint { "–" }
                            td.faint { "–" }
                            td { span.pill.failed { "disconnected" } }
                        }
                    }
                }
                @if agents.is_empty() && missing.is_empty() { tr { td colspan="4" .dim { "No hosts." } } }
            }
        }
    } }
}

fn job_table(jobs: &[JobSummary]) -> Markup {
    html! {
        table {
            caption.sr { "Deploys, newest first" }
            thead { tr { th scope="col" { "When" } th scope="col" { "Caller" } th scope="col" { "Targets" } th scope="col" { "Id" } } }
            tbody {
                @if jobs.is_empty() { tr { td colspan="4" .dim { "No deploys." } } }
                @for j in jobs {
                    tr {
                        td { (ago(j.created)) }
                        td.trunc title=(j.caller) { (j.caller_name) }
                        td.wrap { @for t in &j.targets { (pill(&t.target, t.state, t.status)) " " } }
                        td.mono { a href={"/ui/jobs/" (j.id)} { (j.id.get(..8).unwrap_or(&j.id)) } }
                    }
                }
            }
        }
    }
}

pub(crate) fn jobs(relay: &Relay, principals: &[String], f: &Filter) -> Markup {
    let jobs: Vec<JobSummary> = relay
        .job_summaries(principals)
        .into_iter()
        .filter(|j| {
            let targets: Vec<String> = j.targets.iter().map(|t| t.target.clone()).collect();
            f.matches(
                |k| match k {
                    "caller" => std::iter::once(j.caller_name.clone())
                        .chain(j.caller.lines().map(str::to_owned))
                        .collect(),
                    "target" => targets.clone(),
                    "host" => targets
                        .iter()
                        .filter_map(|t| t.split_once('/'))
                        .map(|x| x.0.to_owned())
                        .collect(),
                    "flakelet" => targets
                        .iter()
                        .filter_map(|t| t.split_once('/'))
                        .map(|x| x.1.to_owned())
                        .collect(),
                    "status" => j
                        .targets
                        .iter()
                        .map(|t| state_of(t.state, t.status).1.to_owned())
                        .collect(),
                    _ => Vec::new(),
                },
                &format!(
                    "{} {} {} {}",
                    j.id,
                    j.caller_name,
                    j.caller,
                    targets.join(" ")
                ),
            )
        })
        .take(200)
        .collect();
    html! { main {
        .bar { .sep {} (search(f, "caller:*ci* host:web1 status:failed")) }
        (job_table(&jobs))
    } }
}

/// Retry button once a deploy has ended with failures.
pub(crate) fn job_actions(id: &str, ok: Option<bool>) -> Markup {
    html! {
        div #actions {
            @if ok == Some(false) {
                button hx-post={"/ui/retry?arg=" (id)} hx-target="#main" hx-select="#main" hx-swap="outerHTML"
                    hx-confirm="Run the failed targets again?" { "Retry failed" }
            }
        }
    }
}

pub(crate) fn job(relay: &Relay, principals: &[String], id: &str) -> Markup {
    let summary = relay
        .job_summaries(principals)
        .into_iter()
        .find(|j| j.id == id);
    let ok = summary
        .as_ref()
        .filter(|j| j.finished.is_some())
        .map(|j| j.targets.iter().all(|t| t.status.is_some_and(Status::ok)));
    html! { main.job {
        .bar {
            h2 { "Deploy " span.mono { (id.get(..8).unwrap_or(id)) } }
            @if let Some(j) = &summary {
                span.dim { (ago(j.created)) " by " span title=(j.caller) { (j.caller_name) } }
            }
            .sep {}
            (job_actions(id, ok))
        }
        ul.targets #targets aria-live="polite" {
            @for t in summary.iter().flat_map(|j| &j.targets) {
                (target_row(&t.target, t.state, t.status))
            }
        }
        h3 { "Log" }
        pre.log #log role="log" aria-live="off"
            hx-sse:connect={"/ui/jobs/" (id) "/events"} hx-swap="beforeend" hx-sse:close="result" {}
    } }
}

#[cfg(test)]
mod tests {
    use super::{Filter, short_rev};

    #[test]
    fn short_rev_uses_rev_not_nar_hash() {
        assert_eq!(
            short_rev(
                "github:Mic92/tribuchet/71caf5d75be693a72299de34fd4a8f538f2deba4?narHash=sha256-1BkNm4b%3D"
            ),
            "71caf5d75be6"
        );
        assert_eq!(short_rev("git+https://x/y?ref=main&rev=abc"), "abc");
        assert_eq!(short_rev("abc"), "abc");
    }

    #[test]
    fn filter_terms_words_and_toggle() {
        let f = Filter::parse("status:degraded host:web* api");
        let vals = |k: &str| match k {
            "status" => vec!["degraded".to_owned()],
            "host" => vec!["web1".to_owned(), "db".to_owned()],
            _ => Vec::new(),
        };
        assert!(f.matches(vals, "my-API"));
        assert!(!f.matches(vals, "worker"));
        assert!(!Filter::parse("status:healthy").matches(vals, "api"));
        assert_eq!(f.toggle("status", "degraded"), "host:web* api");
        assert_eq!(f.toggle("status", "drift"), "host:web* status:drift api");
        assert!(f.has("host", "web*"));
    }
}
