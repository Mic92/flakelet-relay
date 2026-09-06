# flakelet-relay

flakelet-relay lets CI trigger `flakelet update` on hosts it cannot
reach, and returns the log and result.

## Problem

flakelet hosts update themselves on a timer. This is robust but slow:
after CI has built a new revision it can take a full timer interval to
go live, and CI never learns whether it worked. CI cannot connect to
the hosts to speed this up because they sit behind NAT and firewalls.

## Solution

Hosts dial out. Each runs `flakelet-agent`, which keeps a WebSocket
open to one or more `flakelet-relay`s. CI runs `flakelet-push`, which
asks any relay to have a host run `flakelet update <name>` and streams
the output back.

```
CI ──HTTPS──▶ relay A ◀──WSS── agent (web1)
   └────────▶ relay B ◀──WSS── agent (web2)
```

- **flakelet-relay** authenticates both sides, applies policy and
  forwards. Its only state is config, memory and a JWKS cache file, so
  several can run side by side and any one can be lost.
- **flakelet-agent** runs updates for an allowlist of local flakelets
  and keeps a job table on disk. It is the source of truth for what
  happened.
- **flakelet-push** posts a deploy, follows the stream, and retries or
  fails over between relays.

The `autoUpdate` timer stays enabled. If every relay is down, updates
are late, not lost.

Non-goals: switching NixOS systems, shipping closures, pinning
revisions, running arbitrary commands, macOS, queuing work for offline
agents.

## Trust model

An agent does what a relay tells it. The only instruction that exists
is "run `flakelet update` for a flakelet on your allowlist". A stolen
relay key therefore lets an attacker make hosts update early from the
flake ref they already trust, and nothing else.

This is the reason revisions and store paths are non-goals. If a relay
could say what to deploy, the agent would have to verify the CI
credential end to end, and the relay could no longer be a simple
forwarder.

## Identity

Authentication reduces every connection to a set of principal strings. A policy
rule matches if any principal matches.

- An OIDC bearer token yields `oidc:<issuer>:<sub>`, plus
  `oidc:<issuer>:<claim>:<value>` for each claim listed in
  `principalClaims` (one per element for list claims).
- A TLS client certificate yields one principal per SAN:
  `x509:dns:web1.internal`, `x509:email:root@example.org`, `x509:uri:…`.

No principal means 401.

Bearer tokens are valid for their whole lifetime, so keep CI tokens
short-lived. The relay caches JWKS on disk and will use a stale copy
for a while, so an issuer outage does not stop deploys. Agents without
certificates can use `tokenCommand`. Humans can run `push login`,
which does the OAuth2 device flow and caches the token.

## Listeners and certificates

The relay has two listeners:

- **Client API**: plain HTTP on localhost behind a reverse proxy.
  Bearer tokens only.
- **Agent endpoint**: TLS with optional client certificates checked
  against configured CAs. `push` with a client certificate uses this
  one too.

Clients verify the relay against `--ca-file` or the WebPKI roots. The
agent reloads its own certificate when the file changes.

## Finding relays

Both `push` and the agent accept `--relay <url>` (repeatable) and
`--relay-srv <domain>`. The SRV form resolves
`_flakelet-relay._tcp.<domain>` into `https://<target>:<port>` entries
ordered by priority and weight.

`push` tries them in order. The agent connects to all of them and
re-resolves when the TTL expires, so adding a relay is a DNS change. A
failed lookup keeps the previous set. TLS is verified against the SRV
target name, which means DNS can only send agents to hosts holding a
certificate from the pinned CA.

## Policy

An example relay config:

```nix
{
  issuers.ci  = { url = "https://ci.example.org"; audience = "flakelet-relay"; };
  issuers.sso = { url = "https://auth.example.org"; audience = "flakelet-relay";
                  principalClaims = [ "email" "groups" ]; login.clientId = "flakelet-relay"; };

  agents = {                       # host id → principals allowed to be it
    hub  = [ "x509:dns:hub.internal" ];
    web1 = [ "x509:dns:web1.internal" ];
    web2 = [ "x509:dns:web2.internal" ];
  };
  groups.web = [ "web1" "web2" ];

  rules = {                        # name → who may deploy which host/flakelet
    app.principals   = [ "oidc:ci:repo:github:example/app:ref:refs/heads/main" ];
    app.targets      = [ "hub/app-hub" "@web/app-worker" ];
    infra.principals = [ "oidc:ci:repo:github:example/infra:ref:refs/heads/main" ];
    infra.targets    = [ "@web/*" ];
    admin.principals = [ "x509:email:root@example.org" "oidc:sso:groups:admin" ];
    admin.targets    = [ "*/*" ];
  };
}
```

Rules are allow-only, unordered and use globs. Rule names show up in
logs and metrics. They are applied in three places:

- **Deploy**: every requested target must be covered, else 403 listing
  the uncovered ones.
- **Read** (`/v1/jobs`, `/v1/agents`, dashboard): the same check per
  target. Logs contain whatever the service printed, so read access is
  worth restricting.
- **Agent**: the host id is the single `agents.<host>` entry the
  connection's principals match. The agent never names itself. If a
  live connection for that host already exists, the newcomer gets 409.

On top of this the agent has its own `flakelets` allowlist, which is
also what it advertises in `hello`.

`flakelet-relay check-policy <config> <principal>... -- <target>...`
evaluates the rules offline. The flakelet runs it at build time for
`policyChecks`, so a policy mistake fails the update rather than a
deploy.

The relay itself is a flakelet so it deploys through its own agents;
the agent is a NixOS module because it drives `flakelet`.

## Wire format rules

These rules apply to HTTP bodies, SSE events and WebSocket frames. Their
purpose is to let the protocol grow without version bumps.

- List elements are always objects (`{"target": …}`, `{"line": …}`),
  never bare values, so a field can be added anywhere.
- Unknown fields and message types are ignored. Fields are added, never
  redefined. Unknown enum values map to the safe side.
- WS frames are `{"type": …}`. SSE uses `event:` with JSON `data:`.
  HTTP errors are `{"code", "message", …}`.
- `hello`, `welcome` and `accepted` carry `capabilities`. Features are
  negotiated by name and `version` is informational. `/v1/` only bumps
  for something capabilities cannot express.

## HTTP API

### POST /v1/deploy

The request names a client-chosen id and one or more waves of targets:

```json
{"id": "<client uuid>",
 "waves": [
   {"targets": [{"target": "web1/app-worker"}]},
   {"targets": [{"target": "web2/app-worker"}, {"target": "hub/app-hub"}]}
 ],
 "options": {}}
```

Targets within a wave run in parallel. The next wave starts only if
every target in the previous one ended `updated` or `unchanged`. On the
command line this is `push deploy web1/app-worker --wave web2/app-worker
hub/app-hub`.

The host part may be a glob or `@group` (as in policy targets). The
relay expands it to every configured agent the caller may deploy that
flakelet on; targets already named in an earlier wave are dropped, so
`web1/app --wave '*/app'` is a canary. Matching agents that are not
connected end up in `result.targets` with status `offline` and make the
job fail; a pattern that matches nothing is `404 no_targets`.

The response is an SSE stream:

```
accepted {job, relay: {name, version, capabilities}, agents: [{host, version, capabilities}]}
wave     {index}
log      {target, seq, line}
progress {target}
done     {target, status, generation?, tail?: [{line}]}
result   {ok, targets: [{target, status}], skipped: [{target}]}
```

`progress` arrives periodically while a unit runs, so a client can
tell a slow update from a dead stream.

Per-target status is `updated`, `unchanged`, `rolled-back` or `failed`.
`unchanged` counts as success because the timer may have got there
first. `ok` is true when every target is `updated` or `unchanged`.
Targets in waves that never started are listed under `skipped`. There
is no rollback across targets.

The job id is `hash(caller identity, client id)`. Retrying with the
same id is idempotent, and another caller cannot collide with or attach
to your job.

Errors before the stream starts:

| status | code | when |
|---|---|---|
| 403 | `target_denied` | a target is not covered by the caller's rules |
| 404 | `unknown_host` | the relay has no `agents` entry for a host |
| 503 | `agent_unavailable` | the agent is not connected right now. `push` retries with backoff, then moves to the next relay |
| 400 | `unsupported_option` | an option needs a capability a targeted agent lacks |

All carry `targets: [...]` naming the offending ones.

### GET /v1/jobs/{client id}

Re-derives the job id, sends `query` for it to every flakelet the
caller may read, and streams whatever the agents that know it have, as
a single wave. 404 `unknown_job` if none answers. This is where `push`
goes when its deploy stream breaks. It skips lines it has already
printed.

### GET /v1/agents, GET /v1/jobs

```
{"agents": [{host, version, capabilities, flakelets: [{name, generation?, revision?}]}]}
{"jobs":   [{id, caller, created, finished?, targets: [{target, state, status?, generation?}]}]}
```

Both are filtered by read policy. `jobs` groups the agents' job tables
by caller and client id, newest first.

## Agent protocol

A WebSocket at `/v1/agent` carrying one JSON object per text frame,
kept alive with WS pings:

```
← welcome  {host, relay: {name, version, capabilities}}
→ hello    {version, capabilities, flakelets: [{name, generation?, revision?}],
            jobs: [{id, flakelet, state, caller?, client_id?, created, finished?, status?, generation?, revision?}]}
← start    {id, flakelet, rule, caller?, client_id?, options: {}}
→ ack      {id, accepted, reason?}
→ log      {id, seq, line}
→ progress {id}
→ done     {id, status, generation?, tail?: [{line}]}
← query    {id}            (answered like a known start, or error unknown_job)
→ job      {job: {…as in hello}}   (on every state change, to all relays)
↔ error    {id?, code, message}
```

`deploy.options` becomes `start.options`. An option is forwarded only
if every targeted agent advertises the capability, otherwise the deploy
is rejected with 400.

Three mechanisms keep the stream intact across disconnects and
concurrent callers:

- **Replay.** A `start` with an id the agent already knows replays
  that job's ack, log and result instead of running again.
- **Re-send on reconnect.** When an agent reconnects, the relay
  re-sends `start` for every target it is still waiting on. Combined
  with replay, lines logged while the link was down still reach the
  client. The relay drops lines whose `seq` it has already forwarded.
- **Coalescing.** Concurrent `start`s for one flakelet do not queue up.
  New ids attach to a single follow-up run and receive the output of
  the first run that begins after they arrived.

Logs are capped per job at the agent.

## Agent execution

The agent does not run `flakelet update` as a child process. It starts
a transient unit, `flakelet-relay-job-<flakelet>.service`, and follows
its journal from a saved cursor. There are three reasons:

1. The update serialises with the timer through flakelet's per-service
   lock.
2. It survives an agent restart. The agent may be the service being
   updated.
3. Following a live job and reattaching after a restart are the same
   code path.

Each job is a file, `$STATE_DIRECTORY/jobs/<id>.json`, holding
flakelet, caller, client id, journal cursor, generation before, state,
logs and result. Retention is configurable and logs expire before
summaries. On start the agent resumes running entries by following
their unit until it is gone, and starts pending ones. The result
reaches the relay through the replay that its re-sent `start` triggers.

Relays store none of this, by design. `hello` carries recent job summaries per
flakelet, and every state change goes out as a `job` frame to all
connected relays. That is enough for any relay to answer `GET /v1/jobs`
and to know each flakelet's current generation and revision, including
for deploys that went through a different relay. Updates that bypass
the relays entirely (flakelet's auto-update timer, a manual `flakelet
update`, host activation) are picked up by polling `flakelet status`
every `statusInterval` seconds and sent as a `flakelets` frame when the
answer changed.

Deciding the result: a failed unit is `failed`. Otherwise the
agent compares generation and health from `flakelet status --json`
before and after. `failed` and `rolled-back` include the last journal
lines of the flakelet's units as `tail`, so the caller can see the
cause without shell access.

The agent signals readiness once config and job table are loaded,
regardless of relay connectivity. Otherwise a relay outage during an
agent self-update would look like a failed start and get rolled back.

## Failure handling

| failure | behaviour |
|---|---|
| relay down | `push` tries the next one |
| relay dies mid-stream | `push` resumes via `GET /v1/jobs/<id>` on another relay |
| relay restarted, agents not back yet | 503, `push` retries with backoff |
| agent offline | 503, the timer catches up later |
| agent restarts mid-job | unit keeps running, agent reattaches and reports |
| same job via two relays | same id, agent dedups |
| concurrent pushes, one flakelet | coalesced into the current run plus one follow-up |
| timer races a push | flakelet lock serialises them, push may see `unchanged` |
| update breaks connectivity | flakelet's health check rolls the service back. `rolled-back` is reported on reconnect, or `push` hits its idle timeout |
| target in wave 1 fails | later waves are not started and listed as `skipped` |

## Observability

The relay serves Prometheus text on `/metrics` (plain listener only),
prefix `flakelet_relay_`:

| metric | labels | meaning |
|---|---|---|
| `agent_up` | host | 1 while a connection for that host is registered |
| `agent_info` | host, version | constant 1, for version inventory |
| `deploys_total` | rule, host, flakelet, status | finished targets, status as on the wire |

The agent reports connected relays and its last result through
sd-notify `STATUS=`, visible in `systemctl status flakelet-agent`.

## Dashboard

The relay serves a read-only HTML view of the same data under `/ui/`.
Browser login is the OIDC authorization code flow with PKCE against any
issuer that has `login.clientId` set, and that client id is also
accepted as a token audience. The `id_token` goes through the same JWKS
and claim mapping as a bearer token, and the resulting principals are
kept in an HMAC-signed cookie. There is no server-side session store,
so a relay restart logs everyone out. A session is just another source
of principals: the JSON API accepts the cookie too, and the pages show
exactly what `/v1/agents` and `/v1/jobs` would return to that user.
