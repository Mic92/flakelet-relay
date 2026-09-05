# flakelet-relay

CI tells hosts behind firewalls to run `flakelet update <name>` now and
gets the log and result back. Hosts dial out to one or more stateless
relays. CI talks to whichever relay answers.

```
CI ──HTTPS──▶ relay A ◀──WSS── agent (eliza)
   └────────▶ relay B ◀──WSS── agent (jamie)
```

- **flakelet-relay**: authenticates both sides, applies policy, forwards.
  State is config, RAM and a JWKS cache file.
- **flakelet-agent**: holds one WebSocket per configured relay, runs
  updates for an allowlist of local flakelets and keeps a job table on
  disk.
- **flakelet-push**: CLI for CI. Posts a deploy, follows the stream,
  retries and fails over between relays.

flakelet's `autoUpdate` timer stays enabled on hosts. With all relays
down updates are late, not lost.

Out of scope: switching NixOS systems, shipping closures or pinning
revisions, arbitrary commands, macOS, queuing for offline agents.

## Trust model

An agent does whatever a relay tells it, limited to `flakelet update` on
its allowlist. A stolen relay key therefore can make hosts update early
from their already configured flake ref, nothing more. Keeping it that
way is why revisions and store paths are out of scope. Those would need
the agent to verify the client credential itself.

## Identity

A connection yields a set of principals. A rule matches if any does.

- An OIDC bearer token gives `oidc:<issuer>:<sub>` and
  `oidc:<issuer>:<claim>:<value>` for each configured `principalClaims`
  entry, one per element for list claims. Authelia's `sub` is a UUID, so
  match on `email` or `groups` there. Tokens are bearer credentials for
  their whole lifetime, so keep CI tokens short. JWKS is cached on disk and used stale up to 24 h because nixbot
  is both issuer and deploy target.
- A TLS client cert gives one per SAN: `x509:dns:eliza.r`,
  `x509:email:joerg@thalheim.io`, `x509:uri:…`.

No principal means 401. Agents without certs can use `tokenCommand`.
`push login --issuer <url> --client-id <id>` does the OAuth2 device flow
and caches the `id_token` (plus refresh token if granted) in
`$XDG_STATE_HOME/flakelet-push/token.json`. Later calls without a cert or
token command use it and refresh it when it is about to expire.

## Listeners and certificates

- Client API: HTTP on localhost behind nginx :443 (ACME), bearer only.
- Agent endpoint: rustls on :7443 with optional client auth. Server
  cert and client CAs are configurable, step-ca on eve in this
  deployment. `push` with a client cert uses this port too.

Clients verify the relay against `--ca-file` or WebPKI. Agents get
step-ca ACME certs over `.r`, renewed by timer, reloaded on change.

## Finding relays

`push` and the agent take `--relay <url>` (repeatable) and/or
`--relay-srv <domain>`, which resolves `_flakelet-relay._tcp.<domain>`
into `https://<target>:<port>` entries ordered by priority and weight.
`push` walks the union. The agent connects to all of it and re-resolves
on TTL expiry, at most every 60 s, so adding a relay is a DNS change. Lookup
failure keeps the last set. Lookups go through the system resolver
(`res_query`), which works the same on glibc, musl and macOS. TLS is verified against the SRV target name,
so DNS can only point at hosts with a cert from the pinned CA. Records
live under `thalheim.io` to be resolvable from CI sandboxes.

## Policy

```nix
services.flakelet-relay.settings = {
  tls.clientCAs = [ ./step-ca-root.crt ];
  issuers.nixbot = { url = "https://nixbot.thalheim.io"; audience = "flakelet-relay"; };
  issuers.authelia = { url = "https://auth.thalheim.io"; audience = "flakelet-relay"; principalClaims = [ "email" "groups" ]; };

  agents = {                       # host id → principals allowed to be it
    eve   = [ "x509:dns:eve.r" ];
    eliza = [ "x509:dns:eliza.r" ];
    jamie = [ "x509:dns:jamie.r" ];
  };
  groups.tum = [ "eliza" "jamie" ];

  rules = {                        # name → who may deploy which host/flakelet
    tribuchet.principals = [ "oidc:nixbot:repo:github:Mic92/tribuchet:ref:refs/heads/main" ];
    tribuchet.targets    = [ "eve/tribuchet-hub" "@tum/tribuchet-worker" ];
    doctor.principals    = [ "oidc:nixbot:repo:github:TUM-DSE/doctor-cluster-config:ref:refs/heads/master" ];
    doctor.targets       = [ "@tum/*" ];
    nixbot.principals    = [ "oidc:nixbot:repo:github:Mic92/nixbot:ref:refs/heads/main" ];
    nixbot.targets       = [ "*/nixbot" ];
    admin.principals     = [ "x509:email:joerg@thalheim.io" "oidc:authelia:groups:admin" ];
    admin.targets        = [ "*/*" ];
  };
};
```

Globs, allow-only, unordered. Rule names label logs and metrics.

- Deploy: all requested targets covered or 403 with the uncovered ones.
- Read (`/v1/jobs`, `/v1/agents`): same check per target. Logs may
  contain whatever the service printed.
- Agent: the host id is the single `agents.<host>` entry the principals
  match. The agent never names itself. An existing connection for that
  host is kept if it was heard from in the last 45 s (agents ping every
  20 s) and the newcomer gets 409.

`flakelet-relay check-policy <config> <principal>... -- <target>...`
for offline assertions. The agent's local `flakelets` allowlist applies
on top and is what `hello` advertises.

## Wire format rules

For HTTP bodies, SSE events and WebSocket frames:

- List elements are objects (`{"target": …}`, `{"line": …}`), never bare
  values, so fields can be added anywhere.
- Unknown fields and message types are ignored. Fields are added, never
  redefined. Enum strings map unknown values to the safe side.
- WS frames are `{"type": …}`, SSE uses `event:` with JSON `data:`, HTTP
  errors are `{"code", "message", …}`.
- `hello`, `welcome` and `accepted` carry `capabilities`. Features are
  negotiated by name and `version` is informational. `/v1/` bumps only
  for what capabilities cannot express.

## HTTP API

`POST /v1/deploy` answers with SSE. Request:

```json
{"id": "<client uuid>",
 "waves": [
   {"targets": [{"target": "eliza/tribuchet-worker"}]},
   {"targets": [{"target": "jamie/tribuchet-worker"}, {"target": "eve/tribuchet-hub"}]}
 ],
 "options": {}}
```

Targets within a wave run in parallel. The next wave starts only if
every target of the previous one ended `updated` or `unchanged`. `push`
accepts plain targets and `--wave` separators. Events:

```
accepted {job, relay: {name, version, capabilities}, agents: [{host, version, capabilities}]}
wave     {index}
log      {target, seq, line}
progress {target}
done     {target, status, generation?, tail?: [{line}]}
result   {ok, targets: [{target, status}], skipped: [{target}]}
```

`progress` comes every 30 s while a unit runs. `push` aborts after
5 min of silence for a running target or 60 min total.

The job id is `hash(caller identity, client id)`, so retries are
idempotent and other callers cannot collide with or attach to it. Errors before the
stream starts: `403 {"code": "target_denied", "targets": [...]}`,
`404 {"code": "unknown_host", "targets": [...]}` for hosts the relay has
no `agents` entry for,
`503 {"code": "agent_unavailable", "targets": [...]}` when the agent is
not connected right now (retried by `push` with backoff for 30 s, then
next relay), `400 {"code": "unsupported_option", ...}`.

`GET /v1/jobs/<client id>` re-derives the job id, sends `query` for it to
every flakelet the caller may read and streams what the agents that know
it have, as a single wave. 404 `unknown_job` if none does within 3 s.
`push` goes there when its deploy stream breaks and skips lines it
already printed.

`GET /v1/agents` returns
`{"agents": [{host, version, capabilities, flakelets: [{name, running?, pending?, last?: {status, generation, at}}]}]}`
filtered by read policy.

Status per target: `updated`, `unchanged`, `rolled-back`, `failed`.
`unchanged` counts as success since the timer may have been first. `ok`
means all targets `updated` or `unchanged`. Targets in waves that never
started are listed in `skipped`. There is no rollback across targets.

## Agent protocol

WebSocket at `/v1/agent`, one JSON object with a `type` field per text
frame, WS ping every 20 s.

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
if every targeted agent has the capability, else the request is 400.

A `start` with a known id replays. When an agent reconnects the relay
re-sends `start` for every target it still waits on, so lines logged
while the link was down reach the client. The relay drops lines whose
`seq` it already forwarded. Concurrent `start`s for one flakelet
are coalesced: new ids attach to a single follow-up run and receive the
output of the first run that began after they arrived. Logs are capped
at 1 MiB per job at the agent.

## Agent execution

`flakelet update` runs as transient unit
`flakelet-relay-job-<flakelet>.service` logging to the journal. It
serialises with the timer via flakelet's per-service flock, outlives
agent restarts (the agent may be what is updated), and the agent
follows its journal from a saved cursor whether live or reattached.

The job table is `$STATE_DIRECTORY/jobs/<id>.json` with flakelet,
caller, client id, journal cursor, generation before, state, logs and
result. Summaries are kept `keepJobsDays` (90), logs `keepLogsDays`
(14), at most `maxJobs` (5000) entries; pruned at start and after each
run. On start the agent resumes running entries by following the unit
from the cursor until it is gone and starts pending ones. Results reach
the relay through the replay triggered by its re-sent `start`.

Relays persist nothing about jobs. `hello` carries the newest 50
summaries per flakelet and every state change is sent as a `job` frame
to all connected relays, so each relay can serve `GET /v1/jobs` (deploys
grouped by caller and client id, filtered by the caller's read
permission) and knows each flakelet's current generation and revision
without having started the job itself.

A failed unit is `failed`. Otherwise the result comes from generation
and health in `flakelet status --json` before and after. `failed` and `rolled-back` carry
the last 50 journal lines of the flakelet's units as `tail`.

`Type=notify`, ready after loading config and job table regardless of
relay connectivity, so a relay outage cannot roll back an agent update.
`STATUS=connected 1/2 relays; last: tribuchet-worker updated gen 7`.

## Failure handling

| failure | behaviour |
|---|---|
| relay down | `push` tries the next one |
| relay dies mid-stream | `push` resumes via `GET /v1/jobs` on another relay |
| relay restarted, agents not back yet | 503, `push` retries 30 s |
| agent offline | 503, timer catches up |
| agent restarts mid-job | unit keeps running, agent reattaches and reports |
| same job via two relays | same id, agent dedups |
| concurrent pushes, one flakelet | coalesced into current + one follow-up |
| timer races a push | flakelet lock serialises, push may see `unchanged` |
| update breaks connectivity | flakelet health check rolls the service back. `rolled-back` is reported on reconnect, else `push` hits the idle timeout |
| target in wave 1 fails | later waves not started, listed as `skipped` |
| issuer down | stale JWKS from disk |
| two agents claim a host | incumbent kept if heard from recently, newcomer 409 |

## Observability

Job id is a tracing field on both sides. JSON logs under journald.

Relay `/metrics` (localhost):
`agent_up{host}`, `agent_info{host,version,auth}`,
`agent_connects_total{host,result}`, `agent_disconnects_total{host,reason}`,
`deploys_total{rule,host,flakelet,status}` (status also `denied`,
`unavailable`), `deploy_duration_seconds{host,flakelet}`,
`auth_failures_total{mechanism,reason}`, `jwks_refresh_total{issuer,result}`,
`jwks_age_seconds{issuer}`, `streams_open`. Prefix `flakelet_relay_`.

Agent `/metrics` (localhost, optional):
`relay_up{relay}`, `relay_reconnects_total{relay}`,
`jobs_total{flakelet,status}`, `job_duration_seconds{flakelet}`,
`job_running{flakelet}`, `job_pending{flakelet}`,
`last_job_timestamp_seconds{flakelet,status}`,
`flakelet_generation{flakelet}`, `flakelet_healthy{flakelet}`,
`log_truncated_total{flakelet}`. Prefix `flakelet_agent_`.

Optional alert rules in the NixOS module: agent down or without relays
> 10 min, > 5 reconnects or any 409 in 15 min, deploy `failed` or
`rolled-back`, JWKS age > 24 h.

`flakelet-push agents` prints `/v1/agents` as a table.

## Dashboard

Served by the relay under `/ui/` on both listeners, so behind nginx it
sits next to the client API. Server-rendered HTML (maud) and one static
stylesheet, no script so far; `Content-Security-Policy` only allows
same-origin styles and scripts.

Login is OIDC authorization code flow with PKCE against one of the
configured issuers (`issuers.<name>.login` with `clientId` and optional
`clientSecretFile`; the client id is also accepted as token audience).
`/ui/login` redirects with `state` and the PKCE verifier kept in a
short-lived signed cookie, the redirect URI is `https://<Host>/ui/callback`.
`/ui/callback` exchanges the code, verifies the `id_token` with the
same JWKS and claim mapping as bearer tokens and sets a session cookie
holding principals, display name and expiry, HMAC-signed with a
per-process random key, `HttpOnly; Secure; SameSite=Lax`, valid 12 h.
There is no server-side session store and a relay restart logs
everyone out.

A session is just another source of principals: the JSON API accepts
the cookie too, and pages show exactly what `/v1/agents` and
`/v1/jobs` would show that user.

Pages: flakelets (one row per flakelet across connected hosts with
per-host state, revision or drift, last deploy and an overall status),
hosts (agent version and flakelets with generation) and jobs (recent
deploys with caller and per-target result).

## Implementation

github.com/Mic92/flakelet-relay, CI on nixbot.

Rust workspace with tribuchet-sized dependencies: tokio, rustls, hyper
for HTTP/1.1 and the WS upgrade with hand-rolled framing and SSE, JWT
verification for RS256/ES256/EdDSA on `ring`, serde. systemd is driven
through `systemctl`, `busctl` and `journalctl --follow --cursor`.
Crates are `proto`, `auth` (principals, JWKS, policy,
`check-policy`), `relay`, `agent` and `push`. sd-notify and socket
activation are shared with tribuchet. Common flags are `--cert/--key`,
`--token-command` and `--ca-file`.

Relay and agent ship as flakelets and update through themselves. The
NixOS modules render their config and the cert renewal timer, so trust
inputs change with the host. First install and relay-less periods fall
to the `autoUpdate` timer. Policy is asserted at eval time with
`check-policy`.

NixOS container test with the real flakelet: two relays, an mTLS and an OIDC agent, minica, static mock
issuer. Cases: deploy, unchanged, failing first wave, failover
mid-stream, duplicate id, coalescing, agent restart mid-job, idle
timeout, denied target, read filtering, foreign host, duplicate agent,
claim principals, log cap, SRV add/remove.
