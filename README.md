# flakelet-relay

Status: alpha. Wire protocol and configuration may still change.

Lets CI tell hosts behind firewalls to run `flakelet update <name>` now
and streams the result back. Hosts run `flakelet-agent`, which dials out
to one or more stateless `flakelet-relay`s. CI uses `flakelet-push`.

See [docs/DESIGN.md](docs/DESIGN.md).

```
flakelet-push --relay https://relay.example.org deploy web1/app --wave web2/app web3/app
flakelet-push --relay-srv example.org deploy web1/app --wave '*/app'   # canary, then the rest
```
