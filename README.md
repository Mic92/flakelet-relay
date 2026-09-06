# flakelet-relay

Status: alpha. Wire protocol and configuration may still change.

Lets CI tell hosts behind firewalls to run `flakelet update <name>` now
and streams the result back. Hosts run `flakelet-agent`, which dials out
to one or more stateless `flakelet-relay`s. CI uses `flakelet-push`.

Both relay and agent ship as flakelets (`flakelets.default` and
`flakelets.agent`), so a host installs them with

```nix
services.flakelets.services = {
  flakelet-relay = {
    flake = "github:Mic92/flakelet-relay";
    settings = { certFile = …; keyFile = …; clientCAFiles = [ … ]; settings = { name = …; listenTls = "[::]:7443"; agents = …; rules = …; }; };
  };
  flakelet-agent = {
    flake = "github:Mic92/flakelet-relay";
    output = "flakelets.agent";
    settings = { certFile = …; keyFile = …; settings = { relaySrv = "example.org"; }; };
  };
};
```

and they can then update themselves through the relay like any other
flakelet. See [docs/DESIGN.md](docs/DESIGN.md).

```
flakelet-push --relay https://relay.example.org deploy web1/app --wave web2/app web3/app
flakelet-push --relay-srv example.org deploy web1/app --wave '*/app'   # canary, then the rest
```
