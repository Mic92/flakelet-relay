# Relay, agent and client as nspawn containers. Identity via a throwaway
# CA (agent and admin certs) and a static OIDC issuer served by nginx on
# the relay. The agent runs the real flakelet against prebuilt service
# artifacts, so nothing is evaluated or built at test time. The test
# swaps the artifact in /etc/flakelet/config.json to produce updates,
# no-ops and rollbacks.
{ self, flakelet }:
{
  pkgs,
  lib,
  ...
}:
let
  certs = pkgs.runCommand "flakelet-relay-test-certs" { nativeBuildInputs = [ pkgs.minica ]; } ''
    mkdir $out; cd $out
    minica -ca-cert ca.pem -ca-key ca-key.pem -domains relay
    minica -ca-cert ca.pem -ca-key ca-key.pem -domains agent
    minica -ca-cert ca.pem -ca-key ca-key.pem -domains mallory
    # minica cannot do email SANs
    ${pkgs.openssl}/bin/openssl req -new -newkey rsa:2048 -nodes -subj "/CN=admin" \
      -keyout admin-key.pem -out admin.csr
    ${pkgs.openssl}/bin/openssl x509 -req -in admin.csr -CA ca.pem -CAkey ca-key.pem \
      -CAcreateserial -days 3650 -out admin.pem \
      -extfile <(printf "subjectAltName=email:admin@example.org\nextendedKeyUsage=clientAuth")
    chmod -R a+r .
  '';

  # Signing key and JWKS for the mock issuer, fixed at build time.
  issuer = pkgs.runCommand "flakelet-relay-test-issuer" { nativeBuildInputs = [ pkgs.step-cli ]; } ''
    mkdir -p $out/www/.well-known
    step crypto jwk create $out/jwk.pub.json $out/jwk.json --kty OKP --crv Ed25519 --no-password --insecure --kid k1
    echo '{"keys":['"$(cat $out/jwk.pub.json)"']}' > $out/www/.well-known/jwks.json
    cat > $out/www/.well-known/openid-configuration <<EOF
    {"issuer":"https://relay:8443","jwks_uri":"https://relay:8443/.well-known/jwks.json",
     "token_endpoint":"https://relay:8443/token","device_authorization_endpoint":"https://relay:8443/device",
     "authorization_endpoint":"https://relay:8443/authorize"}
    EOF
  '';

  # Device flow: the first token poll is pending, the second returns an
  # id_token signed with the issuer key. Authorization code flow:
  # /authorize redirects straight back with a code, /token checks PKCE.
  deviceMock = pkgs.writers.writePython3 "device-mock" { flakeIgnore = [ "E501" ]; } ''
    import base64
    import hashlib
    import json
    import subprocess
    import time
    import urllib.parse
    from http.server import BaseHTTPRequestHandler, HTTPServer

    polls = {}
    codes = {}


    def id_token(aud):
        claims = json.dumps({"groups": ["wheel"], "email": "dev@example.org", "preferred_username": "someone"})
        return subprocess.run(
            ["${pkgs.step-cli}/bin/step", "crypto", "jwt", "sign", "--key", "${issuer}/jwk.json",
             "--iss", "https://relay:8443", "--aud", aud, "--sub", "someone",
             "--exp", str(int(time.time()) + 300), "--jti", str(time.time())],
            input=claims, capture_output=True, text=True, check=True).stdout.strip()


    class H(BaseHTTPRequestHandler):
        def reply(self, code, body):
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(body).encode())

        def do_GET(self):
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            assert q["client_id"] == ["dashboard"] and q["code_challenge_method"] == ["S256"], q
            codes["c0de"] = q["code_challenge"][0]
            self.send_response(302)
            self.send_header("Location", q["redirect_uri"][0] + "?code=c0de&state=" + q["state"][0])
            self.end_headers()

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            form = dict(urllib.parse.parse_qsl(self.rfile.read(n).decode()))
            if self.path == "/device":
                body = {"device_code": "dev123", "user_code": "ABCD-EFGH", "verification_uri": "https://relay:8443/activate", "interval": 1}
            elif form.get("grant_type") == "authorization_code":
                digest = hashlib.sha256(form["code_verifier"].encode()).digest()
                if codes.pop(form["code"], None) != base64.urlsafe_b64encode(digest).rstrip(b"=").decode() or form.get("client_secret") != "s3cret":
                    return self.reply(400, {"error": "invalid_grant"})
                body = {"id_token": id_token(form["client_id"]), "access_token": "opaque", "token_type": "Bearer"}
            elif polls.setdefault(form.get("device_code"), 0) == 0:
                polls[form["device_code"]] = 1
                return self.reply(400, {"error": "authorization_pending"})
            else:
                body = {"id_token": id_token(form["client_id"]), "access_token": "opaque", "token_type": "Bearer"}
            self.reply(200, body)


    HTTPServer(("127.0.0.1", 8089), H).serve_forever()
  '';

  artifact =
    name: tag:
    {
      execStart ? "${pkgs.coreutils}/bin/sleep infinity",
      startPre ? null,
    }:
    (flakelet.lib.buildArtifact pkgs {
      inherit name;
      module = _: {
        impl = _: {
          services.${name} = {
            description = "${name} ${tag}";
            wantedBy = [ "multi-user.target" ];
            serviceConfig = {
              ExecStart = execStart;
            }
            // lib.optionalAttrs (startPre != null) { ExecStartPre = startPre; };
          };
        };
      };
    }).overrideAttrs
      { name = "flakelet-${name}-${tag}"; };

  appV1 = artifact "app" "v1" { };
  appV2 = artifact "app" "v2" { };
  appBroken = artifact "app" "broken" { execStart = "/nonexistent"; };
  # Activation blocks on ExecStartPre, giving the test a window to cut
  # the agent's relay connection while the update is running.
  appSlow = artifact "app" "slow" { startPre = "${pkgs.coreutils}/bin/sleep 6"; };
  appSlow2 = artifact "app" "slow2" { startPre = "${pkgs.coreutils}/bin/sleep 6"; };
  otherV1 = artifact "other" "v1" { };

  agentArtifact = flakelet.lib.buildArtifact pkgs {
    name = "flakelet-agent";
    module = self.flakelets.agent;
    settings = {
      certFile = "${certs}/agent/cert.pem";
      keyFile = "${certs}/agent/key.pem";
      settings = {
        relaySrv = "test";
        caFile = "${certs}/ca.pem";
        flakelets = [
          "app"
          "other"
        ];
        statusInterval = 2;
      };
    };
  };

  relayArtifact = flakelet.lib.buildArtifact pkgs {
    name = "flakelet-relay";
    module = self.flakelets.default;
    settings = {
      certFile = "${certs}/relay/cert.pem";
      keyFile = "${certs}/relay/key.pem";
      clientCAFiles = [ "${certs}/ca.pem" ];
      settings = {
        name = "relay";
        listenTls = "[::]:7443";
        listenHttp = "127.0.0.1:7400";
        issuerCaFile = "${certs}/ca.pem";
        issuers.mock = {
          url = "https://relay:8443";
          audience = "flakelet-relay";
          principalClaims = [ "groups" ];
          displayClaims = [
            "repository"
            "email"
          ];
          login.clientId = "dashboard";
          login.clientSecretFile = "${pkgs.writeText "secret" "s3cret"}";
        };
        agents.agent = [ "x509:dns:agent" ];
        # Never connects. The dashboard lists it as disconnected.
        agents.ghost = [ "x509:dns:ghost" ];
        groups.all = [ "agent" ];
        rules = {
          ci = {
            principals = [ "oidc:mock:repo:github:example/app:ref:refs/heads/main" ];
            targets = [ "agent/app" ];
          };
          admins = {
            principals = [
              "x509:email:admin@example.org"
              "oidc:mock:groups:wheel"
            ];
            targets = [
              "@all/*"
              "*/*"
            ];
          };
        };
      };
      policyChecks = [
        {
          principals = [ "oidc:mock:repo:github:example/app:ref:refs/heads/main" ];
          targets = [ "agent/app" ];
        }
        {
          principals = [ "oidc:mock:repo:github:example/app:ref:refs/heads/main" ];
          targets = [ "agent/other" ];
          allow = false;
        }
      ];
    };
  };

  pushWrapper = pkgs.writeShellScriptBin "push" ''
    exec ${self.packages.${pkgs.stdenv.hostPlatform.system}.default}/bin/flakelet-push \
      --ca-file ${certs}/ca.pem "$@"
  '';
in
{
  name = "flakelet-relay";

  containers.relay = {
    imports = [ flakelet.nixosModules.default ];
    environment.systemPackages = [ pkgs.iproute2 ];
    services.flakelets = {
      enable = true;
      services.flakelet-relay.prebuilt = relayArtifact;
    };
    networking.firewall.allowedTCPPorts = [
      7443
      8443
      53
    ];
    networking.firewall.allowedUDPPorts = [ 53 ];
    # SRV discovery. dnsmasq also answers A/AAAA from /etc/hosts.
    services.dnsmasq = {
      enable = true;
      resolveLocalQueries = false;
      settings = {
        srv-host = "_flakelet-relay._tcp.test,relay,7443";
        no-resolv = true;
      };
    };
    # mock issuer
    services.nginx = {
      enable = true;
      virtualHosts.relay = {
        listen = [
          {
            addr = "[::]";
            port = 8443;
            ssl = true;
          }
          {
            addr = "0.0.0.0";
            port = 8443;
            ssl = true;
          }
        ];
        onlySSL = true;
        sslCertificate = "${certs}/relay/cert.pem";
        sslCertificateKey = "${certs}/relay/key.pem";
        root = "${issuer}/www";
        locations."/authorize".proxyPass = "http://127.0.0.1:8089";
        locations."/device".proxyPass = "http://127.0.0.1:8089";
        locations."/token".proxyPass = "http://127.0.0.1:8089";
      };
    };
    systemd.services.device-mock = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig.ExecStart = deviceMock;
    };
  };

  containers.agent =
    { containers, ... }:
    {
      networking.nameservers = [ containers.relay.networking.primaryIPAddress ];
      imports = [
        flakelet.nixosModules.default
      ];
      environment.systemPackages = [
        pkgs.iproute2
        pkgs.jq
      ];
      services.flakelets = {
        enable = true;
        services.app.prebuilt = appV1;
        services.other.prebuilt = otherV1;
        services.flakelet-agent.prebuilt = agentArtifact;
      };
      # Referenced only from the test script.
      system.extraDependencies = [
        appV2
        appBroken
        appSlow
        appSlow2
      ];
    };

  containers.client =
    { containers, ... }:
    {
      networking.nameservers = [ containers.relay.networking.primaryIPAddress ];
      environment.systemPackages = [
        pushWrapper
        pkgs.step-cli
      ];
    };

  testScript = ''
    import json

    def token(sub, groups=[], **extra):
        claims = json.dumps({"groups": groups, **extra})
        return client.succeed(
            f"echo '{claims}' | step crypto jwt sign --key ${issuer}/jwk.json --iss https://relay:8443 "
            f"--aud flakelet-relay --sub '{sub}' --exp $(( $(date +%s) + 300 )) --jti $(head -c8 /dev/urandom | base32)"
        ).strip()

    def set_app(artifact):
        agent.succeed(
            f"jq '.services.app.prebuilt=\"{artifact}\"' /etc/flakelet/config.json > /tmp/config.json && "
            "cp --remove-destination /tmp/config.json /etc/flakelet/config.json"
        )

    admin = "push --relay https://relay:7443 --cert ${certs}/admin.pem --key ${certs}/admin-key.pem"

    start_all()
    relay.wait_for_unit("flakelet-relay.service")
    relay.wait_for_unit("nginx.service")
    agent.wait_for_unit("flakelet.target")
    agent.wait_for_unit("flakelet-agent.service")
    client.wait_for_unit("multi-user.target")
    relay.wait_until_succeeds("curl -sf http://127.0.0.1:7400/metrics | grep -q 'agent_up{host=\"agent\"} 1'")
    agent.succeed("systemctl is-active app.service other.service")

    with subtest("deploy with client certificate, relay found via SRV"):
        set_app("${appV2}")
        out = client.succeed("push --relay-srv test --cert ${certs}/admin.pem --key ${certs}/admin-key.pem deploy agent/app 2>&1")
        print(out)
        assert "app: updated to generation 2" in out, out
        assert "agent/app: updated (generation 2)" in out, out
        agent.succeed("systemctl show app.service -p Description | grep -q 'app v2'")
        agent.succeed("journalctl -u flakelet-relay-job-app.service | grep -q 'generation 2'")

    with subtest("deploy with OIDC token, sub principal"):
        set_app("${appV1}")
        tok = token("repo:github:example/app:ref:refs/heads/main")
        out = client.succeed(
            f"FLAKELET_RELAY_TOKEN_COMMAND='echo {tok}' push --relay https://relay:7443 deploy agent/app 2>&1"
        )
        assert "agent/app: updated (generation 3)" in out, out

    with subtest("policy denies uncovered target"):
        out = client.fail(
            f"FLAKELET_RELAY_TOKEN_COMMAND='echo {tok}' push --relay https://relay:7443 deploy agent/other 2>&1"
        )
        assert "target_denied" in out and "agent/other" in out, out

    with subtest("claim principal from groups, unchanged counts as success"):
        tok = token("someone", ["wheel"])
        out = client.succeed(
            f"FLAKELET_RELAY_TOKEN_COMMAND='echo {tok}' push --relay https://relay:7443 deploy agent/other 2>&1"
        )
        assert "agent/other: unchanged (generation 1)" in out, out

    with subtest("push login via device flow, cached token used afterwards"):
        out = client.succeed("push login --issuer https://relay:8443 --client-id flakelet-relay 2>&1")
        assert "confirm code ABCD-EFGH" in out and "Logged in as dev@example.org" in out, out
        client.succeed("test \"$(stat -c %a /root/.local/state/flakelet-push/token.json)\" = 600")
        for _ in range(2):
            out = client.succeed("push --relay https://relay:7443 deploy agent/other 2>&1")
            assert "agent/other: unchanged" in out, out

    with subtest("waves: failing first wave skips the second"):
        set_app("${appBroken}")
        out = client.fail(f"{admin} deploy agent/app --wave agent/other 2>&1")
        print(out)
        assert "agent/app: rolled-back" in out, out
        assert "skipped: agent/other" in out, out
        assert "rolled back" in out, out
        agent.succeed("systemctl show app.service -p Description | grep -q 'app v1'")

    with subtest("host patterns expand on the relay"):
        set_app("${appV1}")
        # @all is only `agent`. `*` also covers the never-connected ghost.
        out = client.succeed(f"{admin} deploy '@all/app' 2>&1")
        assert "agent/app:" in out and "ghost" not in out, out
        out = client.fail(f"{admin} deploy '*/app' 2>&1")
        assert "agent/app:" in out and "offline: ghost/app" in out, out
        # Earlier waves win: agent runs in wave 0, wave 1 only has ghost left.
        out = client.fail(f"{admin} deploy agent/app --wave '*/app' 2>&1")
        assert out.index("agent/app:") < out.index("wave 1") < out.index("offline: ghost/app"), out
        out = client.fail(f"{admin} deploy '@all/nope' 2>&1")
        assert "no_targets" in out, out

    with subtest("detach returns once the job is accepted"):
        set_app("${appSlow2}")
        out = client.succeed(f"timeout 20 {admin} deploy --detach agent/app 2>&1")
        assert "detached" in out and "agent/app:" not in out, out
        # The update still runs to completion on the agent.
        agent.wait_until_succeeds("systemctl is-active flakelet-relay-job-app.service")
        agent.wait_until_fails("systemctl is-active flakelet-relay-job-app.service", timeout=90)

    with subtest("unknown host is final, missing agent is retried, agents listing"):
        out = client.fail(f"{admin} deploy nope/app 2>&1")
        assert "unknown_host" in out, out
        agent.succeed("systemctl stop flakelet-agent")
        relay.wait_until_succeeds("curl -sf http://127.0.0.1:7400/metrics | grep -q 'agent_up{host=\"agent\"} 0'")
        client.succeed(f"{admin} deploy agent/other > /tmp/retry.out 2>&1 &")
        client.wait_until_succeeds("grep -q 'agent_unavailable.*retrying' /tmp/retry.out")
        agent.succeed("systemctl start flakelet-agent")
        client.wait_until_succeeds("grep -q 'agent/other: unchanged' /tmp/retry.out", timeout=60)
        out = client.succeed(f"{admin} agents")
        assert "agent\t" in out and "app@" in out and ",other@1" in out, out
        tok = token("repo:github:example/app:ref:refs/heads/main")
        out = client.succeed(f"FLAKELET_RELAY_TOKEN_COMMAND='echo {tok}' push --relay https://relay:7443 agents")
        assert "\tapp@" in out and "other" not in out, out

    with subtest("out-of-band flakelet update reaches the relay without reconnect"):
        gen = int(agent.succeed("flakelet status --json app | jq '.[0].generation'"))
        conns = agent.succeed("journalctl -u flakelet-agent -o cat | grep -c '\"connected\"' || true").strip()
        set_app("${appV2}")
        agent.succeed("flakelet update app")
        client.wait_until_succeeds(f"{admin} agents | grep -q 'app@{gen + 1}'", timeout=30)
        assert conns == agent.succeed("journalctl -u flakelet-agent -o cat | grep -c '\"connected\"' || true").strip()
        set_app("${appV1}")
        agent.succeed("flakelet update app")
        client.wait_until_succeeds(f"{admin} agents | grep -q 'app@{gen + 2}'", timeout=30)

    with subtest("certificate not listed under agents cannot connect as agent"):
        out = client.succeed(
            "curl -s -o /dev/null -w '%{http_code}' --cacert ${certs}/ca.pem --cert ${certs}/mallory/cert.pem --key ${certs}/mallory/key.pem "
            "-H 'Upgrade: websocket' -H 'Connection: Upgrade' -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' "
            "https://relay:7443/v1/agent"
        )
        assert out == "403", out

    with subtest("metrics"):
        m = relay.succeed("curl -sf http://127.0.0.1:7400/metrics")
        assert 'deploys_total{rule="admins",host="agent",flakelet="app",status="rolled-back"} 1' in m, m
        assert 'deploys_total{rule="ci",host="agent",flakelet="app",status="updated"} 1' in m, m

    with subtest("agent link drop mid-run replays missed lines once"):
        set_app("${appSlow}")
        since = agent.succeed("date +%s").strip()
        client.succeed(f"{admin} deploy agent/app > /tmp/slow.out 2>&1 &")
        agent.wait_until_succeeds(f"journalctl -u flakelet-relay-job-app.service --since=@{since} | grep -q 'app-slow'")
        # Make the relay unreachable for new connections, then reset the
        # established one on both ends.
        agent.succeed("for a in $(getent ahosts relay | cut -d' ' -f1 | sort -u); do ip route add unreachable $a; done")
        relay.succeed("for a in $(getent ahosts agent | cut -d' ' -f1 | sort -u); do ss -K dst \"[$a]\"; done")
        agent.succeed("ss -K dport = 7443")
        agent.wait_until_succeeds(f"journalctl -u flakelet-relay-job-app.service --since=@{since} | grep -q 'updated to generation'")
        agent.succeed("for a in $(getent ahosts relay | cut -d' ' -f1 | sort -u); do ip route del unreachable $a; done")
        client.wait_until_succeeds("grep -q 'agent/app: updated' /tmp/slow.out", timeout=90)
        out = client.succeed("cat /tmp/slow.out")
        print(out)
        assert out.count("updated to generation") == 1, out

    with subtest("agent restart mid-run reattaches to the unit"):
        set_app("${appSlow2}")
        client.succeed(f"{admin} deploy agent/app > /tmp/restart.out 2>&1 &")
        agent.wait_until_succeeds("journalctl -u flakelet-relay-job-app.service --since -20s | grep -q 'app-slow2'")
        agent.succeed("systemctl restart flakelet-agent")
        agent.succeed("test -n \"$(ls /var/lib/flakelet-agent/jobs)\"")
        client.wait_until_succeeds("grep -q 'agent/app: updated' /tmp/restart.out", timeout=90)
        out = client.succeed("cat /tmp/restart.out")
        print(out)
        assert out.count("app: updated to generation") == 1, out
        agent.succeed("systemctl is-active app.service")

    with subtest("relay restart mid-run, push resumes via /v1/jobs"):
        set_app("${appSlow}")
        since = agent.succeed("date +%s").strip()
        client.succeed(f"{admin} deploy agent/app > /tmp/resume.out 2>&1 &")
        agent.wait_until_succeeds(f"journalctl -u flakelet-relay-job-app.service --since=@{since} | grep -q 'app-slow'")
        relay.succeed("systemctl restart flakelet-relay")
        try:
            client.wait_until_succeeds("grep -q '» ok' /tmp/resume.out", timeout=90)
        finally:
            out = client.succeed("cat /tmp/resume.out")
            print(out)
        assert "resuming job" in out, out
        assert out.count("app: updated to generation") == 1, out
        assert "agent/app: updated" in out, out

    with subtest("job history comes from the agents and survives a relay restart"):
        out = client.succeed(f"{admin} deploy --id hist1 agent/other 2>&1")
        relay.succeed("systemctl restart flakelet-relay")
        relay.wait_until_succeeds("curl -sf http://127.0.0.1:7400/metrics | grep -q 'agent_up{host=\"agent\"} 1'")
        out = client.succeed(f"{admin} jobs")
        print(out)
        line = next(l for l in out.splitlines() if "\thist1\t" in l)
        assert "\tadmin@example.org\t" in line and "agent/other:unchanged" in line, line
        # A caller only sees jobs on targets its rules cover, and is
        # named by the issuer's displayClaims rather than its principals.
        tok = token("repo:github:example/app:ref:refs/heads/main", repository="example/app")
        client.succeed(f"FLAKELET_RELAY_TOKEN_COMMAND='echo {tok}' push --relay https://relay:7443 deploy --id hist2 agent/app")
        out = client.succeed(f"FLAKELET_RELAY_TOKEN_COMMAND='echo {tok}' push --relay https://relay:7443 jobs")
        assert "\texample/app\t" in out and "agent/other" not in out, out

    with subtest("dashboard login via authorization code flow"):
        curl = "curl -sS --cacert ${certs}/ca.pem -b /tmp/jar -c /tmp/jar"
        client.succeed(f"{curl} -o /dev/null -w '%{{http_code}} %{{redirect_url}}' https://relay:7443/ui/ | grep -q '303 https://relay:7443/ui/login'")
        page = client.succeed(f"{curl} -L https://relay:7443/ui/login")
        assert "Signed in as" in page and ">dev@example.org<" in page, page
        assert ">app<" in page and ">other<" in page and "healthy" in page, page
        jobs = client.succeed(f"{curl} https://relay:7443/ui/jobs")
        assert "hist1"[:8] in jobs and "agent/other" in jobs, jobs
        # The session cookie also authenticates the JSON API.
        client.succeed(f"{curl} -f https://relay:7443/v1/jobs | grep -q hist1")
        # A job started by another caller (the admin cert) can be followed.
        ev = client.succeed(f"{curl} -N --max-time 10 https://relay:7443/ui/jobs/hist1/events || true")
        assert "event: result" in ev and "hx-partial" in ev, ev
        # Deploy from the UI needs the htmx header, then redirects to the job page.
        client.succeed(f"{curl} -o /dev/null -w '%{{http_code}}' -X POST 'https://relay:7443/ui/deploy?arg=other' | grep -q 403")
        hdr = client.succeed(f"{curl} -D - -o /dev/null -H 'HX-Request: true' -X POST 'https://relay:7443/ui/deploy?arg=other'")
        loc = next(l.split(":", 1)[1].strip() for l in hdr.splitlines() if l.lower().startswith("hx-redirect:"))
        assert loc.startswith("/ui/jobs/"), hdr
        ev = client.succeed(f"{curl} -N --max-time 30 https://relay:7443{loc}/events || true")
        assert "event: result\ndata: true" in ev, ev
        page = client.succeed(f"{curl} https://relay:7443{loc}")
        assert "agent/other" in page and "unchanged" in page and "hx-sse:connect" in page, page
        client.succeed(f"{curl} -sf -o /dev/null https://relay:7443/ui/static/htmx.min.js")
        # Filter, flakelet detail, retry action, hosts incl. configured but absent ones.
        out = client.succeed(f"{curl} 'https://relay:7443/ui/?q=status%3Ahealthy+oth'")
        assert ">other<" in out and 'href="/ui/flakelets/app"' not in out, out
        out = client.succeed(f"{curl} https://relay:7443/ui/flakelets/other")
        assert ">agent<" in out and "History" in out and loc.split("/")[-1][:8] in out, out
        out = client.succeed(f"{curl} 'https://relay:7443/ui/hosts?q=status%3Adisconnected'")
        assert ">ghost<" in out and "disconnected" in out and ">agent<" not in out, out
        # Nothing failed in that deploy, so there is nothing to retry.
        client.succeed(f"{curl} -o /dev/null -w '%{{http_code}}' -H 'HX-Request: true' -X POST 'https://relay:7443/ui/retry?arg={loc.split('/')[-1]}' | grep -q 400")
        # Live list updates: a job elsewhere re-renders the page body over SSE.
        client.succeed(f"{curl} -N --max-time 15 'https://relay:7443/ui/events?path=jobs' > /tmp/ev.out 2>&1 &")
        client.succeed(f"{admin} deploy --id live1 agent/other")
        client.wait_until_succeeds("grep -q live1 /tmp/ev.out", timeout=20)
        client.succeed(f"{curl} -X POST -o /dev/null https://relay:7443/ui/logout")
        client.succeed(f"{curl} -o /dev/null -w '%{{http_code}}' https://relay:7443/ui/ | grep -q 303")
  '';
}
