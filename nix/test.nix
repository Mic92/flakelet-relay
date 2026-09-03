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
     "token_endpoint":"https://relay:8443/token","device_authorization_endpoint":"https://relay:8443/device"}
    EOF
  '';

  # Device flow endpoints: the first token poll is pending, the second
  # returns an id_token signed with the issuer key.
  deviceMock = pkgs.writers.writePython3 "device-mock" { flakeIgnore = [ "E501" ]; } ''
    import json
    import subprocess
    import time
    from http.server import BaseHTTPRequestHandler, HTTPServer

    polls = {}


    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            form = dict(kv.split("=", 1) for kv in self.rfile.read(n).decode().split("&") if kv)
            if self.path == "/device":
                body = {"device_code": "dev123", "user_code": "ABCD-EFGH", "verification_uri": "https://relay:8443/activate", "interval": 1}
            elif polls.setdefault(form.get("device_code"), 0) == 0:
                polls[form["device_code"]] = 1
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"authorization_pending"}')
                return
            else:
                claims = json.dumps({"groups": ["wheel"], "email": "dev@example.org"})
                tok = subprocess.run(
                    ["${pkgs.step-cli}/bin/step", "crypto", "jwt", "sign", "--key", "${issuer}/jwk.json",
                     "--iss", "https://relay:8443", "--aud", form["client_id"], "--sub", "someone",
                     "--exp", str(int(time.time()) + 300), "--jti", str(time.time())],
                    input=claims, capture_output=True, text=True, check=True).stdout.strip()
                body = {"id_token": tok, "access_token": "opaque", "token_type": "Bearer"}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(body).encode())


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

  pushWrapper = pkgs.writeShellScriptBin "push" ''
    exec ${self.packages.${pkgs.stdenv.hostPlatform.system}.default}/bin/flakelet-push \
      --ca-file ${certs}/ca.pem "$@"
  '';
in
{
  name = "flakelet-relay";

  containers.relay =
    { config, ... }:
    {
      imports = [ self.nixosModules.relay ];
      environment.systemPackages = [ pkgs.iproute2 ];
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
      services.flakelet-relay = {
        enable = true;
        tls = {
          certFile = "${certs}/relay/cert.pem";
          keyFile = "${certs}/relay/key.pem";
          clientCAFiles = [ "${certs}/ca.pem" ];
        };
        settings = {
          listenTls = "[::]:7443";
          listenHttp = "127.0.0.1:7400";
          issuerCaFile = "${certs}/ca.pem";
          issuers.mock = {
            url = "https://relay:8443";
            audience = "flakelet-relay";
            principalClaims = [ "groups" ];
          };
          agents.agent = [ "x509:dns:agent" ];
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
        self.nixosModules.agent
      ];
      environment.systemPackages = [
        pkgs.iproute2
        pkgs.jq
      ];
      services.flakelets = {
        enable = true;
        services.app.prebuilt = appV1;
        services.other.prebuilt = otherV1;
      };
      # Referenced only from the test script.
      system.extraDependencies = [
        appV2
        appBroken
        appSlow
        appSlow2
      ];
      services.flakelet-agent = {
        enable = true;
        relaySrv = "test";
        caFile = "${certs}/ca.pem";
        certFile = "${certs}/agent/cert.pem";
        keyFile = "${certs}/agent/key.pem";
        flakelets = [
          "app"
          "other"
        ];
      };
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

    def token(sub, groups=[]):
        claims = json.dumps({"groups": groups})
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

    with subtest("detach returns once the job is accepted"):
        set_app("${appSlow}")
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
        assert "agent\t" in out and "app,other" in out, out
        tok = token("repo:github:example/app:ref:refs/heads/main")
        out = client.succeed(f"FLAKELET_RELAY_TOKEN_COMMAND='echo {tok}' push --relay https://relay:7443 agents")
        assert out.strip().endswith("\tapp"), out

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
  '';
}
