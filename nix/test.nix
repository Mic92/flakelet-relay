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
    {"issuer":"https://relay:8443","jwks_uri":"https://relay:8443/.well-known/jwks.json"}
    EOF
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
      networking.firewall.allowedTCPPorts = [
        7443
        8443
      ];
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
        };
      };
    };

  containers.agent =
    { ... }:
    {
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
      ];
      services.flakelet-agent = {
        enable = true;
        relays = [ "https://relay:7443" ];
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
    { ... }:
    {
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

    with subtest("deploy with client certificate"):
        set_app("${appV2}")
        out = client.succeed(f"{admin} deploy agent/app 2>&1")
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

    with subtest("policy denies uncovered target and jti replay"):
        out = client.fail(
            f"FLAKELET_RELAY_TOKEN_COMMAND='echo {tok}' push --relay https://relay:7443 deploy agent/other 2>&1"
        )
        assert "unauthorized" in out and "jti" in out, out
        tok2 = token("repo:github:example/app:ref:refs/heads/main")
        out = client.fail(
            f"FLAKELET_RELAY_TOKEN_COMMAND='echo {tok2}' push --relay https://relay:7443 deploy agent/other 2>&1"
        )
        assert "target_denied" in out and "agent/other" in out, out

    with subtest("claim principal from groups, unchanged counts as success"):
        tok = token("someone", ["wheel"])
        out = client.succeed(
            f"FLAKELET_RELAY_TOKEN_COMMAND='echo {tok}' push --relay https://relay:7443 deploy agent/other 2>&1"
        )
        assert "agent/other: unchanged (generation 1)" in out, out

    with subtest("waves: failing first wave skips the second"):
        set_app("${appBroken}")
        out = client.fail(f"{admin} deploy agent/app --wave agent/other 2>&1")
        print(out)
        assert "agent/app: rolled-back" in out, out
        assert "skipped: agent/other" in out, out
        assert "rolled back" in out, out
        agent.succeed("systemctl show app.service -p Description | grep -q 'app v1'")

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
        client.succeed(f"{admin} deploy agent/app > /tmp/slow.out 2>&1 &")
        agent.wait_until_succeeds("journalctl -u flakelet-relay-job-app.service --since -20s | grep -q 'app-slow'")
        # Reset the established connection, then make the relay unreachable
        # so the reconnect only succeeds after the update finished.
        agent.succeed("ss -K dport = 7443")
        agent.succeed("for a in $(getent ahosts relay | cut -d' ' -f1 | sort -u); do ip route add unreachable $a; done")
        agent.wait_until_succeeds("journalctl -u flakelet-relay-job-app.service --since -30s | grep -q 'updated to generation'")
        agent.succeed("for a in $(getent ahosts relay | cut -d' ' -f1 | sort -u); do ip route del unreachable $a; done")
        client.wait_until_succeeds("grep -q 'agent/app: updated' /tmp/slow.out", timeout=90)
        out = client.succeed("cat /tmp/slow.out")
        print(out)
        assert out.count("updated to generation") == 1, out

    with subtest("agent reconnects after relay restart"):
        relay.succeed("systemctl restart flakelet-relay")
        relay.wait_until_succeeds("curl -sf http://127.0.0.1:7400/metrics | grep -q 'agent_up{host=\"agent\"} 1'", timeout=90)
  '';
}
