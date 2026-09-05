{ types, ... }:
{
  options = {
    settings = {
      type = types.attrsOf types.any;
      description = ''
        The JSON config: `name`, `listenHttp`, `listenTls`, `issuers`,
        `agents`, `groups`, `rules`. See docs/DESIGN.md. `tls` is filled
        in from `certFile`, `keyFile` and `clientCAFiles`.
      '';
    };
    certFile = {
      type = types.option types.string;
      default = null;
      description = "Server certificate for `settings.listenTls`, loaded via systemd credentials so it may be root-only.";
    };
    keyFile = {
      type = types.option types.string;
      default = null;
    };
    clientCAFiles = {
      type = types.listOf types.string;
      default = [ ];
      description = "CAs whose client certificates yield `x509:*` principals.";
    };
    policyChecks = {
      type = types.listOf (types.attrsOf types.any);
      default = [ ];
      description = ''
        `{ principals; targets; allow ? true; }` assertions run through
        `flakelet-relay check-policy` at build time, so a policy mistake
        fails the update instead of a deploy.
      '';
    };
  };

  impl =
    { options, inputs }:
    let
      inherit (inputs.nixpkgs) pkgs lib;
      inherit (inputs.flakelet) name;
      package = pkgs.rustPlatform.buildRustPackage {
        pname = "flakelet-relay";
        version = "0.1.0";
        src = lib.fileset.toSource {
          root = ./..;
          fileset = lib.fileset.unions [
            ../Cargo.toml
            ../Cargo.lock
            ../src
          ];
        };
        cargoLock.lockFile = ../Cargo.lock;
      };
      tls = options.certFile != null;
      credentials = "/run/credentials/${name}.service";
      json = (pkgs.formats.json { }).generate "${name}.json" (
        options.settings
        // lib.optionalAttrs tls {
          tls = {
            cert = "${credentials}/cert";
            key = "${credentials}/key";
            clientCAs = options.clientCAFiles;
          };
        }
      );
      check =
        c:
        let
          allow = c.allow or true;
        in
        ''
          echo ${lib.escapeShellArg "check: ${toString c.principals} -> ${toString c.targets} (expect ${if allow then "allow" else "deny"})"}
          ${
            lib.optionalString (!allow) "! "
          }flakelet-relay check-policy $out ${lib.escapeShellArgs c.principals} -- ${lib.escapeShellArgs c.targets}
        '';
      configFile = pkgs.runCommand "${name}.json" { nativeBuildInputs = [ package ]; } ''
        cp ${json} $out
        ${lib.concatMapStrings check options.policyChecks}
      '';
    in
    assert lib.assertMsg (
      tls == (options.keyFile != null)
    ) "flakelet-relay: certFile and keyFile go together";
    assert lib.assertMsg (
      (options.settings ? listenTls) -> tls
    ) "flakelet-relay: settings.listenTls needs certFile";
    {
      services.${name} = {
        description = "flakelet-relay";
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig = {
          Type = "notify";
          ExecStart = "${package}/bin/flakelet-relay serve --config ${configFile}";
          DynamicUser = true;
          CacheDirectory = name;
          LoadCredential = lib.optionals tls [
            "cert:${options.certFile}"
            "key:${options.keyFile}"
          ];
          Restart = "always";
          RestartSec = 2;
          NoNewPrivileges = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          PrivateDevices = true;
          ProtectKernelTunables = true;
          ProtectControlGroups = true;
          RestrictAddressFamilies = [
            "AF_INET"
            "AF_INET6"
            "AF_UNIX"
          ];
          LockPersonality = true;
          RestrictNamespaces = true;
          SystemCallFilter = [
            "@system-service"
            "~@privileged"
          ];
        };
      };
    }
    // lib.optionalAttrs (options.settings ? listenHttp) {
      healthCheck = pkgs.writeShellScript "${name}-health" ''
        exec ${pkgs.curl}/bin/curl -sf --retry 5 --retry-connrefused --retry-delay 2 \
          http://${options.settings.listenHttp}/health -o /dev/null
      '';
    };
}
