self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.flakelet-relay;
  format = pkgs.formats.json { };
  credentialsDir = "/run/credentials/flakelet-relay.service";
  settings = lib.filterAttrsRecursive (_: v: v != null) (
    cfg.settings
    // lib.optionalAttrs (cfg.tls.certFile != null) {
      tls = {
        cert = "${credentialsDir}/cert";
        key = "${credentialsDir}/key";
        clientCAs = cfg.tls.clientCAFiles;
      };
    }
  );
  configFile = format.generate "flakelet-relay.json" settings;

  policyChecks = lib.concatMapStrings (c: ''
    echo ${lib.escapeShellArg "check: ${toString c.principals} -> ${toString c.targets} (expect ${if c.allow then "allow" else "deny"})"}
    if ${
      lib.optionalString (!c.allow) "!"
    } flakelet-relay check-policy ${configFile} ${lib.escapeShellArgs c.principals} -- ${lib.escapeShellArgs c.targets}; then
      :
    else
      echo "policy check failed" >&2
      exit 1
    fi
  '') cfg.policyChecks;
in
{
  options.services.flakelet-relay = {
    enable = lib.mkEnableOption "flakelet-relay, forwarding deploy requests from CI to flakelet agents";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "flakelet-relay.packages.\${system}.default";
    };

    tls = {
      certFile = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        default = null;
        description = "Server certificate for `settings.listenTls`. Loaded via systemd credentials so it may be root-only.";
      };
      keyFile = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        default = null;
      };
      clientCAFiles = lib.mkOption {
        type = lib.types.listOf lib.types.path;
        default = [ ];
        description = "CAs whose client certificates yield `x509:*` principals.";
      };
    };

    settings = lib.mkOption {
      inherit (format) type;
      default = { };
      description = ''
        Contents of the JSON config: `name`, `listenHttp`, `listenTls`,
        `issuers`, `issuerCaFile`, `agents`, `groups`, `rules`. See docs/DESIGN.md.
      '';
      example = lib.literalExpression ''
        {
          listenHttp = "127.0.0.1:7400";
          listenTls = "[::]:7443";
          issuers.nixbot = { url = "https://nixbot.example.org"; audience = "flakelet-relay"; };
          agents.web1 = [ "x509:dns:web1.example.org" ];
          rules.ci = { principals = [ "oidc:nixbot:repo:github:me/app:ref:refs/heads/main" ]; targets = [ "web1/app" ]; };
        }
      '';
    };

    policyChecks = lib.mkOption {
      type = lib.types.listOf (
        lib.types.submodule {
          options = {
            principals = lib.mkOption { type = lib.types.listOf lib.types.str; };
            targets = lib.mkOption { type = lib.types.listOf lib.types.str; };
            allow = lib.mkOption {
              type = lib.types.bool;
              default = true;
            };
          };
        }
      );
      default = [ ];
      description = "Assertions evaluated with `flakelet-relay check-policy` at build time.";
    };
  };

  config = lib.mkIf cfg.enable {
    services.flakelet-relay.settings.name = lib.mkDefault config.networking.hostName;

    assertions = [
      {
        assertion = (cfg.tls.certFile != null) == (cfg.tls.keyFile != null);
        message = "services.flakelet-relay.tls.certFile and keyFile go together";
      }
      {
        assertion = (cfg.settings.listenTls or null != null) -> cfg.tls.certFile != null;
        message = "services.flakelet-relay.settings.listenTls needs tls.certFile";
      }
    ];

    system.checks = lib.optional (cfg.policyChecks != [ ]) (
      pkgs.runCommand "flakelet-relay-policy-checks" { nativeBuildInputs = [ cfg.package ]; } ''
        ${policyChecks}
        touch $out
      ''
    );

    systemd.services.flakelet-relay = {
      description = "flakelet-relay";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      # Restarting drops agent connections and in-flight streams; both
      # sides recover, but there is no reason to do it on every switch
      # when only unrelated units changed.
      stopIfChanged = false;
      serviceConfig = {
        Type = "notify";
        ExecStart = "${lib.getExe' cfg.package "flakelet-relay"} serve --config ${configFile}";
        DynamicUser = true;
        CacheDirectory = "flakelet-relay";
        LoadCredential =
          lib.optional (cfg.tls.certFile != null) "cert:${cfg.tls.certFile}"
          ++ lib.optional (cfg.tls.keyFile != null) "key:${cfg.tls.keyFile}";
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
  };
}
