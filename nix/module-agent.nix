self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.flakelet-agent;
  format = pkgs.formats.json { };
  configFile = format.generate "flakelet-agent.json" (
    lib.filterAttrs (_: v: v != null) {
      inherit (cfg)
        relays
        relaySrv
        caFile
        flakelets
        tokenCommand
        ;
      cert = cfg.certFile;
      key = cfg.keyFile;
      flakeletCommand = cfg.flakeletCommand;
      inherit (cfg) retention;
    }
  );
in
{
  options.services.flakelet-agent = {
    enable = lib.mkEnableOption "flakelet-agent, running `flakelet update` when a relay asks";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "flakelet-relay.packages.\${system}.default";
    };

    relays = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Relay base URLs. The agent keeps a connection to each.";
      example = [ "https://relay1.example.org:7443" ];
    };

    relaySrv = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Domain whose `_flakelet-relay._tcp` SRV records list relays, in addition to `relays`.";
      example = "example.org";
    };

    caFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "CA to verify relays against instead of the WebPKI roots.";
    };

    certFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Client certificate whose SANs identify this host to the relay.";
    };

    keyFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
    };

    tokenCommand = lib.mkOption {
      type = lib.types.nullOr (lib.types.listOf lib.types.str);
      default = null;
      description = "Command printing an OIDC bearer token, used instead of a certificate.";
    };

    flakelets = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      description = "Flakelets relays may update on this host.";
    };

    flakeletCommand = lib.mkOption {
      type = lib.types.str;
      default = lib.getExe config.services.flakelets.package;
      defaultText = lib.literalExpression "lib.getExe config.services.flakelets.package";
    };

    retention = {
      keepJobsDays = lib.mkOption {
        type = lib.types.ints.positive;
        default = 90;
        description = "Days to keep job table entries.";
      };
      keepLogsDays = lib.mkOption {
        type = lib.types.ints.positive;
        default = 14;
        description = "Days to keep a job's log; the summary stays for `keepJobsDays`.";
      };
      maxJobs = lib.mkOption {
        type = lib.types.ints.positive;
        default = 5000;
        description = "Upper bound on entries, oldest dropped first.";
      };
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.flakelet-agent = {
      description = "flakelet-agent";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      # Jobs run in their own transient units, so restarting the agent
      # does not interrupt an update.
      stopIfChanged = false;
      path = [
        config.systemd.package
      ];
      serviceConfig = {
        Type = "notify";
        ExecStart = "${lib.getExe' cfg.package "flakelet-agent"} --config ${configFile}";
        StateDirectory = "flakelet-agent";
        Restart = "always";
        RestartSec = 5;
      };
    };
  };
}
