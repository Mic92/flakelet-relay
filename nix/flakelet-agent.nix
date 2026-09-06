{ types, ... }:
{
  options = {
    settings = {
      type = types.attrsOf types.any;
      description = ''
        The agent's JSON config: `relays`, `relaySrv`, `caFile`,
        `flakelets`, `tokenCommand`, `statusInterval`, `retention`.
        `cert` and `key` are filled in from `certFile` and `keyFile`.
      '';
    };
    certFile = {
      type = types.option types.string;
      default = null;
      description = "Client certificate for the relays, loaded via systemd credentials so it may be root-only.";
    };
    keyFile = {
      type = types.option types.string;
      default = null;
    };
  };

  impl =
    { options, inputs }:
    let
      inherit (inputs.nixpkgs) pkgs lib;
      inherit (inputs.flakelet) name;
      package = import ./build.nix { inherit pkgs lib; };
      tls = options.certFile != null;
      credentials = "/run/credentials/${name}.service";
      configFile = (pkgs.formats.json { }).generate "${name}.json" (
        options.settings
        // lib.optionalAttrs tls {
          cert = "${credentials}/cert";
          key = "${credentials}/key";
        }
      );
    in
    assert lib.assertMsg (
      tls == (options.keyFile != null)
    ) "flakelet-agent: certFile and keyFile go together";
    {
      services.${name} = {
        description = "flakelet-agent";
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        # The host's flakelet and systemctl, not ones pinned by this flake.
        path = [ "/run/current-system/sw" ];
        serviceConfig = {
          Type = "notify";
          ExecStart = "${package}/bin/flakelet-agent --config ${configFile}";
          StateDirectory = name;
          LoadCredential = lib.optionals tls [
            "cert:${options.certFile}"
            "key:${options.keyFile}"
          ];
          Restart = "always";
          RestartSec = 5;
        };
      };
    };
}
