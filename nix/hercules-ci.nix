# Roll out main: agents first (their restart does not interrupt the
# update job, which runs in its own unit), then the relays. Authorized
# by this repo's nixbot id token (rule "flakelet-relay" in Mic92/dotfiles
# nixosModules/flakelet-relay). The relay serving the request restarts
# as part of its own deploy, so that one is not waited for.
{ pkgs, flakelet-push }:
let
  effects = import ./effects.nix { inherit pkgs; };
in
{ primaryRepo, ... }:
{
  onPush.default.outputs.effects.deploy = effects.runIf ((primaryRepo.branch or null) == "main") (
    effects.mkEffect {
      name = "deploy";
      idTokenAudiences = [ "flakelet-relay" ];
      inputs = [ flakelet-push ];
      effectScript = ''
        export FLAKELET_RELAY_TOKEN_COMMAND="nixbot-id-token flakelet-relay"
        flakelet-push --relay-srv thalheim.io deploy '*/flakelet-agent'
        flakelet-push --relay-srv thalheim.io deploy --detach '@relays/flakelet-relay'
      '';
    }
  );
}
