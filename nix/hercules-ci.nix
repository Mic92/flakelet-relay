# Ask the relays to update themselves, authorized by this repo's nixbot
# id token (rule "flakelet-relay" in Mic92/dotfiles
# nixosModules/flakelet-relay). The relay serving the request restarts
# as part of the deploy, so do not wait for the result.
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
        flakelet-push --relay-srv thalheim.io deploy --detach '@relays/flakelet-relay'
      '';
    }
  );
}
