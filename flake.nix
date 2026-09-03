{
  description = "flakelet-relay: let CI trigger flakelet updates on firewalled hosts";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.crane.url = "github:ipetkov/crane";
  inputs.flakelet = {
    url = "github:Mic92/flakelet";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  inputs.treefmt-nix = {
    url = "github:numtide/treefmt-nix";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    inputs@{
      self,
      nixpkgs,
      crane,
      flakelet,
      treefmt-nix,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      treefmtFor = pkgs: treefmt-nix.lib.evalModule pkgs ./nix/treefmt.nix;
    in
    {
      packages = forAllSystems (pkgs: {
        default = pkgs.callPackage ./nix/package.nix { craneLib = crane.mkLib pkgs; };
      });

      formatter = forAllSystems (pkgs: (treefmtFor pkgs).config.build.wrapper);

      nixosModules = {
        relay = import ./nix/module-relay.nix self;
        agent = import ./nix/module-agent.nix self;
      };

      checks = forAllSystems (
        pkgs:
        let
          inherit (pkgs.stdenv.hostPlatform) system;
        in
        {
          package = self.packages.${system}.default;
          treefmt = (treefmtFor pkgs).config.build.check self;
          flake-inputs = pkgs.linkFarm "flake-inputs" (
            nixpkgs.lib.mapAttrsToList (name: i: {
              inherit name;
              path = i.outPath;
            }) (builtins.removeAttrs inputs [ "self" ])
          );
        }
        // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          nixos-test = pkgs.testers.runNixOSTest (import ./nix/test.nix { inherit self flakelet; });
        }
      );

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            rustfmt
            clippy
            rust-analyzer
            (treefmtFor pkgs).config.build.wrapper
          ];
        };
      });
    };
}
