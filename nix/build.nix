# Plain rustPlatform build for the flakelet modules, which only get
# nixpkgs as input (nix/package.nix uses crane for the dev flake).
{ pkgs, lib }:
pkgs.rustPlatform.buildRustPackage {
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
}
