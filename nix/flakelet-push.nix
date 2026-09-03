# flakelet-push only, without crane, so CI repos can
# `pkgs.callPackage "${fetchFromGitHub …}/nix/flakelet-push.nix" { }`
# instead of taking this flake as an input.
{ lib, rustPlatform }:
let
  root = ./..;
in
rustPlatform.buildRustPackage {
  pname = "flakelet-push";
  version = "0.1.0";
  src = lib.fileset.toSource {
    inherit root;
    fileset = lib.fileset.unions [
      (root + "/Cargo.toml")
      (root + "/Cargo.lock")
      (root + "/src")
    ];
  };
  cargoLock.lockFile = root + "/Cargo.lock";
  cargoBuildFlags = [
    "--bin"
    "flakelet-push"
  ];
  doCheck = false;
  meta.mainProgram = "flakelet-push";
}
