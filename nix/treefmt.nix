{ ... }:
{
  projectRootFile = "flake.nix";
  programs.rustfmt.enable = true;
  programs.nixfmt.enable = true;
  programs.actionlint.enable = true;
  settings.global.excludes = [
    "*.lock"
    "target/*"
  ];
}
