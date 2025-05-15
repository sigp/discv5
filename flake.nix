{
  description = "Description for the project";

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    devshell = {
      url = "github:numtide/devshell";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [ inputs.devshell.flakeModule ];
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];
      perSystem =
        {
          config,
          self',
          inputs',
          pkgs,
          system,
          ...
        }:
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [ inputs.fenix.overlays.default ];
          };

          devshells.default = {
            env = [
              {
                name = "LD_LIBRARY_PATH";
                value = "${pkgs.openssl.out}/lib:$LD_LIBRARY_PATH";
              }
              {
                name = "PKG_CONFIG_PATH";
                value = "${pkgs.openssl.dev}/lib/pkgconfig";

              }
            ];

            packages = with pkgs; [
              fenix.stable.completeToolchain
              openssl
              pkg-config
              gnumake
            ];

          };
        };
      flake = { };
    };
}
