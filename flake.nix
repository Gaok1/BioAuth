{
  # At the repository root rather than under desktop/, because that is where a
  # flake reference without `?dir=` looks. `nix build github:Gaok1/BioAuth` is
  # the command the README gives out, and it cannot resolve a flake nested in a
  # subdirectory. The paths below reach down into desktop/; nothing else moves.
  description = "PhoneAuth desktop verifier: background agent, CLI and tray UI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    let
      # The NixOS module is system-independent, so it sits outside eachSystem.
      moduleOutputs = {
        nixosModules.default = import ./desktop/nixos/module.nix;
        nixosModules.phone-auth = self.nixosModules.default;
      };
    in
    moduleOutputs // flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.callPackage ./desktop/nixos/package.nix { };
        packages.phone-auth = self.packages.${system}.default;
        packages.phone-auth-tray =
          pkgs.callPackage ./desktop/nixos/package.nix { withTray = true; };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            rustfmt
            clippy
            nodejs
            electron
          ];

          shellHook = ''
            echo "PhoneAuth desktop"
            echo "  cargo test --workspace          run every test"
            echo "  cargo run -p phone-auth-agent --features dev-simulator -- --dev-simulator"
            echo "  (cd ui && npm install && npm start)"
            echo
            echo "The simulator signs in-process with a software key."
            echo "It is not a phone and cannot unlock a disk."
          '';
        };

        checks.default = self.packages.${system}.default;
      });
}
