{
  description = "PhoneAuth desktop verifier: background agent, CLI and tray UI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    let
      # The NixOS module is system-independent, so it sits outside eachSystem.
      moduleOutputs = {
        nixosModules.default = import ./nixos/module.nix;
        nixosModules.phone-auth = self.nixosModules.default;
      };
    in
    moduleOutputs // flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.callPackage ./nixos/package.nix { };
        packages.phone-auth = self.packages.${system}.default;
        packages.phone-auth-tray =
          pkgs.callPackage ./nixos/package.nix { withTray = true; };

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
