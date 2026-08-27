# Build definition for the PhoneAuth desktop binaries.
#
# The simulator is not built. It is a development fixture that signs without
# any biometric gate, and a package in a system profile is exactly where it
# must never appear.
{
  lib,
  rustPlatform,
  # Kept optional so the module can install the agent and CLI on a headless
  # machine without pulling in Electron.
  withTray ? false,
  electron,
  makeWrapper,
  nodejs,
  fetchNpmDeps,
}:
rustPlatform.buildRustPackage {
  pname = "phone-auth";
  version = "0.1.0";

  src = lib.cleanSource ../.;

  cargoLock.lockFile = ../Cargo.lock;

  # `--dev-simulator` is a compile-time feature and stays off. A build that
  # could be flipped into simulator mode by a runtime flag would defeat the
  # point of gating it.
  buildNoDefaultFeatures = false;
  cargoBuildFlags = [
    "--package"
    "phone-auth-agent"
    "--package"
    "phone-auth-cli"
    "--package"
    "phone-auth-initrd"
  ];

  nativeBuildInputs = lib.optionals withTray [ makeWrapper nodejs ];

  # The tray's only runtime dependency is a QR encoder, used in the Electron
  # main process. Reed-Solomon and mask selection are not worth hand-rolling:
  # a subtly wrong encoder produces a code that simply will not scan.
  #
  # `npmDeps` needs a hash Nix can only tell you by trying. On the first build
  # it will report the real one; paste it in place of `fakeHash`.
  npmDeps = lib.optionalAttrs withTray (
    fetchNpmDeps {
      src = ../ui;
      hash = lib.fakeHash;
    }
  );

  postInstall = lib.optionalString withTray ''
    mkdir -p $out/share/phone-auth
    cp -r ${../ui}/src ${../ui}/renderer ${../ui}/assets ${../ui}/package.json \
      $out/share/phone-auth/
    cp -r node_modules $out/share/phone-auth/

    makeWrapper ${electron}/bin/electron $out/bin/phone-auth-tray \
      --add-flags $out/share/phone-auth
  '';

  meta = with lib; {
    description = "Authorize a Linux desktop from a paired phone's biometrics";
    longDescription = ''
      PhoneAuth verifier for the desktop. Runs a background agent that asks a
      paired phone to sign an authorization request, and verifies the answer
      against a hardware-backed public key.

      The BLE and QR/network transports are not implemented yet, so a running
      agent currently reports every transport as unavailable. See
      docs/desktop.md for what is outstanding on the mobile side.
    '';
    license = licenses.mit;
    platforms = platforms.linux;
    mainProgram = "phone-auth";
  };
}
