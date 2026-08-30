# Windows updates and rollback

PhoneAuth checks for a newer stable Windows release one minute after startup
and every six hours after that. A check can also be started from the tray. It
downloads but never silently runs an installer: **Install PhoneAuth _version_**
appears only after verification, and the user starts it explicitly.

The updater is deliberately unavailable on Linux, in development builds and
in unsigned Windows builds. Those builds continue to be installed manually.

## What is trusted

The installed `PhoneAuth.exe` is the trust root. Windows must report a valid
Authenticode signature, and its signed file version must equal the running
app version before PhoneAuth makes any release request. The updater then:

1. accepts only GitHub's canonical, non-draft, non-prerelease `vX.Y.Z` release;
2. accepts exactly `PhoneAuth-Setup-X.Y.Z-x64.exe` from this repository;
3. bounds and matches the release metadata and downloaded byte count;
4. requires a valid Authenticode signature with the installed app's exact
   public key and the expected signed file version; and
5. repeats the signature, signer and version checks immediately before launch.

A certificate renewal may reuse the same signing key. A signing-key rotation
cannot be automatic: existing installations fail closed and require a manually
verified installer. This prevents a compromised release account from replacing
an update with an old or differently signed executable.

The release job supplies the certificate to electron-builder *before*
packaging, so it signs `PhoneAuth.exe`, bundled Windows helpers and the NSIS
installer. Stable releases fail if the signing secrets are absent, and the job
verifies every shipped executable with `signtool` after packaging.

## Rollback

Before accepting an update, PhoneAuth downloads the installer for the version
currently running and verifies it by the same rules. After the newer version
starts, **Roll back to PhoneAuth _version_** runs that preserved installer only
after verifying it again. Missing, changed, wrongly versioned or differently
signed files are deleted or refused; an update without a valid rollback
installer is not offered.

Rollback does not rewrite user data. Versioned stores preserve pre-migration
snapshots, and older builds refuse future store versions rather than treating
them as corruption or offering destructive recovery. This is an explicit tray
rollback, not an unattended crash detector: if the new tray cannot start, run
the preserved signed installer from the per-user PhoneAuth `updates` directory.
