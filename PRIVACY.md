# Privacy policy

Effective: 2026-08-27

BioAuth is local-first software. The project does not operate an account,
analytics, advertising, telemetry, synchronization, or credential-storage
service.

## Data stored locally

The Android app stores pairing records and passkey metadata in app-private
storage; private keys stay in the Android Keystore. The desktop agent stores
its identity, pairing records, permissions, IPC token, configuration, and
bounded audit log in the current user's application-data directories. Exact
contents and retention may change while the product remains pre-1.0;
migrations must not silently discard data.

## Data sent over the network

Paired devices communicate directly over the local network or Bluetooth using
the authenticated encrypted session. BioAuth has no project-operated relay or
cloud backend. Android passkey validation may contact the relying party named
by a request to verify its published Digital Asset Links association. Using a
website or app can separately expose data to that relying party under its own
privacy policy.

## Logs

The project audit log records bounded operational metadata needed to explain an
authorization decision. It must not contain keys, challenges, signatures,
passwords, TOTP seeds, plaintext files, or LUKS material. Diagnostic logs and
crash reports are not uploaded automatically by BioAuth. Users should inspect
and redact logs before sharing them in a support or security report.

## Deletion and retention

Users can revoke local pairings, but revocation on one device does not yet erase
the peer's retained public record automatically. Uninstalling an app delegates
local data removal to the operating system. Back up recoverable data before
uninstalling; passkey, vault, and locker recovery remain subject to the explicit
limitations in the implementation tracker.

## Contact

For a security or privacy incident, use the private process in
[`SECURITY.md`](SECURITY.md). Never include secrets or personal data in a public
issue.
