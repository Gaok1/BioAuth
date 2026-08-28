# PhoneAuth Desktop

The verifier side: a background agent that asks a paired phone to authorize
something, and decides whether the answer is worth anything.

Written in Rust, with a small Electron tray as the only UI. The split is
deliberate — every decision that matters happens in the agent, and the tray is
a view that cannot approve anything even if it is fully compromised.

## What runs today

| Piece | State |
|---|---|
| Canonical wire format, byte-compatible with the Dart codec | done, golden-vector locked |
| Secure session handshake, record layer, session binding | done, vector-locked |
| Verifier core: pairing, policy, replay, signature checking | done |
| `QrNetworkTransport`: listen, handshake, hand a session to the verifier | done |
| Pairing: QR, verification code, enrolment, storage | done end to end |
| Background agent with local IPC | done |
| `phone-auth` CLI (the PAM entry point) | done |
| Electron tray, with a scannable QR | done |
| NixOS module, systemd units, PAM wiring | done |
| `phone-auth-initrd` decision logic | done |
| **A phone that speaks any of it** | **not built — see pendências** |

The desktop is complete. A phone can connect over TCP, pair, and authorize,
and the whole path runs today against a simulated phone that speaks the real
protocol over a real socket.

That simulator is not security: it signs with a software key and approves
everything. It enrols as `KeyKind::Software`, which is on its own enough to
make a boot-time unlock request fail.

## Layout

```text
desktop/
├── crates/
│   ├── phone-auth-protocol/   canonical CBOR frames, validation. No I/O, no deps.
│   ├── phone-auth-session/    handshake, record layer, session binding
│   ├── phone-auth-verifier/   pairing store, policy, replay guard, ECDSA checks
│   ├── phone-auth-agent/      the daemon: IPC, transports, audit log
│   ├── phone-auth-cli/        `phone-auth` — used by PAM, sudo and scripts
│   └── phone-auth-initrd/     boot-time unlock, separate binary on purpose
├── ui/                        Electron tray
└── nixos/                     package.nix and the NixOS module
```

`flake.nix` sits at the repository root, not here. A flake reference without
`?dir=` only resolves at the root, and `nix build github:Gaok1/BioAuth#default`
is the command the README hands out. Its paths reach down into `desktop/`.

`phone-auth-protocol` has no dependencies at all. It defines the bytes that get
signed, so its encoding must not drift with a third-party CBOR library's
choices, and it has to stay small enough to link into an initrd.

`phone-auth-session` deliberately does not depend on `phone-auth-verifier`.
The verifier consumes the `SecureSession` trait, and an edge pointing the other
way would make the abstraction depend on one of its implementations. The
adapter that joins them lives in the agent, which already has both. The session
binding is derived in exactly one place, for the same reason: two copies of a
derivation that must match across two devices is precisely the thing that
drifts.

## Running it

```sh
# Everything, including the cross-language golden vector
cargo test --workspace

# The agent, with the development simulator standing in for a phone
cargo run -p phone-auth-agent --features dev-simulator -- --dev-simulator

# In another shell
cargo run -p phone-auth-cli -- status
cargo run -p phone-auth-cli -- authorize \
  --service sudo --action "nixos-rebuild switch" \
  --resource "$(hostname)" --user "$USER"

# The tray
cd ui && npm install && npm start
```

`--dev-simulator` prints a banner on every start, the tray shows a permanent
warning, and every audit entry it produces is tagged. It cannot satisfy a
boot-time unlock: the verifier refuses both its software key and its
development-flagged transport.

## The authorization flow

```text
  sudo / login / a script
          │
          ▼
   phone-auth authorize          exit 0 only on a verified grant
          │  loopback IPC + token
          ▼
   phone-auth-agent
          │  1. pick a paired credential whose policy covers the request
          │  2. open a confidential, peer-authenticated session
          │  3. build a request: fresh 32-byte challenge, fresh request id,
          │     session binding, ≤2 minute window
          ▼
     AuthTransport  ── canonical CBOR frame ──▶  phone
                                                  │ shows verifier, service,
                                                  │ action, resource, user
                                                  │ BIOMETRIC_STRONG per use
                                                  │ signs the whole frame
     AuthTransport  ◀── response frame ─────────  │
          │
          ▼
   phone-auth-agent
             4. burn the request id (single use, whatever the outcome)
             5. re-check pairing and policy — both may have changed
             6. verify ECDSA P-256 over the *request frame*, not the challenge
             7. Grant
```

Step 6 is the one that carries the weight. The signature covers
`requestId, verifierId, verifierName, credentialId, challenge, service, action,
resource, user, issuedAt, expiresAt, sessionBinding` — so a signature collected
for `sudo ls` cannot authorize `sudo rm`, and one collected on another session
cannot be replayed here.

## What the verifier refuses

Each of these has a test that fails if the check is removed:

- a channel that is not both confidential and peer-authenticated, refused
  *before* the phone is made to buzz
- a response whose signature covers a different request
- a signature from a key that is not the paired one
- a valid response replayed a second time
- a response answering a different request id
- a response arriving on a different session than the request left on
- an expired request
- a device unpaired while the user was tapping their phone
- a permission narrowed while the user was tapping their phone
- a software key, or a development transport, offered for disk unlock
- the `sudo` credential borrowed for a LUKS unwrap
- any single-bit mutation of a frame

## Current mobile integration state

The Android and desktop halves now share the production protocol. The remaining
work in this section is real-device validation and product scope, not missing
transport, handshake, or scanner code.

### Transport and background operation

`QrNetworkTransport` is the Android TCP client for the Rust listener and uses
4-byte length-prefixed frames. `BleTransport` is the Android GATT client for the
Linux BlueZ service. `FallbackAuthTransport` tries LAN before BLE and never
changes transport during pairing. Both paths use the same authenticated secure
session. They still need the hardware, network-failure, OEM background, and task
removal matrices tracked in `implementation-tracker.md`.

### Handshake, QR, and verification

The Dart client handshake lives under `mobile/lib/core/transport/` and matches
the Rust server through the pinned v1/v2 vectors. `PairingQRScanner` scans the
bootstrap, `PairingBootstrap` validates its identity commitment and expiry, and
`PairingController` presents the six-digit comparison before persisting the
pairing. The desktop tray renders the QR and requires its own matching
confirmation.

### Credential purpose and key kind

Android enrolls `bioauth_authorization_v1` for ordinary authorization and
reports hardware/StrongBox backing in the enrolment frame. The verifier stores
and enforces both `KeyKind` and `CredentialPurpose`. Reserved `vault`, `locker`,
`luks`, and `webauthn` services select distinct credential purposes inside the
verifier; IPC callers cannot override that mapping. Their native Android aliases
are delivered with the corresponding feature and never reuse the authorization
alias.

### iOS

`packages/phone_auth_native/ios/.../PhoneAuthNativePlugin.swift` remains a
scaffold. There is no Secure Enclave/Keychain, biometric, transport, background,
or credential-provider implementation, so iOS is outside the current product
matrix.

### Cross-language vectors

`desktop/crates/phone-auth-protocol/tests/golden_vectors.rs` and
`mobile/test/protocol_golden_vector_test.dart` pin the authorization frame.
Handshake and session-binding vectors live in
`desktop/crates/phone-auth-session/tests/handshake_vectors.rs` and the Dart
session-binding tests. Rust and Flutter run both sides in CI; the current local
suite results are recorded in `implementation-tracker.md`.

## Boot, NixOS and PAM

### Two agents, and why

The NixOS module runs the agent twice:

- a **system** agent (`/var/lib/phone-auth`, root-owned) for anything that
  grants root — sudo, login, display-manager unlock
- a **user** agent for the tray and user-level flows

This is not tidiness. PAM's `auth` stack runs as root, and a per-user agent
keeps its pairing store in the user's home. A user who can edit the file that
says which phones may approve `sudo` can add their own phone. Pointing PAM at a
user agent would look like it works and would be a privilege escalation.

### Enabling it

```nix
{
  services.phone-auth = {
    enable = true;
    verifierName = "Desktop-Casa";
    pam.services = [ "sudo" ];
  };
}
```

The PAM rule is `sufficient` by default: the phone can satisfy authentication,
and the password rule below it still works. `pam.required = true` makes the
phone mandatory, which turns a flat battery into a lockout — only set it with a
tested recovery path.

Add `sudo` first, keep a root shell open while testing, and confirm the
password fallback still works before adding anything else.

### Exit codes are the interface

`pam_exec` reads any zero exit as success, so the CLI never returns 0 unless a
grant was actually verified:

| Code | Meaning |
|---|---|
| 0 | verified grant |
| 1 | declined, expired, replayed, or refused by policy |
| 2 | usage error |
| 3 | agent unreachable, or failed before deciding |

3 is kept distinct from 1 so a PAM stack can tell an outage from a refusal.

### Boot-time unlock

`phone-auth-initrd` is a separate binary from the agent. It has no IPC
listener, no tray protocol and no audit log, because an initrd has no user
session to protect them and no way to patch them short of regenerating the
image. It shares only `phone-auth-protocol` and `phone-auth-verifier`.

On success it writes the key to stdout and exits 0, so it pipes into
`cryptsetup open --key-file=-`. Everything else exits non-zero and writes
nothing to stdout — a boot log must never capture key material.

The credential selection, key-separation and hardware-key gates are
implemented and tested. What is missing:

- a transport that works in an initrd. This is not the desktop transport with
  a different config: there is no NetworkManager, no D-Bus and no BlueZ, and
  adding any of them expands what runs before the disk is decrypted. The
  roadmap gates this behind a separate attack-surface review, which has not
  happened.
- a dedicated LUKS wrapping credential — see pendência 4.

The module deliberately ships no initrd unit. A unit that cannot work would
only invite someone to enable it and find out at the next reboot.

**An offline recovery keyslot is mandatory.** The phone must never be the only
way into the volume, and `phone-auth-initrd` is written so that every failure
path falls back to the passphrase prompt rather than retrying.

### Other systems

- **sudo, login, ssh, display managers** — all reachable through `pam_exec`
  today, once a transport exists. Add the service name to `pam.services`.
- **Windows** — the agent, CLI and tray already build and run on Windows; the
  paths module handles `%LOCALAPPDATA%`. A Credential Provider is roadmap
  phase 4 and is not started.
- **polkit** — not wired. `phone-auth authorize` is a plain exit-code program,
  so a polkit agent could shell out to it.

## Wire format

Fixed-order CBOR arrays, never maps, so no key-ordering ambiguity can exist
between implementations. Encoding rules mirror
`mobile/lib/core/protocol/protocol_codec.dart` exactly, including measuring
string lengths in UTF-16 code units, because that is what Dart's
`String.length` counts.

Request frame, 14 elements:

```text
[1, protocolVersion, requestId, verifierId, verifierName, credentialId,
 challenge(32), service, action, resource, user, issuedAt, expiresAt,
 sessionBinding(32)]
```

Response frame, 8 elements:

```text
[2, protocolVersion, requestId, verifierId, credentialId, decision,
 algorithm, signature]
```

`decision` is the Dart enum index: `0 = authorized`, `1 = denied`. Reordering
that enum would silently turn a denial into an approval, so the values are
pinned by a test.

Decoders re-encode what they parsed and compare it to the input. A frame that
does not reproduce itself is rejected, because the signature covers those exact
bytes.

- `algorithm`: `SHA256withECDSA` — ECDSA P-256 with SHA-256, DER signature
- public key: `EC_P256_SPKI` — X.509 SubjectPublicKeyInfo DER

Enrolment frame, 9 elements, sent once after a pairing handshake:

```text
[3, protocolVersion, deviceName, credentialId, algorithm, publicKey,
 keyKind, purpose, reserved]
```

The handshake that carries these frames is a separate contract, specified with
its own test vectors in `protocol-handshake.md`.

## Browser passkey relay

`phone-auth-webauthn-host` is a native-messaging adapter, not another verifier.
It reads the user-only agent endpoint file and calls `webauthn.perform` over the
existing token-authenticated loopback IPC. The agent selects one already-paired
phone and sends a bounded `BAWA1\n` JSON envelope over the same confidential,
peer-authenticated session. Request and response IDs must match; a mismatched,
oversized, non-HTTPS, or malformed envelope fails closed.

The WebAuthn relay is intentionally separate from the canonical signed
`AuthRequest`/`AuthResponse` arrays above: WebAuthn assertions are signed by the
per-RP passkey over WebAuthn `authenticatorData || clientDataHash`, while the
PhoneAuth session authenticates the paired computer carrying that operation.
Installation and the desktop-origin trust asymmetry are in `webauthn.md`.

## Copying a secret

A secret is copied by the agent, never by the tray. `vault.generate-copy`
generates a password, writes it into page-locked memory, and puts it on the
clipboard:

```text
vault.generate-copy
  params: { length?, lowercase?, uppercase?, digits?, symbols?, clearAfterMs? }
  result: { length, clearsAtMs, historyExcluded, cloudExcluded, memoryLocked }
```

Every parameter is optional and falls back to the generator's default, so `{}`
is a valid call. **The result carries no field holding the password**, and that
is the point rather than an omission: a password that crossed this boundary
would enter a renderer and a V8 heap that may be dumped. A test goes through the
real socket, reads back what actually landed on the clipboard, and searches for
that text in the raw response bytes — a new field, a debug echo or an error
message carrying the secret fails there.

`historyExcluded`, `cloudExcluded` and `memoryLocked` report what the OS
actually granted. They are not decoration: on a platform that refuses page
locking or offers no exclusion markers they come back false, and the UI must
show what is true rather than a lock that is not there.

`clearAfterMs` is bounded to 5s–600s, defaulting to 45s. The scheduled clear
fires only if the clipboard sequence number is still the one we set — otherwise
the timer would erase whatever the user copied in the meantime.

## Reading the phone's vault

Two methods reach the vault the phone holds. Both need a credential enrolled
with the `vault` purpose — the same credential that authorizes `sudo` will not
do, and naming one by `credentialId` does not let a caller borrow it.

```text
vault.list
  params: { credentialId? }
  result: { items: [{ id, revision, kind, name, username, uri, updatedAtMs }],
            deviceName, development }

vault.copy
  params: { itemId, expectedRevision, credentialId?, clearAfterMs? }
  result: { length, clearsAtMs, historyExcluded, cloudExcluded, memoryLocked }
```

`vault.list` costs no biometric prompt, because it releases no secret. It walks
the phone's pages itself and returns the whole list; a phone that repeats a
cursor or never ends is refused rather than followed.

`vault.copy` is one approval on the phone for one item. The secret arrives, is
moved into page-locked memory, and goes to the clipboard along the path
described above — it reaches no reply, no event and no audit entry, and
`VaultCopyResult` is the same type `vault.generate-copy` returns precisely
because it has no field that could carry it.

`expectedRevision` is the revision of the row the user clicked, and a phone that
answers with a different one gets a `revision-conflict` rather than a copy: the
item was edited elsewhere, and pasting it would hand over a value the user never
looked at.

A refusal comes back as `declined` whether the item is missing, the revision is
stale, or the user dismissed the prompt. That is `protocol-application.md`'s
coarse taxonomy surfacing at the IPC edge, and it is why `vault.copy` cannot be
used to discover which item IDs exist.

### From the command line

```sh
phone-auth vault list
phone-auth vault copy github
phone-auth vault copy github --revision 4 --clear-after 15000
phone-auth vault generate --length 32 --no-symbols
```

`vault copy` takes an id, a name, or a unique fragment of either a name or a
URI. Resolving it is also where `expectedRevision` comes from: the agent refuses
a copy that does not name a revision, and a person typing a command has no way
to know one, so the CLI lists first and copies second — the same two steps the
tray takes when the user clicks a row. Passing `--revision` pins a revision read
earlier instead, which is the stronger check.

An ambiguous fragment is refused and the refusal prints the candidates with
their ids. Guessing would be worse here than anywhere else in the CLI: nothing
downstream ever displays what was copied, so the wrong secret on the clipboard
is silent until it is pasted somewhere.

Exit codes follow `authorize`: `0` copied, `1` refused — declined on the phone,
no vault credential enrolled, `revision-conflict` — `2` for a value the command
line got wrong, and `3` for an agent that could not be reached or a clipboard
that would not take the value. All three vault commands share one mapping, so a
computer with no vault credential answers `1` to `list` and to `copy` alike.

There is deliberately no `vault create`, `vault edit` or `vault delete`. The
phone serves all three, but a write driven from the computer needs a screen on
the phone that names what is being changed, and until that exists the phone's
own UI is the only place a vault item is edited.

## Files the agent owns

| Path (Linux) | Contents |
|---|---|
| `~/.config/phone-auth/agent.json` | verifier id and display name |
| `~/.local/share/phone-auth/devices.json` | paired public keys and permissions |
| `~/.local/share/phone-auth/audit.jsonl` | decisions, bounded to ~500 entries |
| `$XDG_RUNTIME_DIR/phone-auth/agent-endpoint.json` | live IPC port and token, 0600 |

The pairing store holds only public keys: leaking it discloses nothing that can
authorize on its own, but *writing* to it is an authority grant.

The audit log deliberately contains no challenge, session binding, signature,
public key or frame bytes. A test asserts their absence, so a future field
carrying protocol material fails the build rather than quietly turning a
readable history into a file that must be protected like a secret.
