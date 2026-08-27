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
| Verifier core: pairing, policy, replay, signature checking | done, 57 tests |
| Background agent with local IPC | done |
| `phone-auth` CLI (the PAM entry point) | done |
| Electron tray | done |
| NixOS module, systemd units, PAM wiring | done |
| `phone-auth-initrd` decision logic | done |
| **A transport that reaches a real phone** | **not built — see pendências** |

So the desktop can do everything except talk to a phone. The full path —
issue, sign, verify, grant — runs end to end today against an in-process
development simulator, which proves the logic with real ECDSA but is not a
phone and is not security.

## Layout

```text
desktop/
├── crates/
│   ├── phone-auth-protocol/   canonical CBOR frames, validation. No I/O, no deps.
│   ├── phone-auth-verifier/   pairing store, policy, replay guard, ECDSA checks
│   ├── phone-auth-agent/      the daemon: IPC, transports, audit log
│   ├── phone-auth-cli/        `phone-auth` — used by PAM, sudo and scripts
│   └── phone-auth-initrd/     boot-time unlock, separate binary on purpose
├── ui/                        Electron tray
├── nixos/                     package.nix and the NixOS module
└── flake.nix
```

`phone-auth-protocol` has no dependencies at all. It defines the bytes that get
signed, so its encoding must not drift with a third-party CBOR library's
choices, and it has to stay small enough to link into an initrd.

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

## Pendências — bloqueadas no mobile

The desktop is finished up to the transport boundary. Nothing below can be
completed here, because each needs the phone to speak the other half.

### 1. No production end-to-end transport exists (blocks real authorization)

`mobile/lib/core/transport/auth_transport.dart` defines `AuthTransport` and
`SecureTransportSession`. Both `FakeTransport` and `BleTransport` implement
that boundary without changing the protocol or authorization core.

- **`BleTransport`** — the mobile Android GATT client, bounded framing, MTU,
  notifications, permissions, and timeout behavior exist. It still needs the
  desktop GATT server, production pairing/session handshake, reconnect policy,
  and Android background policy. The desktop agent therefore correctly lists
  it as `unimplemented` rather than pretending the raw link is secure.
- **`QrNetworkTransport`** — roadmap phase 1B. Needs the QR scanner on the
  phone, the endpoint publication on the desktop, and TLS from a standard
  stack.

Until one exists, `phone-auth authorize` exits 3 (`no-transport`) on any real
machine.

### 2. The session-binding derivation is not agreed

`phone_auth_verifier::session::derive_session_binding` is the verifier's half:

```text
SHA-256( "PhoneAuth/session-binding/v1"
       ‖ len‖transport_name ‖ len‖session_id
       ‖ len‖verifier_handshake_key ‖ len‖peer_handshake_key
       ‖ len‖transcript_secret )
```

Every field is length-prefixed. Fake sessions derive a binding on both sides
and the core rejects mismatches. A production handshake must implement the
same exporter/binding contract on mobile and desktop; the fake establisher is
never wired into a release build.

### 3. Pairing cannot complete

`pair.begin` produces a bootstrap — version, verifier id, session id, a fresh
32-byte nonce, an expiry — and carries no permanent secret, per the threat
model. What is missing on mobile:

- the QR bootstrap scanner (`shared/pairing_qr_code.dart` is a placeholder
  icon, not a scanner)
- the pairing handshake that proves possession of the device key
- returning the public key, its `KeyKind`, and its `CredentialPurpose`

Consequence: the QR payload the tray shows is informational. Pairing today is
only possible by writing `devices.json` directly, which is what
`--dev-simulator` does for its own fixture.

The desktop also renders the bootstrap as text rather than a QR image. There is
no point drawing a code nothing can scan; QR rendering lands with this item.

### 4. One credential, no purpose separation

`DeviceKeyStore.kt` has a single alias, `bioauth_authorization_v1`. The
architecture requires separate credentials per purpose, and the desktop already
models and enforces that (`CredentialPurpose::{Authorization, DiskUnlock}`).

Needed on mobile: a second, separately-enrolled alias for the LUKS wrapping
credential, and a way to report which alias is which at pairing time. Without
it, no disk-unlock credential can ever be enrolled — the verifier will refuse
to reuse the authorization credential, by design.

### 5. `KeyKind` is not reported at pairing

`PhoneAuthNativePlugin.kt` computes `keySecurity()` — `hardwareBacked`,
`strongBoxBacked` — but nothing carries it into a pairing record. The desktop
needs it: it is what distinguishes a StrongBox key from a software one, and the
boot-time gate depends on it. Until then, every real pairing has to be assigned
a `keyKind` by hand.

### 6. iOS is not implemented

`packages/phone_auth_native/ios/.../PhoneAuthNativePlugin.swift` is a stub. The
desktop is platform-agnostic — it verifies a P-256 SPKI key and a DER signature
regardless of origin — so a Secure Enclave implementation should need no
desktop change. Worth confirming that `SecKeyCreateSignature` with
`ecdsaSignatureMessageX962SHA256` produces the same bytes Android's
`SHA256withECDSA` does. It should; it is the same algorithm and the same DER
encoding.

### 7. Cross-language golden vector

`desktop/crates/phone-auth-protocol/tests/golden_vectors.rs` pins the wire
format against a vector derived independently from RFC 8949.
`mobile/test/protocol_golden_vector_test.dart` asserts the same bytes from the
Dart side. Both the Flutter and Rust suites execute it in CI, proving the two
independent codecs agree on the pinned frame.

It has not been executed: no Flutter or Dart SDK is installed on this machine.
**Run `flutter test test/protocol_golden_vector_test.dart` before trusting the
two codecs to match.** If it fails, the desktop is wrong and the phone is
right — the Dart codec is the older of the two.

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
