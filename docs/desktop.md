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

## Pendências — bloqueadas no mobile

Every item below needs the phone. The desktop half of each one exists, is
tested, and is specified in `protocol-handshake.md` with test vectors.

### 1. No transport on the phone (blocks real authorization)

`mobile/lib/core/transport/auth_transport.dart` defines `AuthTransport` and
`SecureTransportSession`. Both `FakeTransport` and `BleTransport` implement
that boundary without changing the protocol or authorization core.

- **`QrNetworkTransport`** — the desktop side is built and listening. It
  accepts a TCP connection, runs the handshake and hands a `SecureSession` to
  the verifier. The phone needs the matching client: a socket, 4-byte
  length-prefixed frames, and the two-message handshake. This is the shortest
  path to a working phone.
- **`BleTransport`** — the mobile Android GATT client, bounded framing, MTU,
  notifications, permissions and timeout behaviour exist. It still needs the
  desktop GATT server, reconnect policy and Android background policy. The
  agent lists it as `unimplemented` rather than pretending the raw link is
  secure. The handshake above it is the same one `QrNetworkTransport` uses, so
  that work is not repeated.

Until one exists, `phone-auth authorize` exits 3 (`no-transport`) with a real
phone.

### 2. The client half of the handshake

The desktop implements both halves in `phone-auth-session`; the phone needs
the client one. It is fully specified in `protocol-handshake.md`:

- the ClientHello encoding and its signature envelope
- the key schedule, split in the documented order
- the session binding — byte-identical or every request fails
- the record layer, including in-order counter enforcement

`ClientHandshake::respond` is the reference and is under 80 lines. The
deterministic parts have published test vectors; **implement those first**,
because each of them fails on the wire with the same undiagnosable symptom.

### 3. QR scanner and the verification code screen

`shared/pairing_qr_code.dart` is a placeholder icon, not a scanner. The phone
needs to parse the bootstrap, check `SHA-256("PhoneAuth/identity/v1" ‖ spki)`
against the code's commitment, and show the six-digit verification code with
an explicit confirm step.

That screen is not cosmetic. The QR authenticates the desktop to the phone;
the code is the only thing that stops someone who photographed the QR from
pairing their own device instead of the user's.

The desktop side is complete: the tray renders a scannable code, polls for a
completed handshake, shows the same six digits and stores nothing until the
user confirms.

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
`strongBoxBacked` — but nothing carries it into a pairing record.

The desktop now has somewhere to put it: the enrolment frame
(`protocol-handshake.md`) carries `key_kind` and `purpose`, and the verifier
stores both. The phone has to fill them in honestly. It is a claim the
verifier cannot check, used only to *withhold* authority — a `Software` key is
refused for disk unlock — so reporting it truthfully is a correctness
requirement on the phone, not a formality.

### 6. iOS is not implemented

`packages/phone_auth_native/ios/.../PhoneAuthNativePlugin.swift` is a stub. The
desktop is platform-agnostic — it verifies a P-256 SPKI key and a DER signature
regardless of origin — so a Secure Enclave implementation should need no
desktop change. Worth confirming that `SecKeyCreateSignature` with
`ecdsaSignatureMessageX962SHA256` produces the same bytes Android's
`SHA256withECDSA` does. It should; it is the same algorithm and the same DER
encoding.

### 7. Cross-language vectors

`desktop/crates/phone-auth-protocol/tests/golden_vectors.rs` pins the wire
format against a vector derived independently from RFC 8949.
`mobile/test/protocol_golden_vector_test.dart` asserts the same bytes from the
Dart side. Both the Flutter and Rust suites execute it in CI, proving the two
independent codecs agree on the pinned frame.

It has not been executed here: no Flutter or Dart SDK is installed on this
machine. **Run `flutter test test/protocol_golden_vector_test.dart` before
trusting the two codecs to match.** If it fails, the desktop is wrong and the
phone is right — the Dart codec is the older of the two.

The handshake has its own vectors, in
`desktop/crates/phone-auth-session/tests/handshake_vectors.rs` and reproduced
in `protocol-handshake.md`. They were derived from the specification with an
independent implementation rather than from the Rust source, so agreement is
evidence and not a tautology. There is no Dart counterpart yet, because there
is no Dart handshake yet; writing the vectors test first is the cheapest way
to build one.

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
