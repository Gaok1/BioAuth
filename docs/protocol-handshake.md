# PhoneAuth Secure Session Handshake

The contract between a phone and a desktop, below the authorization protocol
and above whatever moves bytes.

The desktop implements this in `desktop/crates/phone-auth-session`. This
document is what the mobile side is written against. Where the two disagree,
nothing works and the symptom is always the same — a decryption failure with
no explanation — so the test vectors at the end matter more than they look.

## What it provides

- **Confidentiality and integrity** for every frame, from an AEAD keyed by a
  fresh Diffie-Hellman exchange.
- **Mutual authentication**: each side proves possession of a long-lived
  P-256 identity key the other side already trusts.
- **A session binding**: 32 bytes both ends derive, folded into the signed
  authorization request so a response cannot be moved between sessions.
- **Forward secrecy**: identity keys sign, they never encrypt. Recording a
  session and later stealing an identity key does not decrypt the recording.

## What it does not provide

It establishes *which device* is on the other end. It says nothing about
whether a human approved anything. Authorization comes afterwards, from a
biometric signature over an `AuthRequest`, and this layer only carries those
bytes.

## Roles

| Role | Who | Does |
|---|---|---|
| **Server** | the desktop verifier | listens, sends the first message |
| **Client** | the phone | connects, answers |

The desktop speaks first even though the phone dials. That keeps the phone
from having to guess a session id, and means every session's parameters are
signed by the desktop before the phone commits to anything.

## Keys

Two entirely separate keys live on the phone, and conflating them is the
mistake this section exists to prevent.

| Key | Curve | Used for | Gated by |
|---|---|---|---|
| **Session identity** | P-256 | signing handshake messages | nothing |
| **Authorization credential** | P-256 | signing `AuthRequest` | `BIOMETRIC_STRONG`, per use |

A handshake happens whenever a phone comes into range, with no user present.
It must never touch the key that approves a login. On Android the
authorization credential is the Keystore alias with
`setUserAuthenticationRequired(true)`; the session identity is an ordinary
app-held key.

Ephemeral keys are X25519, fresh per handshake, never reused.

## The bootstrap (QR code)

Only used for first contact. An already-paired phone never scans anything.

```text
phoneauth://pair/v1?vid=<verifier-id>&sid=<session-id>&n=<nonce>&k=<identity-hash>&ep=<endpoint>&exp=<expiry-ms>
```

| Field | Meaning |
|---|---|
| `vid` | verifier id, 1–64 characters |
| `sid` | session id, 1–64 characters |
| `n` | 32 random bytes, unpadded base64url |
| `k` | SHA-256 of the verifier's identity SPKI, unpadded base64url |
| `ep` | `host:port` to connect to; empty for transports without addresses |
| `exp` | expiry, milliseconds since the Unix epoch |

Parsing rules: every field is required, an unknown field is a hard failure,
and no field may contain `&` or `=`. Missing fields must not default —
a bootstrap without `k` would leave the phone with nothing to authenticate the
desktop against.

`k` is the whole point. It is the only thing that distinguishes the real
desktop from a relay on first contact, and it is trustworthy because the user
physically pointed a camera at that screen.

```text
identity_hash = SHA-256("PhoneAuth/identity/v1" ‖ spki)
```

The code carries no private key, no long-term secret and nothing that
authorizes anything. Photographing it lets someone *attempt* a pairing. It does
not let them complete one, because of the verification code below.

## Message 1 — ServerHello

A CBOR array of 8 elements, wrapped in a signature envelope.

```text
[16, 1, session_id, nonce, verifier_id, expires_at_ms, identity_spki, ephemeral]
```

| # | Type | Notes |
|---|---|---|
| 0 | uint | message type, always `16` |
| 1 | uint | handshake version, always `1` |
| 2 | text | session id |
| 3 | bytes | 32-byte nonce |
| 4 | text | verifier id |
| 5 | int | expiry, epoch milliseconds |
| 6 | bytes | verifier identity, X.509 SubjectPublicKeyInfo DER |
| 7 | bytes | 32-byte X25519 ephemeral public key |

## Message 2 — ClientHello

A CBOR array of 11 elements, wrapped in the same envelope.

```text
[17, 2, session_id, nonce, verifier_id, expires_at_ms,
 device_id, server_ephemeral, ephemeral, identity_spki, intent]
```

| # | Type | Notes |
|---|---|---|
| 0 | uint | message type, always `17` |
| 1 | uint | client hello version, `2` |
| 2–5 | | echoed from the ServerHello, byte for byte |
| 6 | text | device id, 1–64 characters |
| 7 | bytes | the server's ephemeral, echoed |
| 8 | bytes | the client's 32-byte X25519 ephemeral |
| 9 | bytes | client identity SPKI |
| 10 | uint | intent: `0` resume, `1` pair |

### The intent, and why it is in the signed body

Revoking a desktop on the phone does not change the phone's session identity.
A hello sent to pair afresh therefore verifies exactly as a reconnect does, and
a verifier that still holds the old record cannot tell them apart. It used to
guess from who spoke next — a pairing phone sends its enrolment immediately, a
reconnecting one waits to be asked — which costs a wait on every reconnect
while a code is armed and, worse, reads a slow link as a reconnect and fails
the pairing in silence.

Stating the intent removes the guess. It sits inside the signed body so a relay
cannot flip a reconnect into a re-enrolment, and last in the array so every
earlier field keeps the offset it had in version 1.

### Version compatibility

Only this message is versioned separately; the ServerHello stays at `1`, so a
phone built before intents still accepts a current verifier's hello.

| Phone | Verifier | Result |
|---|---|---|
| v2 | current | intent is used |
| v1 | current | accepted; the verifier falls back to the enrolment-timing heuristic |
| v2 | older | **refused** — the older verifier only reads a 10-element hello |

The last row is the deliberate cost: update the desktop at least as early as
the phone. It is bounded — a phone that cannot pair shows an error — whereas
the heuristic it replaces fails by pairing nothing and saying nothing.

The transcript hashes the exact bytes of both hellos, so nothing else needs to
change: each side derives its keys from what was actually sent.

Echoing the server's ephemeral is what stops a captured ClientHello from being
presented to a different handshake: every handshake has a fresh ephemeral, so
the echo will not match.

## The signature envelope

```text
[unsigned_body, signature]
```

A 2-element CBOR array of two byte strings. `signature` is ECDSA P-256 with
SHA-256 over `unsigned_body` exactly as encoded, in ASN.1 DER — the same shape
Android's `SHA256withECDSA` produces.

Frames are canonical CBOR: definite lengths, shortest-form integer arguments,
arrays never maps. A decoder must reject anything else rather than normalising
it, because the signature covers the bytes as received.

Maximum handshake frame: 8192 bytes.

## Verification rules

The server, on receiving a ClientHello:

1. `session_id`, `verifier_id`, `nonce` and `expires_at_ms` must equal this
   handshake's own.
2. `server_ephemeral` must equal the ephemeral just sent.
3. If the device is paired, `device_id` and `identity_spki` must equal the
   stored values. If it is not, a pairing must be armed, or the connection is
   refused.
4. The signature must verify against the presented `identity_spki`.

The client, on receiving a ServerHello:

1. If paired, `identity_spki` must equal the stored verifier key. The
   session's own `session_id`, `nonce` and `expires_at_ms` are then taken from
   the hello, because there is no scanned code to compare against.
2. If pairing, every field must equal the scanned bootstrap, **and**
   `SHA-256("PhoneAuth/identity/v1" ‖ identity_spki)` must equal the
   bootstrap's `k`.
3. `expires_at_ms` must be in the future.
4. The signature must verify.

Order matters in step 2: authenticate the verifier before deriving anything
with its key.

## Key derivation

```text
shared      = X25519(own_ephemeral_private, peer_ephemeral_public)
transcript  = SHA-256("PhoneAuth/handshake-transcript/v1"
                      ‖ u64be(len(server_hello_body)) ‖ server_hello_body
                      ‖ u64be(len(client_hello_body)) ‖ client_hello_body)
material    = HKDF-SHA256(ikm = shared, salt = transcript,
                          info = "PhoneAuth/secure-session/v1", length = 96)

client_to_server = material[0..32]
server_to_client = material[32..64]
exporter         = material[64..96]
```

The **hello bodies**, not the envelopes: signatures are excluded because ECDSA
is randomised, and each body already covers the other side's contribution.

Salting HKDF with the transcript is what ties the keys to the exact messages
exchanged. A replayed handshake against a fresh nonce produces a different
transcript and therefore different keys.

Splitting the 96 bytes in this order is part of the contract. Two
implementations that both reverse it would interoperate with each other and
with nothing else.

The `exporter` never encrypts anything and never goes on the wire. It exists so
that the session binding cannot be computed by an observer who saw the whole
handshake.

## Record layer

ChaCha20-Poly1305. Each direction has its own key and its own counter starting
at zero.

```text
record = u64be(counter) ‖ ChaCha20Poly1305(key, nonce, plaintext, aad = session_binding)
nonce  = 0x00000000 ‖ u64be(counter)
```

- The session binding is authenticated as associated data, so a record cannot
  be lifted into another session even by someone holding its keys.
- Records must arrive in order: a counter that is not exactly the expected one
  is rejected. The transports below this are reliable and ordered, so a gap
  means loss or tampering, and a tolerance window would only widen what an
  attacker can replay.
- The counter must never wrap. Refuse rather than reuse a nonce.
- Maximum plaintext: 8192 bytes.

Over a stream transport such as TCP, each record is framed with a 4-byte
big-endian length prefix, checked before allocating.

## Session binding

```text
session_binding = SHA-256("PhoneAuth/session-binding/v1"
                          ‖ u64be(len(transport_name)) ‖ transport_name
                          ‖ u64be(len(session_id))     ‖ session_id
                          ‖ u64be(len(server_eph))     ‖ server_eph
                          ‖ u64be(len(client_eph))     ‖ client_eph
                          ‖ u64be(len(exporter))       ‖ exporter)
```

Every field is length-prefixed. Under plain concatenation a transport name
ending in digits and a session id starting with them would hash the same as a
different split of the same characters.

`transport_name` is the exact string the transport reports: `QrNetworkTransport`,
`BleTransport`. Both sides must use the same one, or every request fails.

These 32 bytes go into `sessionBinding` in the signed `AuthRequest`.

## Pairing verification code

```text
digest = SHA-256("PhoneAuth/pairing-verification/v1" ‖ exporter)
code   = decimal(u32be(digest[0..4]) mod 1000000), zero-padded to 6 digits
```

Shown on both screens during pairing. The user confirms they match.

The QR already authenticates the desktop to the phone. This closes the other
direction: someone who photographed the code and raced to pair their own device
produces a different transcript, so the codes differ. Zero-padding matters —
`42` and `000042` on two screens is a failed comparison.

## Enrolment

Sent by the phone immediately after a *pairing* handshake, inside the encrypted
channel. A CBOR array of 9 elements, not signature-wrapped — the channel
already authenticates it.

```text
[3, 1, device_name, credential_id, algorithm, public_key, key_kind, purpose, 0]
```

| # | Type | Notes |
|---|---|---|
| 0 | uint | message type, always `3` |
| 1 | uint | protocol version, always `1` |
| 2 | text | display name, 1–128 characters |
| 3 | text | credential id, 1–64 characters |
| 4 | text | `EC_P256_SPKI` |
| 5 | bytes | authorization credential public key, 1–512 bytes |
| 6 | uint | `0` StrongBox, `1` Hardware, `2` Software |
| 7 | uint | `0` Authorization, `1` DiskUnlock, `2` WebAuthn, `3` Vault, `4` FileLocker |
| 8 | uint | reserved, must be `0` |

`key_kind` is a claim the verifier cannot check. It is used only to *withhold*
authority: a `Software` key is refused for disk unlock. Reporting it honestly
is a correctness requirement on the phone.

`purpose` enforces key separation. The verifier derives the required purpose
from the reserved service name (`luks`, `webauthn`, `vault`, or `locker`); a
caller cannot relabel one of those requests as ordinary authorization. A phone
that supports more than one purpose must enrol distinct keystore aliases.

A freshly enrolled credential authorizes nothing until the user grants
permissions.

## Failure rules

Everything fails closed:

- unknown version, message type, key kind or purpose → reject
- unknown bootstrap field → reject
- non-canonical CBOR → reject
- reserved field not zero → reject
- expired bootstrap or hello → reject
- signature mismatch → reject, and do not report which check failed

## Test vectors

Derived from this specification with an independent implementation, not from
the Rust source. `desktop/crates/phone-auth-session/tests/handshake_vectors.rs`
asserts all of them.

**Implement these before attempting a live handshake.** Each one fails on the
wire with the same undiagnosable symptom, so checking them in isolation is what
turns a long hunt into a five-minute fix.

Inputs:

```text
session_id      "session-1"
verifier_id     "desktop-1"
device_id       "phone-1"
expires_at_ms   1787745660000
nonce           00 01 02 ... 1f          (32 bytes, ascending)
server_ephemeral 0x11 repeated 32 times
client_ephemeral 0x22 repeated 32 times
server_spki     0xa0, 0xa1, ... wrapping, 91 bytes
client_spki     0x50, 0x51, ... wrapping, 91 bytes
shared_secret   00 01 02 ... 1f          (32 bytes, ascending)
```

Outputs:

```text
transcript
  76b72c40a881574d332adada02a0960e39c3236f4a14b6bd53c42c565e01860d

client_to_server
  8dfa481719332738c6ba26756da8c2b30fa5dde7fb300c343aee6553cf655539

server_to_client
  7ebbd0e4c9f0c0b1129ecb14324eeadafcf53483e85752ee6205a139f865b43c

exporter
  eb2501574690d2f829f0f625cf1789e5c3203b8d402d2e6fe6fee9d911cc5522

session_binding  (transport_name = "QrNetworkTransport")
  e8435f560ac83635c296802cfb1b07c01aba8c47efead3b880dcc3bbed024017

verification_code
  420017

identity_hash  (of server_spki)
  713920868af55094ba143c90dfadc9f532ce00dd11e7ffece6a3b3a71f51ab90
```

The full ServerHello and ClientHello encodings are pinned in
`desktop/crates/phone-auth-session/src/handshake.rs`, in the `wire_vectors`
test module.

## The mobile side

| | Where |
|---|---|
| Client half of the handshake | `mobile/lib/core/transport/authenticated_session_establisher.dart` |
| Bootstrap parsing | `mobile/lib/core/transport/pairing_bootstrap.dart` |
| QR scanner | `mobile/lib/shared/pairing_qr_scanner.dart` |
| Verification code screen | `mobile/lib/shared/verification_code_panel.dart` |
| Enrolment | `mobile/lib/core/protocol/enrolment.dart` |
| Transport | `mobile/lib/core/transport/qr_network_transport.dart` |

`mobile/test/handshake_vectors_test.dart` asserts every value above, and
`mobile/test/pairing_flow_test.dart` runs a pairing and an authorization over a
real socket against a desktop written from this document.

Still open:

- **A second keystore alias** for disk-unlock credentials. The existing
  `bioauth_authorization_v1` must not be reused: `purpose` enforces key
  separation, so a phone that wants both must enrol two credentials from two
  distinct aliases.
- **BLE.** The phone has a transport; the desktop's GATT adapter does not
  exist. Both ends must report the transport name `BleTransport`, since it is
  hashed into the session binding.
- **A live run against the Rust agent.** The two implementations agree with the
  vectors above and with a desktop double, but the P-256 SPKI signature
  exchange between the Android Keystore and the Rust verifier has not been
  exercised on hardware.

See `docs/desktop.md` for the verifier's side.
