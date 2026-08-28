# Vault and File Locker application frames

Status: version 1, implemented in Rust and Dart with a shared golden vector.

Authorization continues to use `AuthRequest`/`AuthResponse`. Vault and locker
traffic uses a separate application envelope inside the authenticated encrypted
session. An application frame is **not** a biometric-signature payload and must
never be copied into an authorization request, audit entry, exception, or debug
string.

## Canonical wire form

The frame is a canonical CBOR array with nine elements:

| Index | Field | Rule |
|---:|---|---|
| 0 | message type | `4` |
| 1 | protocol version | `1`; unknown versions fail closed |
| 2 | kind | `0` request, `1` response, `2` cancel, `3` error |
| 3 | request ID | non-blank, at most 64 UTF-16 code units |
| 4 | session binding | exactly 32 bytes from the current handshake |
| 5 | operation | at most 64 ASCII bytes under `vault.*` or `locker.*` |
| 6 | issued at | UTC Unix time in milliseconds |
| 7 | expires at | after issuance and no more than 120 seconds later |
| 8 | payload | opaque service bytes, at most 6144 bytes |

The whole transport frame remains limited to 8192 bytes. Definite lengths,
shortest integer encodings, valid UTF-8, no trailing bytes, and byte-for-byte
canonical re-encoding are mandatory.

## Acceptance rules

A response, cancellation, or error is accepted only when request ID, session
binding, and operation equal the still-pending request and the frame has not
expired. The caller owns that pending-request check; successfully decoding an
envelope is not authorization.

Payload schemas are versioned by their operation and are defined with the vault
or locker feature. They may contain secrets only while held inside the secure
channel processing path. Implementations must not derive `Debug`/`toString`
output that includes payload bytes, and audit logs record only generic operation
outcomes.

The shared vector is pinned in
`desktop/crates/phone-auth-protocol/src/application.rs` and
`mobile/test/application_frame_test.dart`.

## File Locker operations

Three operations are defined. All three carry a container binding — the value
described in `docs/locker-format.md` — so an approval given for one container
cannot be replayed onto another, and none of them ever names a path: the phone
is shown a file name and a computer name, which is what a person can actually
check.

| Operation | Direction | Purpose |
|---|---|---|
| `locker.create` | desktop → phone | Wrap a data key for a new container |
| `locker.unlock` | desktop → phone | Unwrap an existing container's data key |
| `locker.rekey` | desktop → phone | Unwrap in order to bind the container to a new key |

`locker.rekey` is structurally identical to `locker.unlock` and deliberately
separate: the phone tells the user that this container is about to change
hands, and the audit trail says so too. A rekey is therefore two approvals when
the same phone does both halves, and one when the current key comes from the
offline recovery code — which is the case that actually matters, because a
phone being replaced cannot open the wrapper it is replacing.

### `locker.create`

Request payload — a six-element CBOR array:

| Index | Field | Rule |
|---:|---|---|
| 0 | schema | `1` |
| 1 | verifier name | the computer, as the user named it; at most 255 units |
| 2 | file name | shown on the phone; at most 255 units |
| 3 | plaintext length | bytes |
| 4 | container binding | exactly 32 bytes |
| 5 | data key | exactly 32 bytes |

Response payload — three elements: schema, the credential id that wrapped it,
and the opaque wrapper (1 to 512 bytes). The credential id goes into the
container so a later unlock asks the phone that can answer.

### `locker.unlock` and `locker.rekey`

Request payload — seven elements: schema, verifier name, the container's file
name, plaintext length, container binding, credential id, and the wrapper.
Response payload — two elements: schema and the 32-byte data key.

The phone computes the wrapper's additional data from the binding it was sent
and the credential id **it holds**, never the one in the frame. A container
whose wrapper id was edited therefore fails its tag rather than being unwrapped
under a different name.

### What crosses the link

A data key crosses in both directions: to the phone on `locker.create`, back to
the desktop on `locker.unlock`. That is the design — the desktop holds the
ciphertext and does the decryption, the phone holds the authority to release
the key — and it is why these operations are refused outright on a session that
is not both confidential and peer-authenticated.

The shared vector is pinned in
`desktop/crates/phone-auth-protocol/src/locker.rs` and
`mobile/test/locker_payloads_test.dart`.
