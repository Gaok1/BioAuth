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

## Error payloads

A frame of kind `3` carries a two-element canonical CBOR array: the protocol
version, then one of three codes.

| Code | Meaning |
|---:|---|
| `0` | Rejected — the peer said no, and will not say why |
| `1` | Invalid request — the frame or its payload is malformed |
| `2` | Unavailable — cannot be served right now; retrying later is meaningful |

The taxonomy is coarse on purpose, and widening it is a security change rather
than an improvement. A missing item, a revision that has moved on, and a
biometric prompt the user dismissed all answer `0`. If they answered
differently, a desktop that is not entitled to a secret could ask for item IDs
one at a time and learn which ones exist — the vault would leak its index to
exactly the caller it is refusing.

An error payload that will not decode is treated as `0` by both sides. A
malformed refusal is still a refusal, and falling back to anything softer would
turn a corrupt frame into a grant.

The same three encodings are pinned in
`desktop/crates/phone-auth-protocol/src/application.rs` and
`mobile/test/application_frame_test.dart`.

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

## Vault operations

Five operations are defined. The phone is the authoritative store: it holds the
ciphertext, and the desktop never sees an item's secret until it asks for that
one item and the user approves it.

| Operation | Direction | Purpose |
|---|---|---|
| `vault.list` | desktop → phone | One page of item metadata; no secret crosses |
| `vault.fetch` | desktop → phone | Release exactly one item's secret |
| `vault.create` | desktop → phone | Store a new item |
| `vault.update` | desktop → phone | Replace an item, naming the revision replaced |
| `vault.delete` | desktop → phone | Remove an item, naming the revision removed |

### Listing and reading are separate on purpose

A list is metadata the user already agreed to show on the desktop. A fetch is
one secret, released once, behind a biometric prompt. Collapsing them would mean
the desktop holding the whole vault in memory just to render a search box, which
is exactly what the phone-as-vault design exists to avoid.

This is a statement about the session, not about storage. `DEC-06` governs what
is encrypted **at rest on the phone** — names, sites, usernames and indexes all
are. Metadata travels in the clear only inside the already-encrypted channel.

### Optimistic revision

Every item carries a `revision`, starting at 1. `vault.update` and
`vault.delete` must name the revision they believe they are replacing; a phone
holding a different one refuses, and the desktop re-reads instead of overwriting
an edit it never saw. Revision `0` is refused everywhere: it means a caller
built the request without reading the item first, which is the overwrite this
rule exists to stop.

Two computers paired to one phone is not hypothetical, and a last-writer-wins
vault eats a password change in silence.

### Payloads

Every payload is a CBOR array whose element 0 is the schema, currently `1`.

| Operation | Request elements | Response elements |
|---|---|---|
| `vault.list` | schema, verifier name, cursor | schema, item array, next cursor |
| `vault.fetch` | schema, verifier name, item id | schema, item id, revision, secret |
| `vault.create` | schema, verifier name, kind, name, username, uri, secret | schema, item id, revision |
| `vault.update` | schema, verifier name, item id, expected revision, kind, name, username, uri, secret | schema, item id, revision |
| `vault.delete` | schema, verifier name, item id, expected revision | schema, item id |

An item summary is a nested seven-element array: id, revision, kind, name,
username, uri, updated-at. `kind` is `0` for a login and `1` for a secure note;
per `DEC-05`, cards, identities and attachments stay out until the threat model
is revisited, so adding a kind is a schema change on both sides rather than a
new free-text field.

`username` and `uri` may be empty — a note has neither, and plenty of logins
have no URL worth recording. `name` and `secret` may not: an empty secret would
put an empty clipboard in front of the user and look like a successful copy.

`vault.update` carries the whole item rather than a patch. A patch would need
the desktop to hold the previous secret in order to know what it is *not*
changing, and the point of the design is that it holds no secret between
operations.

### Limits

| Field | Bound |
|---|---|
| item id | 64 units |
| name, username | 255 units |
| uri | 1024 units |
| cursor | 128 units |
| secret | 4096 units |
| items per page | 32 |

A page is additionally bounded by the 6 KiB application payload limit, checked
after encoding. A page that does not fit is refused by the sender rather than
built and dropped by the session layer for being oversized. On the receiving
side the page's length prefix is checked *before* any allocation, because that
prefix arrives ahead of the items and trusting it would be the whole denial of
service.

### What crosses the link

One secret, for one item, per approved `vault.fetch` — plus the secret being
stored on a `create` or `update`. Nothing else. The carriers wipe on drop, and
none of them implement `Debug`/`toString`.

That wipe is a limited promise: enough that freed memory is not still a
password, and deliberately not a claim about pages, cores or optimisers. Keeping
a fetched secret out of the swap file is the agent's job (`VLT-06`), and keeping
it out of the Windows clipboard history is `VLT-07`.

The shared vector is pinned in
`desktop/crates/phone-auth-protocol/src/vault.rs` and
`mobile/test/vault_payloads_test.dart`.
