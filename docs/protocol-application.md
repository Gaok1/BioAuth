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

