# File Locker container format

Status: version 1, implemented in `desktop/crates/phone-auth-locker`.

A locker file holds one encrypted file. The phone authorizes unwrapping the
key; it does not hold the ciphertext, and it is never required to read a
container that was already unlocked with the offline recovery code.

Nothing in this format is a biometric-signature payload. The container is
written and read by the desktop; the phone only ever sees a data key and a
32-byte binding value.

## Layout

All integers on disk are big-endian. All CBOR is canonical: definite lengths,
shortest integer encodings, no trailing bytes, and a decoded structure must
re-encode to the exact input bytes.

```
offset  0  magic          8 bytes, "BIOALCK" followed by the container version
offset  8  core length    u32, at most 4096
offset 12  core           canonical CBOR, see below
           wrapper length u32, at most 8192
           wrappers       canonical CBOR
           metadata length u32, at most 4096
           metadata       AEAD ciphertext
           chunks         ceil(plaintextLength / chunkSize) authenticated chunks,
                          and exactly one chunk when the plaintext is empty
```

The magic's last byte is the container version, so a future version is
detectable from the first eight bytes without parsing anything.

### Core header

A six-element CBOR array. It carries no secret and no file name.

| Index | Field | Rule |
|---:|---|---|
| 0 | container version | `1`; unknown versions fail closed |
| 1 | cipher | `1` = ChaCha20-Poly1305 in the chunked construction below |
| 2 | chunk size | plaintext bytes per chunk; a power of two in `[4096, 1048576]`, written as 65536 |
| 3 | nonce prefix | exactly 7 random bytes, fresh per container |
| 4 | content salt | exactly 32 random bytes, fresh per container |
| 5 | plaintext length | length of the original file in bytes |

### Binding

```
binding = SHA-256("bioauth-locker-binding-v1" || magic || core)
```

The binding is the additional authenticated data for the metadata and for every
chunk. It is what stops a metadata block or a chunk from being lifted out of one
container and pasted into another: the core header of the container it came from
is covered by the tag.

A wrapper's additional data goes one step further, because the binding alone
would leave the wrapper's own kind and id unauthenticated — and the id is what
decides which credential the desktop goes and asks:

```
wrapperAad = SHA-256("bioauth-locker-wrapper-v1" || binding || kind || id)
```

The phone computes this itself from the binding it is sent and the credential id
it already holds, so no new field has to be trusted on the wire.

### Key derivation

The data encryption key (DEK) is 32 random bytes, generated per container and
never reused between containers, files, or products. Everything else is derived
from it:

```
contentKey  = HKDF-SHA256(ikm = DEK, salt = contentSalt, info = "bioauth-locker-content-v1")
metadataKey = HKDF-SHA256(ikm = DEK, salt = contentSalt, info = "bioauth-locker-metadata-v1")
```

The DEK itself never touches the disk in the clear and never leaves the agent
except inside the authenticated encrypted session with the phone.

### Chunks

Chunk `i` of the plaintext is encrypted with `contentKey` under a 12-byte nonce:

```
nonce = noncePrefix (7 bytes) || i as u32 || final
final = 1 for the last chunk, 0 otherwise
aad   = binding
```

Each chunk is `chunkSize` plaintext bytes, except the last, which may be
shorter and may be empty only when the plaintext is empty. On disk a chunk is
its ciphertext followed by the 16-byte Poly1305 tag.

The counter makes reordering and duplication detectable, and the final flag
makes truncation detectable: a truncated file either ends on a chunk whose
`final` byte is 0, or fails to reach the chunk count implied by the
authenticated plaintext length. Chunk index is bounded so the counter cannot
wrap, which caps a v1 container at 256 TiB.

Reading is driven by the authenticated plaintext length, so trailing bytes
after the last chunk are rejected rather than ignored.

### Metadata

Encrypted with `metadataKey`, nonce `noncePrefix || 0xFFFFFFFF || 0x02`, and
`aad = binding`. That nonce cannot collide with a chunk nonce: chunk counters
are bounded well below `0xFFFFFFFF` and the final byte is only ever 0 or 1.

The plaintext is a five-element CBOR array:

| Index | Field | Rule |
|---:|---|---|
| 0 | schema version | `1` |
| 1 | original name | file name only, never a path; at most 255 UTF-16 code units |
| 2 | mode | Unix permission bits, or `0` where the platform has none |
| 3 | modified at | UTC Unix time in milliseconds, or `0` when unknown |
| 4 | original length | must equal the core header's plaintext length |

The name is encrypted because a directory listing of locked files should not be
an index of what the user has. Only framing — sizes, chunk count, wrapper count
— is visible to someone holding the file.

### Wrappers

A CBOR array of at most eight entries. Each entry is a five-element array:

| Index | Field | Rule |
|---:|---|---|
| 0 | kind | `0` phone, `1` offline recovery |
| 1 | id | at most 64 UTF-16 code units; the credential id for a phone wrapper |
| 2 | salt | 32 bytes, or empty for a phone wrapper |
| 3 | nonce | 12 bytes, or empty for a phone wrapper |
| 4 | ciphertext | at most 512 bytes |

A **phone wrapper** is opaque to the desktop. The phone encrypts the DEK with
its own Keystore key, dedicated to the `FileLocker` credential purpose and
gated on a strong biometric per use, with `aad = wrapperAad`. The desktop
stores and forwards the blob and cannot open it. It must never be logged.

An **offline recovery wrapper** is:

```
recoveryKey = 32 random bytes, shown to the user once as a recovery code
wrappingKey = HKDF-SHA256(ikm = recoveryKey, salt = salt, info = "bioauth-locker-recovery-v1")
ciphertext  = ChaCha20-Poly1305(wrappingKey, nonce, DEK, aad = wrapperAad)
```

Unwrapping with the recovery code requires only the container and the code: no
agent, no phone, no network, and no other file. That is the whole point of it,
and it is why `locker unlock --recovery-code` is a separate path through the
same engine rather than a fallback inside the phone path.

Each wrapper authenticates itself, and only the wrapper an unlock actually uses
is on that unlock's path. Damaging the recovery wrapper is invisible to a phone
unlock and vice versa, which is what having two independent ways in means. What
holds unconditionally is the property the tests assert: no change anywhere in a
container can make it open and produce a *different* file. Removing a wrapper is
therefore a denial of service, not a forgery — a deleted recovery wrapper is
visible in `locker status`, and an appended one cannot produce a key its author
does not have.

### Recovery code

The recovery key is rendered as `BAL1-` followed by the key in RFC 4648 base32,
uppercase, unpadded, in groups of four characters. The alphabet has no `0`,
`1`, `8`, or `9`, so a digit typed in place of a letter is rejected rather than
silently accepted. Parsing ignores case, dashes, and whitespace. There is no
checksum: a wrong code fails on the AEAD tag, which is the check that matters.

## Limits

| Limit | Value |
|---|---|
| Core header | 4096 bytes |
| Wrapper section | 8192 bytes |
| Wrappers per container | 8 |
| Single wrapper ciphertext | 512 bytes |
| Metadata section | 4096 bytes |
| Original name | 255 UTF-16 code units |
| Chunk size | power of two in `[4096, 1048576]` |
| Chunk index | below `0xFFFFFFFF` |

Every one of these is checked before allocation, so a hostile header cannot
make the reader reserve memory proportional to a number it chose.

## Writing without losing the original

Locking and unlocking never write over an existing file:

1. create a temporary file in the destination directory, so the eventual rename
   stays inside one filesystem;
2. stream the whole transformation into it;
3. `fsync` the temporary file, then rename it onto the destination, then
   `fsync` the directory where the platform supports it;
4. verify the result by decrypting it end to end and checking every tag;
5. only then remove the input.

A crash, a full disk, or a kill at any step leaves either the original or a
complete replacement, never a half-written file under the name of either. The
temporary file is removed on failure.

Removal of the original is an ordinary delete. On a journalling filesystem or
an SSD the plaintext may remain recoverable from unreferenced blocks; the
locker does not claim to erase it, and full-disk encryption is the answer to
that threat rather than an overwrite pass this format cannot make reliable.

## What this format does not do

- It does not hide the size of a file, the number of files, or when they were
  locked. Padding is not part of version 1.
- It does not deduplicate, compress, or store more than one file per container.
- It does not make a locker readable on a phone. The phone authorizes; the
  desktop decrypts.
- It does not survive losing both the phone and the recovery code. That is the
  intended failure mode, and `DEC-03` is why the recovery code exists.
