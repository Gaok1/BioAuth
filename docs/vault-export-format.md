# Vault export format

The file a phone writes so its vault can outlive it.

Everything else about the vault is bound to one device on purpose: the Keystore
key cannot leave, so losing the phone loses what it protects. That is the right
default and a terrible only option. This is the way out — one encrypted file,
one code, and a restore that adds rather than replaces.

`DEC-03` asks for both halves of recovery: an encrypted export whose key lives
somewhere else, and a second trusted phone. This is the first half.

## Construction

Deliberately the locker's, primitive for primitive. Two recovery stories in one
project would be two things to get right.

```
exportKey  = 32 random bytes from the system CSPRNG, rendered as a code
fileKey    = HKDF-SHA256(ikm = exportKey, salt = salt, info = "bioauth-vault-export-v1")
ciphertext = ChaCha20-Poly1305(fileKey, nonce, items, aad = header)
```

There is no passphrase and therefore no password KDF. A key the user cannot
choose cannot be guessed; offering a passphrase would let someone protect a
whole vault with something worth less than one entry in it.

## Layout

```
file   = CBOR array(2) [ header: bytes, sealed: bytes ]
header = CBOR array(5) [ schema=1, salt(16), nonce(12), createdAtMs, itemCount ]
sealed = ciphertext || Poly1305 tag(16)
items  = CBOR array(n) of array(5) [ kind, name, username, uri, secret ]
```

`schema` is `1`. A file from a later version is refused by name rather than by
failing to decrypt, so the message can say what happened.

### Why the count is outside the ciphertext

A restore screen has to say *what it is about to do* before the user types a
code — how many items, from when. Both fields are covered by the AEAD's
associated data, so a file that claims three items and holds three hundred
fails to open rather than surprising anyone. Readable without the key,
unforgeable without it.

### What is not in the file

Ids and revisions. They belonged to the vault the backup came from; a restore
mints its own, because reusing an id would collide with an unrelated item on a
phone that has been in use since.

## The code

`BAV1-` followed by the key in RFC 4648 base32, uppercase, unpadded, in groups
of four. The alphabet has no `0`, `1`, `8` or `9`, so a digit typed in place of
a letter is rejected rather than silently accepted. Parsing ignores case,
dashes, underscores and whitespace.

There is no checksum: a wrong code fails on the Poly1305 tag, which is the
check that cannot be fooled.

The prefix differs from the locker's `BAL1` so the two are not interchangeable.
A user who hands over the wrong one should be told so, not left to work it out
from a decryption failure.

## Export and restore on the phone

Both are one biometric prompt. The vault is a single blob under a key that
demands authentication per use, so reading it item by item would be one prompt
per item — a backup nobody finishes. The native store gained an `export` that
returns every item from the single decryption `list` already performs, and a
`restore` that writes the merged vault once.

**A restore adds; it never replaces.** One wrong file — the wrong backup, the
right backup from a year ago — must not cost the user everything stored since.
Items the vault already holds are counted and skipped, so restoring the same
file twice is harmless. Sameness is `(kind, name, username, uri)`; the secret
is not part of it, because two rows for one login with different passwords are
one account whose password changed.

## Limits

| Limit | Value |
|---|---|
| Items in one export | 4096 |
| Poly1305 tag | 16 bytes |
| Salt | 16 bytes |
| Nonce | 12 bytes |

## What this does not survive

Losing both the file and the code. That is the intended failure mode and the
reason the screen that shows the code says to keep the two apart: together they
are the vault in the clear, and a code stored next to the file it opens is not
a key, it is a filename.
