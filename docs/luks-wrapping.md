# LUKS credential and wrapping protocol

Status: version 1 implemented. `phone-auth luks enroll` creates the keyslot
and the NixOS module installs the initrd unit; what is untested is a real boot
(`LUK-06`).

PhoneAuth never derives a disk key from ECDSA, a biometric result, or a
signature. Setup generates a fresh random **32-byte LUKS credential**. The
phone protects it with a dedicated Android Keystore AES-256-GCM key and boot
receives it only through the mutually authenticated encrypted session.

## Separate keys and credentials

Disk unlock uses both of these, for different jobs:

1. the purpose-specific ECDSA credential identifies the pairing and lets the
   verifier apply the hardware-backed `DiskUnlock` policy; and
2. `bioauth_luks_wrapping_v1` wraps the random LUKS credential.

The AES alias, AAD domain and application namespace are not shared with File
Locker, the vault, WebAuthn, SSH, authorization, or the session identity. The
AES key requires `BIOMETRIC_STRONG` for every use, has no grace period or
device-credential fallback, prefers StrongBox, and is invalidated by biometric
re-enrolment. A software-backed wrapping key is reported as software, so the
desktop refuses it for boot enrollment.

## Enrollment

Over a live session opened with the `DiskUnlock` credential, the desktop sends
`luks.enroll` with schema `1`, the displayed computer and volume names, a
random 32-byte volume binding, and the random 32-byte disk key. After the user
approves the biometric prompt, the phone returns the credential id and an
opaque wrapper. Retrying the same request id and payload reuses the result
without another wrapping operation; changed payloads fail closed.

The public initrd configuration stores the canonical CBOR array:

```text
[1, volumeBinding: bstr(32), credentialId: text(1..64), wrapper: bstr(1..512)]
```

It contains no plaintext disk key and no phone or desktop private key.

## Android wrapper

The opaque wrapper is:

```text
[version=1][ivLength][GCM IV][ciphertext || 128-bit GCM tag]
```

The authenticated additional data is:

```text
SHA-256("bioauth-luks-wrapper-v1" || volumeBinding || 0x00 || credentialId)
```

Editing the volume binding, credential id, ciphertext, IV, or tag therefore
causes the same generic refusal. The domain and alias are pinned as different
from File Locker in JVM tests.

## Boot unlock

`phone-auth-initrd` selects only a hardware-backed `DiskUnlock` credential,
loads the public wrapper, authenticates the paired phone, and sends
`luks.unlock`. The request repeats the displayed names, binding, credential id,
and wrapper. The phone checks that the session purpose and local credential
match, asks for one strong biometric, and returns the exact 32-byte disk key.

The initrd accepts only a response for the same request id, operation, session
binding and validity window. On success it writes exactly 32 bytes to stdout;
all diagnostics remain on stderr. Denial, malformed data, timeout, missing
phone, invalidated key, and unavailable networking write no key and fall back
to the mandatory offline recovery keyslot.

## Loss and deletion

Deleting or invalidating `bioauth_luks_wrapping_v1` permanently removes that
phone's ability to open every wrapper it owns. Replacement therefore uses the
offline recovery keyslot to boot, removes the obsolete PhoneAuth keyslot, and
enrolls a new random credential with the new phone. The setup tooling must
never remove or overwrite the last independently tested recovery keyslot.
