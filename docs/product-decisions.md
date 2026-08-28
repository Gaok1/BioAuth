# Product and security decisions

Adopted for the first production sequence on 2026-08-27. Reversing one of
these decisions requires updating the implementation tracker and the affected
threat model before code changes.

## First-release platform matrix

The first supported matrix is:

- Android 14 or newer;
- Windows 11 x64;
- Linux x64 on a desktop distribution that can run the packaged AppImage or
  Debian package; and
- current stable Chrome, Edge, and Firefox on the supported desktop systems.

iOS, macOS, Safari, Windows 10, ARM64 desktop, and other Android versions are
explicitly unsupported in the first release. Builds may happen to run there,
but the project does not claim security or recovery validation for them.

## Vault trust boundary

The phone is the authoritative encrypted vault. A copy or reveal operation may
deliver plaintext to the native desktop agent for the requested operation.
Browser autofill necessarily delivers the selected username/password to the
browser and page origin after an explicit user gesture and phone approval.

Electron must never receive passwords, TOTP seeds, vault keys, or plaintext
file contents. The promise that plaintext never reaches the PC applies only to
operations completed entirely on the phone, not desktop copy or autofill.

## Recovery

Vault, passkeys where export is technically possible, and File Locker use both
of these recovery paths:

1. an encrypted export protected by a separately presented recovery key; and
2. enrollment of a second trusted phone.

The recovery key must not be stored beside the export. A recovery drill on a
fresh device is part of the release gate. Losing the only phone without either
recovery path is an explicit unrecoverable state, not a hidden fallback.

## File Locker topology

Ciphertext and its versioned header stay on the PC. Every locker receives a
fresh random data-encryption key (DEK). The header contains two independent
authenticated wrappers for that DEK:

- a phone wrapper, released only by a locker-specific Android Keystore key with
  strong biometric authentication for each use; and
- an offline wrapper protected by the recovery key.

The phone stores no large file and no locker plaintext. Locker, vault,
WebAuthn, LUKS, SSH, and ordinary authorization credentials are separate and
cannot unwrap one another.

## Personal-vault MVP

The MVP contains personal logins, secure notes, search, a password/passphrase
generator, encrypted export/restore, Bitwarden JSON and generic CSV import, and
user-initiated autofill.

Organizations, sharing, cards, identities, attachments, emergency access, and
automatic injection are outside the MVP. They require a new trust model and do
not block the personal vault.

## Metadata confidentiality

Item names, sites, URLs, usernames, custom-field names, note titles, file names,
paths, timestamps that reveal user activity, and search indexes are secret by
default and remain inside authenticated ciphertext.

Only the minimum needed to recognize and safely parse a container may be clear:
magic, format version, algorithm and KDF identifiers, bounded lengths,
salt/nonces, chunk layout, and opaque random IDs. Any additional clear metadata
requires a documented leak analysis and format-version change.

