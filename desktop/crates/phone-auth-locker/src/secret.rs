//! The data key, and the small amount of care it needs.
//!
//! Memory is wiped on drop. It is not page-locked: on the platforms this
//! product targets, the realistic path from a key in RAM to an attacker is a
//! process that can already read that RAM, not a swap file, and locking pages
//! would buy a dependency on `libc`/`windows-sys` for a threat full-disk
//! encryption already covers.

use zeroize::Zeroizing;

/// Length of every key this crate handles: the data key, the derived content
/// and metadata keys, and the recovery key.
pub const KEY_LEN: usize = 32;

/// A data encryption key.
///
/// One per container, random, never reused, never written to disk in the
/// clear, and never rendered: there is no `Debug`, no `Display`, and no
/// `Serialize`, so it cannot reach a log through the usual accidents.
#[derive(Clone, PartialEq, Eq)]
pub struct Dek(Zeroizing<[u8; KEY_LEN]>);

impl Dek {
    /// A fresh key from the OS CSPRNG.
    ///
    /// Panics if the OS cannot provide randomness, matching the verifier's
    /// rule: a container encrypted under a predictable key is worse than no
    /// container at all, so there is no degraded mode.
    pub fn random() -> Self {
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        getrandom::getrandom(bytes.as_mut()).expect("operating system CSPRNG is unavailable");
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Fails rather than padding or truncating a wrong-sized key.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        Some(Self::from_bytes(bytes.try_into().ok()?))
    }

    /// The raw key. Every call site is a place a secret can escape, so there
    /// are deliberately few of them.
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// HKDF-SHA256 with this crate's fixed output length.
///
/// Separate `info` strings are what keep the content key, the metadata key and
/// a recovery wrapping key from ever being the same bytes, even though two of
/// them share an input key and a salt.
pub fn derive(ikm: &[u8], salt: &[u8], info: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
    let mut okm = Zeroizing::new([0u8; KEY_LEN]);
    hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), ikm)
        .expand(info, okm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_keys_are_not_the_same_key() {
        // `Dek` has no `Debug`, so these compare rather than assert equal.
        assert!(Dek::random() != Dek::random());
        assert!(Dek::random().expose() != &[0u8; KEY_LEN]);
    }

    #[test]
    fn a_wrong_length_key_is_refused_rather_than_padded() {
        assert!(Dek::from_slice(&[0u8; KEY_LEN]).is_some());
        assert!(Dek::from_slice(&[0u8; KEY_LEN - 1]).is_none());
        assert!(Dek::from_slice(&[0u8; KEY_LEN + 1]).is_none());
    }

    #[test]
    fn separate_info_strings_separate_the_keys() {
        let dek = Dek::random();
        let salt = [9u8; 32];
        let content = derive(dek.expose(), &salt, b"bioauth-locker-content-v1");
        let metadata = derive(dek.expose(), &salt, b"bioauth-locker-metadata-v1");
        assert_ne!(content.as_ref(), metadata.as_ref());
        assert_ne!(content.as_ref(), dek.expose());
    }
}
