//! The way back into a container without the phone.
//!
//! A recovery code is the whole point of `DEC-03`: losing a phone must not be
//! the same event as losing the files. Unwrapping with it touches nothing but
//! the container itself — no agent, no network, no second file — because the
//! moment recovery depends on infrastructure, it depends on infrastructure
//! being available on the worst day of the year.

use zeroize::Zeroizing;

use crate::format::{wrapper_aad, Wrapper, WrapperKind, NONCE_LEN, RECOVERY_INFO, SALT_LEN};
use crate::secret::{derive, Dek, KEY_LEN};
use crate::stream::{open_key, seal_key};
use crate::{LockerError, Result};

/// RFC 4648 base32. No `0`, `1`, `8` or `9`, so a digit typed in place of a
/// letter is rejected instead of quietly decoding to something else.
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Marks the code's version, so a future scheme is distinguishable on sight
/// rather than by failing to decrypt.
const PREFIX: &str = "BAL1";

const GROUP: usize = 4;

/// The secret behind a recovery code. Wiped on drop, never rendered.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryKey(Zeroizing<[u8; KEY_LEN]>);

impl RecoveryKey {
    pub fn random() -> Self {
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        getrandom::getrandom(bytes.as_mut()).expect("operating system CSPRNG is unavailable");
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

/// Renders a recovery key as the code the user writes down.
pub fn format_recovery_code(key: &RecoveryKey) -> String {
    let mut code = String::from(PREFIX);
    let mut accumulator: u32 = 0;
    let mut bits = 0u32;
    let mut written = 0usize;

    for byte in key.0.iter() {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            push(&mut code, &mut written, (accumulator >> bits) as usize & 31);
        }
    }
    if bits > 0 {
        push(
            &mut code,
            &mut written,
            (accumulator << (5 - bits)) as usize & 31,
        );
    }
    code
}

fn push(code: &mut String, written: &mut usize, index: usize) {
    if *written % GROUP == 0 {
        code.push('-');
    }
    code.push(ALPHABET[index] as char);
    *written += 1;
}

/// Parses a code the user typed. Case, dashes and whitespace are ignored; a
/// character outside the alphabet is not.
pub fn parse_recovery_code(code: &str) -> Result<RecoveryKey> {
    let cleaned: String = code
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '_')
        .collect::<String>()
        .to_ascii_uppercase();
    let body = cleaned
        .strip_prefix(PREFIX)
        .ok_or(LockerError::BadRecoveryCode)?;

    // 32 bytes is 256 bits, which is 52 base32 characters with four bits of
    // padding in the last one.
    if body.len() != 52 {
        return Err(LockerError::BadRecoveryCode);
    }

    let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
    let mut accumulator: u32 = 0;
    let mut bits = 0u32;
    let mut index = 0usize;
    for character in body.bytes() {
        let value = ALPHABET
            .iter()
            .position(|candidate| *candidate == character)
            .ok_or(LockerError::BadRecoveryCode)?;
        accumulator = (accumulator << 5) | value as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes[index] = (accumulator >> bits) as u8;
            index += 1;
        }
    }
    // The trailing bits are padding. A code that puts anything there is not a
    // code this build produced, and accepting it would make two spellings of
    // one key.
    if index != KEY_LEN || accumulator & ((1 << bits) - 1) != 0 {
        return Err(LockerError::BadRecoveryCode);
    }
    Ok(RecoveryKey(bytes))
}

/// Builds the offline wrapper for a container and returns the code's key.
///
/// The caller shows the code once and never stores it: a recovery code the
/// computer keeps is not a recovery code, it is a second copy of the key next
/// to the lock.
pub(crate) fn wrap(dek: &Dek, binding: &[u8; 32]) -> (Wrapper, RecoveryKey) {
    let key = RecoveryKey::random();
    (wrap_with(dek, binding, &key), key)
}

pub(crate) fn wrap_with(dek: &Dek, binding: &[u8; 32], key: &RecoveryKey) -> Wrapper {
    let mut random = [0u8; SALT_LEN + NONCE_LEN];
    getrandom::getrandom(&mut random).expect("operating system CSPRNG is unavailable");
    let (salt, nonce) = random.split_at(SALT_LEN);
    let wrapping = derive(key.0.as_ref(), salt, RECOVERY_INFO);
    let ciphertext = seal_key(
        &wrapping,
        nonce.try_into().expect("nonce length"),
        &wrapper_aad(binding, WrapperKind::Recovery, ""),
        dek,
    );
    Wrapper {
        kind: WrapperKind::Recovery,
        id: String::new(),
        salt: salt.to_vec(),
        nonce: nonce.to_vec(),
        ciphertext,
    }
}

pub(crate) fn unwrap(wrapper: &Wrapper, key: &RecoveryKey, binding: &[u8; 32]) -> Result<Dek> {
    if wrapper.kind != WrapperKind::Recovery {
        return Err(LockerError::NoWrapper(WrapperKind::Recovery));
    }
    let wrapping = derive(key.0.as_ref(), &wrapper.salt, RECOVERY_INFO);
    let nonce: &[u8; NONCE_LEN] = wrapper
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| LockerError::Malformed("recovery nonce"))?;
    open_key(
        &wrapping,
        nonce,
        &wrapper_aad(binding, WrapperKind::Recovery, &wrapper.id),
        &wrapper.ciphertext,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_round_trips_through_what_a_human_types() {
        let key = RecoveryKey::random();
        let code = format_recovery_code(&key);
        assert!(code.starts_with("BAL1-"), "{code}");
        assert_eq!(
            code.len(),
            4 + 13 * 5,
            "prefix plus thirteen groups of four"
        );
        assert!(parse_recovery_code(&code).expect("parse") == key);

        // Lower case, extra spacing and missing dashes are transcription, not
        // a different code.
        let mangled = code.to_lowercase().replace('-', " ");
        assert!(parse_recovery_code(&mangled).expect("parse") == key);
    }

    #[test]
    fn a_code_that_is_not_one_is_refused() {
        let code = format_recovery_code(&RecoveryKey::random());
        for bad in [
            String::new(),
            "BAL1".into(),
            code[..code.len() - 1].to_owned(),
            format!("{code}A"),
            code.replacen("BAL1", "BAL2", 1),
            // `0` and `1` are not in the alphabet, so a mistyped O or I fails.
            code.replacen(|c: char| c.is_ascii_alphabetic(), "0", 1),
        ] {
            assert!(parse_recovery_code(&bad).is_err(), "`{bad}` must not parse");
        }
    }

    #[test]
    fn padding_bits_must_be_zero_so_one_key_has_one_code() {
        let key = RecoveryKey::from_bytes([0xFF; KEY_LEN]);
        let code = format_recovery_code(&key);
        let last = code.chars().last().expect("a last character");
        let index = ALPHABET
            .iter()
            .position(|c| *c as char == last)
            .expect("in alphabet");
        // Flipping a padding bit gives a second spelling of the same 32 bytes.
        let alternative = ALPHABET[index | 1] as char;
        if alternative != last {
            let mutated = format!("{}{alternative}", &code[..code.len() - 1]);
            assert!(parse_recovery_code(&mutated).is_err());
        }
    }

    #[test]
    fn recovery_survives_the_container_but_not_the_wrong_code() {
        let dek = Dek::random();
        let binding = [5u8; 32];
        let (wrapper, key) = wrap(&dek, &binding);

        assert!(unwrap(&wrapper, &key, &binding).expect("unwrap") == dek);
        assert!(unwrap(&wrapper, &RecoveryKey::random(), &binding).is_err());
        assert!(unwrap(&wrapper, &key, &[6u8; 32]).is_err());
    }

    #[test]
    fn two_wrappers_of_one_key_do_not_repeat_a_salt_or_a_nonce() {
        let dek = Dek::random();
        let key = RecoveryKey::random();
        let first = wrap_with(&dek, &[0; 32], &key);
        let second = wrap_with(&dek, &[0; 32], &key);
        assert_ne!(first.salt, second.salt);
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
    }
}
