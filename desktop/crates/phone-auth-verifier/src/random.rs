//! Randomness for challenges and request identifiers.
//!
//! Everything here comes from the OS CSPRNG. A predictable challenge would let
//! an attacker collect a signature in advance for a request the verifier has
//! not issued yet, which is the whole reason the challenge exists.

use crate::encoding::to_hex;

/// Fills a buffer from the operating system's CSPRNG.
///
/// Panics if the OS cannot provide randomness. There is no safe degraded mode:
/// continuing with weak randomness would silently void the freshness guarantee
/// the protocol depends on, so failing loudly is the correct behaviour.
pub fn fill(buffer: &mut [u8]) {
    getrandom::getrandom(buffer).expect("operating system CSPRNG is unavailable");
}

pub fn bytes<const N: usize>() -> [u8; N] {
    let mut buffer = [0u8; N];
    fill(&mut buffer);
    buffer
}

/// A fresh request identifier: 128 random bits, hex encoded.
///
/// Random rather than sequential so that a request id discloses nothing about
/// how many authorizations this machine has performed, and so two verifiers
/// sharing a phone cannot collide.
pub fn request_id() -> String {
    to_hex(&bytes::<16>())
}

/// A fresh session identifier for transport bootstraps.
pub fn session_id() -> String {
    to_hex(&bytes::<12>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn request_ids_are_unique_and_bounded() {
        let ids: HashSet<String> = (0..1_000).map(|_| request_id()).collect();
        assert_eq!(ids.len(), 1_000, "request ids must not repeat");

        let id = request_id();
        assert_eq!(id.len(), 32);
        assert!(id.len() <= 64, "must fit the protocol's requestId bound");
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn challenges_differ_between_calls() {
        assert_ne!(bytes::<32>(), bytes::<32>());
    }

    #[test]
    fn output_is_not_trivially_constant() {
        // A stub RNG returning zeroes is a realistic porting mistake.
        assert_ne!(bytes::<32>(), [0u8; 32]);
    }
}
