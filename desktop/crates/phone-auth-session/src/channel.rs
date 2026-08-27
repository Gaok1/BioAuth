//! The record layer: ChaCha20-Poly1305 over an established handshake.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

use crate::keys::{KeySchedule, KEY_LEN};
use crate::SessionError;

/// Largest cleartext frame a record may carry, matching the protocol's frame
/// ceiling.
pub const MAX_FRAME: usize = 8192;

/// Bytes a record adds on top of its cleartext: an 8-byte counter and the
/// Poly1305 tag.
const RECORD_OVERHEAD: usize = 8 + 16;

/// Which end of the handshake a channel belongs to.
///
/// The two ends use opposite keys for opposite directions. Selecting them from
/// this rather than by slicing the schedule by hand is what stops one side
/// from being built with the other's keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The verifier: the desktop that published the bootstrap.
    Server,
    /// The authenticator: the phone that scanned it.
    Client,
}

pub struct SecureChannel {
    send: ChaCha20Poly1305,
    receive: ChaCha20Poly1305,
    binding: [u8; KEY_LEN],
    send_counter: u64,
    receive_counter: u64,
}

impl SecureChannel {
    pub(crate) fn new(role: Role, schedule: &KeySchedule, binding: [u8; KEY_LEN]) -> Self {
        let (send, receive) = match role {
            Role::Server => (schedule.server_to_client, schedule.client_to_server),
            Role::Client => (schedule.client_to_server, schedule.server_to_client),
        };
        Self {
            send: ChaCha20Poly1305::new((&send).into()),
            receive: ChaCha20Poly1305::new((&receive).into()),
            binding,
            send_counter: 0,
            receive_counter: 0,
        }
    }

    /// The session binding to put inside the signed authorization request.
    pub fn session_binding(&self) -> [u8; KEY_LEN] {
        self.binding
    }

    /// Encrypts one frame.
    ///
    /// The binding is authenticated as associated data, so a record cannot be
    /// lifted into a different session even by someone holding its keys.
    pub fn seal(&mut self, cleartext: &[u8]) -> Result<Vec<u8>, SessionError> {
        if cleartext.is_empty() || cleartext.len() > MAX_FRAME {
            return Err(SessionError::InvalidFrame("invalid cleartext frame size"));
        }
        let counter = self.send_counter;
        let cipher = self
            .send
            .encrypt(
                &Nonce::from(nonce(counter)),
                Payload {
                    msg: cleartext,
                    aad: &self.binding,
                },
            )
            .map_err(|_| SessionError::Encrypt)?;

        // Refuse to wrap rather than reuse a nonce. At one record per
        // authorization this is unreachable; a bug that reset the counter is
        // not, and reuse would leak the keystream.
        self.send_counter = self
            .send_counter
            .checked_add(1)
            .ok_or(SessionError::CounterExhausted)?;

        let mut record = Vec::with_capacity(8 + cipher.len());
        record.extend_from_slice(&counter.to_be_bytes());
        record.extend_from_slice(&cipher);
        Ok(record)
    }

    /// Decrypts one frame.
    ///
    /// Records must arrive in order. The transports this runs over are
    /// reliable and ordered, so a gap means loss or tampering, not reordering,
    /// and accepting a window would only widen what an attacker can replay.
    pub fn open(&mut self, record: &[u8]) -> Result<Vec<u8>, SessionError> {
        if record.len() <= RECORD_OVERHEAD || record.len() > MAX_FRAME + RECORD_OVERHEAD {
            return Err(SessionError::InvalidFrame("invalid encrypted record size"));
        }
        let counter = u64::from_be_bytes(
            record[..8]
                .try_into()
                .map_err(|_| SessionError::InvalidFrame("truncated record"))?,
        );
        if counter != self.receive_counter {
            return Err(SessionError::Replay);
        }
        let clear = self
            .receive
            .decrypt(
                &Nonce::from(nonce(counter)),
                Payload {
                    msg: &record[8..],
                    aad: &self.binding,
                },
            )
            .map_err(|_| SessionError::Decrypt)?;

        self.receive_counter = self
            .receive_counter
            .checked_add(1)
            .ok_or(SessionError::CounterExhausted)?;
        Ok(clear)
    }
}

/// Builds a 96-bit nonce from the record counter.
///
/// Each direction has its own key and its own counter starting at zero, so a
/// counter is never reused under one key.
fn nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A connected pair, as a completed handshake would produce.
    fn pair() -> (SecureChannel, SecureChannel) {
        let schedule = KeySchedule::derive(&[5; 32], &[6; 32]).expect("derive");
        let binding = [0xab; KEY_LEN];
        (
            SecureChannel::new(Role::Server, &schedule, binding),
            SecureChannel::new(Role::Client, &schedule, binding),
        )
    }

    #[test]
    fn a_pair_talks_in_both_directions() {
        let (mut server, mut client) = pair();

        let record = server.seal(b"request").expect("seal");
        assert_eq!(client.open(&record).expect("open"), b"request");

        let record = client.seal(b"response").expect("seal");
        assert_eq!(server.open(&record).expect("open"), b"response");
    }

    #[test]
    fn the_two_ends_agree_on_the_binding() {
        let (server, client) = pair();
        assert_eq!(server.session_binding(), client.session_binding());
    }

    #[test]
    fn a_record_is_opaque_on_the_wire() {
        let (mut server, _) = pair();
        let record = server.seal(b"nixos-rebuild switch").expect("seal");
        assert!(
            !record
                .windows(20)
                .any(|window| window == b"nixos-rebuild switch"),
            "cleartext must not survive into the record"
        );
    }

    #[test]
    fn tampering_with_any_byte_is_rejected() {
        // Every byte, not a spot check: the counter prefix, the ciphertext and
        // the tag each have to be covered, and it is easy to authenticate only
        // part of a record by accident.
        let (mut server, mut client) = pair();
        let record = server.seal(b"request").expect("seal");

        for index in 0..record.len() {
            for bit in 0..8 {
                let mut mutated = record.clone();
                mutated[index] ^= 1 << bit;

                let (_, mut fresh_client) = pair();
                assert!(
                    fresh_client.open(&mutated).is_err(),
                    "byte {index} bit {bit} was accepted after tampering"
                );
            }
        }
        // The untouched record still opens, so the loop above was not merely
        // rejecting everything.
        assert_eq!(client.open(&record).expect("open"), b"request");
    }

    #[test]
    fn a_replayed_record_is_rejected() {
        let (mut server, mut client) = pair();
        let first = server.seal(b"first").expect("seal");
        let second = server.seal(b"second").expect("seal");

        assert_eq!(client.open(&first).expect("open"), b"first");
        assert_eq!(client.open(&second).expect("open"), b"second");

        assert!(
            matches!(client.open(&first), Err(SessionError::Replay)),
            "a record already accepted must not be accepted again"
        );
        assert!(
            matches!(client.open(&second), Err(SessionError::Replay)),
            "the most recent record must not be accepted twice either"
        );
    }

    #[test]
    fn records_must_arrive_in_order() {
        let (mut server, mut client) = pair();
        let first = server.seal(b"first").expect("seal");
        let second = server.seal(b"second").expect("seal");

        assert!(
            matches!(client.open(&second), Err(SessionError::Replay)),
            "skipping a record must be refused"
        );
        // The stream is still usable from where it actually is.
        assert_eq!(client.open(&first).expect("open"), b"first");
        assert_eq!(client.open(&second).expect("open"), b"second");
    }

    #[test]
    fn a_record_from_another_session_is_rejected() {
        let (mut server, _) = pair();

        let other_schedule = KeySchedule::derive(&[7; 32], &[8; 32]).expect("derive");
        let mut stranger = SecureChannel::new(Role::Client, &other_schedule, [0xab; KEY_LEN]);

        let record = server.seal(b"request").expect("seal");
        assert!(matches!(
            stranger.open(&record),
            Err(SessionError::Decrypt)
        ));
    }

    #[test]
    fn a_record_replayed_into_a_different_binding_is_rejected() {
        // Same keys, different binding: the binding is the associated data, so
        // it must break authentication on its own.
        let schedule = KeySchedule::derive(&[5; 32], &[6; 32]).expect("derive");
        let mut server = SecureChannel::new(Role::Server, &schedule, [0xab; KEY_LEN]);
        let mut client = SecureChannel::new(Role::Client, &schedule, [0xcd; KEY_LEN]);

        let record = server.seal(b"request").expect("seal");
        assert!(matches!(client.open(&record), Err(SessionError::Decrypt)));
    }

    #[test]
    fn a_channel_cannot_open_what_it_sealed() {
        // Directions use different keys. This also documents why the previous
        // tamper test proved nothing: it sealed and opened on one channel, so
        // it failed on the key mismatch before the tampering mattered.
        let (mut server, _) = pair();
        let record = server.seal(b"request").expect("seal");
        assert!(matches!(server.open(&record), Err(SessionError::Decrypt)));
    }

    #[test]
    fn empty_and_oversized_frames_are_refused() {
        let (mut server, _) = pair();
        assert!(matches!(
            server.seal(&[]),
            Err(SessionError::InvalidFrame(_))
        ));
        assert!(matches!(
            server.seal(&vec![0u8; MAX_FRAME + 1]),
            Err(SessionError::InvalidFrame(_))
        ));
        assert!(server.seal(&vec![0u8; MAX_FRAME]).is_ok());
    }

    #[test]
    fn undersized_records_are_refused_before_decryption() {
        let (_, mut client) = pair();
        for len in 0..=RECORD_OVERHEAD {
            assert!(
                matches!(client.open(&vec![0u8; len]), Err(SessionError::InvalidFrame(_))),
                "a {len}-byte record must be refused on size"
            );
        }
    }

    #[test]
    fn nonces_are_unique_per_counter() {
        let first = nonce(0);
        let second = nonce(1);
        assert_ne!(first, second);
        assert_eq!(first.len(), 12);
        assert_ne!(nonce(u64::MAX), nonce(0));
    }
}
