//! Chunked authenticated encryption.
//!
//! One key, one nonce prefix, a counter per chunk and a flag on the last one.
//! That combination is what makes reordering, duplication, truncation and
//! cross-container splicing all fail on a tag rather than produce a shorter,
//! plausible file.

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;

use crate::format::{CoreHeader, CONTENT_INFO, METADATA_INFO};
use crate::secret::{derive, Dek, KEY_LEN};
use crate::{LockerError, Result};

/// The keys derived from one container's data key.
pub(crate) struct ContainerCipher {
    content: ChaCha20Poly1305,
    metadata: ChaCha20Poly1305,
    header: CoreHeader,
    binding: [u8; 32],
}

impl ContainerCipher {
    pub(crate) fn new(dek: &Dek, header: &CoreHeader, binding: [u8; 32]) -> Self {
        let content = derive(dek.expose(), &header.content_salt, CONTENT_INFO);
        let metadata = derive(dek.expose(), &header.content_salt, METADATA_INFO);
        Self {
            content: cipher(&content),
            metadata: cipher(&metadata),
            header: header.clone(),
            binding,
        }
    }

    /// Encrypts one chunk in place, appending its tag.
    pub(crate) fn seal_chunk(&self, index: u64, last: bool, buffer: &mut Vec<u8>) {
        self.content
            .encrypt_in_place(
                &self.header.chunk_nonce(index, last).into(),
                &self.binding,
                buffer,
            )
            .expect("chunk plaintext is bounded by the chunk size");
    }

    /// Decrypts one chunk in place. Failure is always [`LockerError::Corrupt`]:
    /// which byte was wrong is not something a caller should be told.
    pub(crate) fn open_chunk(&self, index: u64, last: bool, buffer: &mut Vec<u8>) -> Result<()> {
        self.content
            .decrypt_in_place(
                &self.header.chunk_nonce(index, last).into(),
                &self.binding,
                buffer,
            )
            .map_err(|_| LockerError::Corrupt)
    }

    pub(crate) fn seal_metadata(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut buffer = plaintext.to_vec();
        self.metadata
            .encrypt_in_place(
                &self.header.metadata_nonce().into(),
                &self.binding,
                &mut buffer,
            )
            .expect("metadata is bounded by its own limit");
        buffer
    }

    pub(crate) fn open_metadata(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut buffer = ciphertext.to_vec();
        self.metadata
            .decrypt_in_place(
                &self.header.metadata_nonce().into(),
                &self.binding,
                &mut buffer,
            )
            .map_err(|_| LockerError::Corrupt)?;
        Ok(buffer)
    }
}

/// Wraps a data key under a key-wrapping key, bound to one wrapper of one
/// container by `aad`.
pub(crate) fn seal_key(
    wrapping_key: &[u8; KEY_LEN],
    nonce: &[u8; 12],
    aad: &[u8; 32],
    dek: &Dek,
) -> Vec<u8> {
    let mut buffer = dek.expose().to_vec();
    cipher(wrapping_key)
        .encrypt_in_place(nonce.into(), aad, &mut buffer)
        .expect("a 32 byte key is well within the AEAD limit");
    buffer
}

pub(crate) fn open_key(
    wrapping_key: &[u8; KEY_LEN],
    nonce: &[u8; 12],
    aad: &[u8; 32],
    ciphertext: &[u8],
) -> Result<Dek> {
    let mut buffer = ciphertext.to_vec();
    cipher(wrapping_key)
        .decrypt_in_place(nonce.into(), aad, &mut buffer)
        .map_err(|_| LockerError::Corrupt)?;
    let dek = Dek::from_slice(&buffer).ok_or(LockerError::Corrupt);
    buffer.iter_mut().for_each(|byte| *byte = 0);
    dek
}

fn cipher(key: &[u8; KEY_LEN]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(key.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::TAG_LEN;

    fn fixture() -> (Dek, CoreHeader, ContainerCipher) {
        let dek = Dek::random();
        let header = CoreHeader::fresh(1234);
        let binding = crate::format::binding_of(&header.encode());
        let cipher = ContainerCipher::new(&dek, &header, binding);
        (dek, header, cipher)
    }

    #[test]
    fn a_chunk_round_trips_and_grows_by_exactly_one_tag() {
        let (_, _, cipher) = fixture();
        let plaintext = b"the quick brown fox".to_vec();
        let mut buffer = plaintext.clone();
        cipher.seal_chunk(0, true, &mut buffer);
        assert_eq!(buffer.len(), plaintext.len() + TAG_LEN);
        cipher.open_chunk(0, true, &mut buffer).expect("open");
        assert_eq!(buffer, plaintext);
    }

    #[test]
    fn a_chunk_will_not_open_at_another_index_or_as_another_last() {
        let (_, _, cipher) = fixture();
        let mut sealed = b"payload".to_vec();
        cipher.seal_chunk(4, false, &mut sealed);

        for (index, last) in [(5, false), (3, false), (4, true)] {
            let mut moved = sealed.clone();
            assert!(
                matches!(
                    cipher.open_chunk(index, last, &mut moved),
                    Err(LockerError::Corrupt)
                ),
                "chunk 4 must not open as ({index}, {last})"
            );
        }
    }

    #[test]
    fn a_chunk_will_not_open_in_another_container() {
        let (dek, header, cipher) = fixture();
        let mut sealed = b"payload".to_vec();
        cipher.seal_chunk(0, true, &mut sealed);

        // Same key, same header, different container: only the binding differs.
        let elsewhere = ContainerCipher::new(&dek, &header, [0xAA; 32]);
        assert!(matches!(
            elsewhere.open_chunk(0, true, &mut sealed.clone()),
            Err(LockerError::Corrupt)
        ));

        // And a different key on the same container.
        let stranger = ContainerCipher::new(&Dek::random(), &header, cipher.binding);
        assert!(matches!(
            stranger.open_chunk(0, true, &mut sealed),
            Err(LockerError::Corrupt)
        ));
    }

    #[test]
    fn metadata_and_chunks_do_not_share_a_key() {
        let (_, _, cipher) = fixture();
        let sealed = cipher.seal_metadata(b"metadata");
        assert!(cipher
            .open_chunk(crate::format::MAX_CHUNK_INDEX, false, &mut sealed.clone())
            .is_err());
        assert_eq!(cipher.open_metadata(&sealed).expect("open"), b"metadata");
    }

    #[test]
    fn a_wrapped_key_is_bound_to_its_container() {
        let dek = Dek::random();
        let wrapping = [7u8; KEY_LEN];
        let nonce = [3u8; 12];
        let binding = [1u8; 32];
        let sealed = seal_key(&wrapping, &nonce, &binding, &dek);

        assert!(open_key(&wrapping, &nonce, &binding, &sealed).expect("open") == dek);
        assert!(open_key(&wrapping, &nonce, &[2u8; 32], &sealed).is_err());
        assert!(open_key(&[8u8; KEY_LEN], &nonce, &binding, &sealed).is_err());
    }
}
