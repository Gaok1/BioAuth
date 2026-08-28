//! The bytes on disk: header, wrappers, metadata and the binding that ties
//! them to one container.
//!
//! Every decode checks its limits before it allocates, and re-encodes what it
//! decoded to reject a second spelling of the same structure. Both rules exist
//! for the same reason as in `phone-auth-protocol`: a value that parses two
//! ways is a value two implementations can disagree about.

use phone_auth_protocol::cbor::{Reader, Writer};
use sha2::{Digest, Sha256};

use crate::{LockerError, Result};

/// First eight bytes of every container. The final byte is the version, so a
/// future format is recognisable without parsing anything.
pub(crate) const MAGIC_PREFIX: &[u8; 7] = b"BIOALCK";

pub const CONTAINER_VERSION: u8 = 1;

/// The only cipher version 1 defines: ChaCha20-Poly1305 over chunks.
pub(crate) const CIPHER_CHACHA20_POLY1305: u64 = 1;

/// Plaintext bytes per chunk when writing.
pub const CHUNK_SIZE: u32 = 64 * 1024;
pub(crate) const MIN_CHUNK_SIZE: u32 = 4 * 1024;
pub(crate) const MAX_CHUNK_SIZE: u32 = 1024 * 1024;

pub(crate) const TAG_LEN: usize = 16;
pub(crate) const NONCE_PREFIX_LEN: usize = 7;
pub(crate) const SALT_LEN: usize = 32;
pub(crate) const NONCE_LEN: usize = 12;

/// A chunk counter must stay below this, so the nonce cannot repeat.
pub(crate) const MAX_CHUNK_INDEX: u64 = u32::MAX as u64 - 1;

pub(crate) const MAX_CORE_BYTES: usize = 4096;
pub(crate) const MAX_WRAPPER_BYTES: usize = 8192;
pub(crate) const MAX_METADATA_BYTES: usize = 4096;
pub const MAX_WRAPPERS: usize = 8;
pub(crate) const MAX_WRAPPER_CIPHERTEXT: usize = 512;
pub(crate) const MAX_NAME_UNITS: usize = 255;
pub(crate) const MAX_ID_UNITS: usize = 64;

/// Extension given to a locked file.
pub const LOCKER_EXTENSION: &str = "balock";

const BINDING_DOMAIN: &[u8] = b"bioauth-locker-binding-v1";
const WRAPPER_DOMAIN: &[u8] = b"bioauth-locker-wrapper-v1";
pub(crate) const CONTENT_INFO: &[u8] = b"bioauth-locker-content-v1";
pub(crate) const METADATA_INFO: &[u8] = b"bioauth-locker-metadata-v1";
pub(crate) const RECOVERY_INFO: &[u8] = b"bioauth-locker-recovery-v1";

const CORE_FIELDS: u64 = 6;
const WRAPPER_FIELDS: u64 = 5;
const METADATA_FIELDS: u64 = 5;
const METADATA_SCHEMA: u64 = 1;

/// The public part of a container: no name, no key, no secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreHeader {
    pub container_version: u8,
    pub chunk_size: u32,
    pub nonce_prefix: [u8; NONCE_PREFIX_LEN],
    pub content_salt: [u8; SALT_LEN],
    pub plaintext_len: u64,
}

impl CoreHeader {
    /// A header for a new container, with fresh randomness.
    pub fn fresh(plaintext_len: u64) -> Self {
        let mut random = [0u8; NONCE_PREFIX_LEN + SALT_LEN];
        getrandom::getrandom(&mut random).expect("operating system CSPRNG is unavailable");
        let (prefix, salt) = random.split_at(NONCE_PREFIX_LEN);
        Self {
            container_version: CONTAINER_VERSION,
            chunk_size: CHUNK_SIZE,
            nonce_prefix: prefix.try_into().expect("prefix length"),
            content_salt: salt.try_into().expect("salt length"),
            plaintext_len,
        }
    }

    /// How many chunks this plaintext occupies. An empty file still has one,
    /// so that a container can never legitimately hold zero chunks and a
    /// truncation to nothing is detectable.
    pub fn chunk_count(&self) -> u64 {
        let chunk_size = u64::from(self.chunk_size);
        match self.plaintext_len {
            0 => 1,
            len => len.div_ceil(chunk_size),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.container_version != CONTAINER_VERSION {
            return Err(LockerError::UnsupportedVersion(self.container_version));
        }
        if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&self.chunk_size)
            || !self.chunk_size.is_power_of_two()
        {
            return Err(LockerError::Malformed("chunk size"));
        }
        if self.chunk_count() > MAX_CHUNK_INDEX {
            return Err(LockerError::Malformed("plaintext length"));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.array(CORE_FIELDS);
        writer.uint(u64::from(self.container_version));
        writer.uint(CIPHER_CHACHA20_POLY1305);
        writer.uint(u64::from(self.chunk_size));
        writer.bytes(&self.nonce_prefix);
        writer.bytes(&self.content_salt);
        writer.uint(self.plaintext_len);
        writer.into_bytes()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_CORE_BYTES {
            return Err(LockerError::TooLarge {
                section: "header",
                limit: MAX_CORE_BYTES,
            });
        }
        let mut reader = Reader::new(bytes);
        if reader.array()? != CORE_FIELDS {
            return Err(LockerError::Malformed("header shape"));
        }
        let container_version = u8::try_from(reader.uint()?)
            .map_err(|_| LockerError::Malformed("container version"))?;
        if container_version != CONTAINER_VERSION {
            return Err(LockerError::UnsupportedVersion(container_version));
        }
        if reader.uint()? != CIPHER_CHACHA20_POLY1305 {
            return Err(LockerError::Malformed("cipher"));
        }
        let header = Self {
            container_version,
            chunk_size: u32::try_from(reader.uint()?)
                .map_err(|_| LockerError::Malformed("chunk size"))?,
            nonce_prefix: fixed(reader.bytes()?, "nonce prefix")?,
            content_salt: fixed(reader.bytes()?, "content salt")?,
            plaintext_len: reader.uint()?,
        };
        reader.finish()?;
        header.validate()?;
        if header.encode() != bytes {
            return Err(LockerError::Malformed("header is not canonical"));
        }
        Ok(header)
    }

    /// Nonce for chunk `index`. `final_chunk` is what makes a truncated file
    /// fail its tag instead of decrypting to a shorter, plausible file.
    pub(crate) fn chunk_nonce(&self, index: u64, final_chunk: bool) -> [u8; NONCE_LEN] {
        debug_assert!(index <= MAX_CHUNK_INDEX);
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..NONCE_PREFIX_LEN].copy_from_slice(&self.nonce_prefix);
        nonce[NONCE_PREFIX_LEN..NONCE_PREFIX_LEN + 4]
            .copy_from_slice(&(index as u32).to_be_bytes());
        nonce[NONCE_LEN - 1] = u8::from(final_chunk);
        nonce
    }

    /// Nonce for the metadata block. Reserved: no chunk can reach counter
    /// `0xFFFFFFFF`, and no chunk's final byte is ever 2.
    pub(crate) fn metadata_nonce(&self) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..NONCE_PREFIX_LEN].copy_from_slice(&self.nonce_prefix);
        nonce[NONCE_PREFIX_LEN..NONCE_PREFIX_LEN + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        nonce[NONCE_LEN - 1] = 2;
        nonce
    }
}

/// The eight magic bytes for this build's container version.
pub(crate) fn magic() -> [u8; 8] {
    let mut magic = [0u8; 8];
    magic[..MAGIC_PREFIX.len()].copy_from_slice(MAGIC_PREFIX);
    magic[7] = CONTAINER_VERSION;
    magic
}

/// The value every tag in the container authenticates.
///
/// Covering the magic as well as the header means a container cannot be
/// re-labelled as another version and still open.
pub fn binding_of(core: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BINDING_DOMAIN);
    hasher.update(magic());
    hasher.update(core);
    hasher.finalize().into()
}

/// What a wrapper's own tag covers, on top of the container it belongs to.
///
/// The binding alone leaves the wrapper's kind and id unauthenticated, and an
/// id is what decides which credential the desktop will go and ask. Folding
/// both into the additional data means every byte of a container is covered by
/// some tag, and the phone can compute this itself from the binding it is sent
/// and the credential id it already knows.
pub fn wrapper_aad(binding: &[u8; 32], kind: WrapperKind, id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(WRAPPER_DOMAIN);
    hasher.update(binding);
    hasher.update([kind.wire() as u8]);
    hasher.update(id.as_bytes());
    hasher.finalize().into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapperKind {
    /// Unwrapped by the phone, behind a strong biometric, per use.
    Phone,
    /// Unwrapped by a recovery code the user stored offline.
    Recovery,
}

impl WrapperKind {
    fn wire(self) -> u64 {
        match self {
            Self::Phone => 0,
            Self::Recovery => 1,
        }
    }

    fn from_wire(value: u64) -> Result<Self> {
        match value {
            0 => Ok(Self::Phone),
            1 => Ok(Self::Recovery),
            _ => Err(LockerError::Malformed("wrapper kind")),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Phone => "phone",
            Self::Recovery => "recovery",
        }
    }
}

/// One wrapped copy of the data key.
///
/// The ciphertext of a phone wrapper is opaque here: it was produced by the
/// phone's Keystore and only the phone can open it. Carrying it without
/// understanding it is the point.
#[derive(Clone, PartialEq, Eq)]
pub struct Wrapper {
    pub kind: WrapperKind,
    /// The credential id for a phone wrapper; empty for a recovery wrapper.
    pub id: String,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl Wrapper {
    fn validate(&self) -> Result<()> {
        if utf16_len(&self.id) > MAX_ID_UNITS {
            return Err(LockerError::Malformed("wrapper id"));
        }
        if self.ciphertext.is_empty() || self.ciphertext.len() > MAX_WRAPPER_CIPHERTEXT {
            return Err(LockerError::Malformed("wrapper ciphertext"));
        }
        let (salt, nonce) = match self.kind {
            // A phone wrapper carries its own nonce inside the blob the phone
            // produced; the desktop has nothing to say about either field.
            WrapperKind::Phone => (0, 0),
            WrapperKind::Recovery => (SALT_LEN, NONCE_LEN),
        };
        if self.salt.len() != salt || self.nonce.len() != nonce {
            return Err(LockerError::Malformed("wrapper salt or nonce"));
        }
        Ok(())
    }
}

pub(crate) fn encode_wrappers(wrappers: &[Wrapper]) -> Result<Vec<u8>> {
    if wrappers.is_empty() || wrappers.len() > MAX_WRAPPERS {
        return Err(LockerError::Malformed("wrapper count"));
    }
    let mut writer = Writer::new();
    writer.array(wrappers.len() as u64);
    for wrapper in wrappers {
        wrapper.validate()?;
        writer.array(WRAPPER_FIELDS);
        writer.uint(wrapper.kind.wire());
        writer.text(&wrapper.id);
        writer.bytes(&wrapper.salt);
        writer.bytes(&wrapper.nonce);
        writer.bytes(&wrapper.ciphertext);
    }
    let encoded = writer.into_bytes();
    if encoded.len() > MAX_WRAPPER_BYTES {
        return Err(LockerError::TooLarge {
            section: "wrappers",
            limit: MAX_WRAPPER_BYTES,
        });
    }
    Ok(encoded)
}

pub(crate) fn decode_wrappers(bytes: &[u8]) -> Result<Vec<Wrapper>> {
    if bytes.len() > MAX_WRAPPER_BYTES {
        return Err(LockerError::TooLarge {
            section: "wrappers",
            limit: MAX_WRAPPER_BYTES,
        });
    }
    let mut reader = Reader::new(bytes);
    let count = reader.array()?;
    if count == 0 || count > MAX_WRAPPERS as u64 {
        return Err(LockerError::Malformed("wrapper count"));
    }
    let mut wrappers = Vec::with_capacity(count as usize);
    for _ in 0..count {
        if reader.array()? != WRAPPER_FIELDS {
            return Err(LockerError::Malformed("wrapper shape"));
        }
        let wrapper = Wrapper {
            kind: WrapperKind::from_wire(reader.uint()?)?,
            id: reader.text()?.to_owned(),
            salt: reader.bytes()?.to_vec(),
            nonce: reader.bytes()?.to_vec(),
            ciphertext: reader.bytes()?.to_vec(),
        };
        wrapper.validate()?;
        wrappers.push(wrapper);
    }
    reader.finish()?;
    if encode_wrappers(&wrappers)? != bytes {
        return Err(LockerError::Malformed("wrappers are not canonical"));
    }
    Ok(wrappers)
}

/// What the container knows about the file it holds. Encrypted, because a
/// directory of locked files should not be an index of what the user owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    pub original_name: String,
    /// Unix permission bits, or 0 where the platform has none.
    pub mode: u32,
    pub modified_at_ms: i64,
    pub original_len: u64,
}

impl Metadata {
    pub fn validate(&self) -> Result<()> {
        if self.original_name.is_empty() || utf16_len(&self.original_name) > MAX_NAME_UNITS {
            return Err(LockerError::UnsafeName);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut writer = Writer::new();
        writer.array(METADATA_FIELDS);
        writer.uint(METADATA_SCHEMA);
        writer.text(&self.original_name);
        writer.uint(u64::from(self.mode));
        writer.int(self.modified_at_ms);
        writer.uint(self.original_len);
        let encoded = writer.into_bytes();
        if encoded.len() > MAX_METADATA_BYTES {
            return Err(LockerError::TooLarge {
                section: "metadata",
                limit: MAX_METADATA_BYTES,
            });
        }
        Ok(encoded)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_METADATA_BYTES {
            return Err(LockerError::TooLarge {
                section: "metadata",
                limit: MAX_METADATA_BYTES,
            });
        }
        let mut reader = Reader::new(bytes);
        if reader.array()? != METADATA_FIELDS {
            return Err(LockerError::Malformed("metadata shape"));
        }
        if reader.uint()? != METADATA_SCHEMA {
            return Err(LockerError::Malformed("metadata schema"));
        }
        let metadata = Self {
            original_name: reader.text()?.to_owned(),
            mode: u32::try_from(reader.uint()?).map_err(|_| LockerError::Malformed("mode"))?,
            modified_at_ms: reader.int()?,
            original_len: reader.uint()?,
        };
        reader.finish()?;
        metadata.validate()?;
        if metadata.encode()? != bytes {
            return Err(LockerError::Malformed("metadata is not canonical"));
        }
        Ok(metadata)
    }

    /// The file name to write, checked against everything a hostile container
    /// might put there.
    ///
    /// The name is attacker-controlled in exactly the case that matters —
    /// someone hands you a container — so a separator, a parent reference, or
    /// a Windows device name has to be refused rather than sanitised into
    /// something that merely looks safe.
    pub fn safe_file_name(&self) -> Result<&str> {
        let name = self.original_name.as_str();
        let stem = name.split('.').next().unwrap_or(name);
        let reserved = matches!(
            stem.to_ascii_uppercase().as_str(),
            "CON" | "PRN" | "AUX" | "NUL"
        ) || (stem.len() == 4
            && matches!(&stem.to_ascii_uppercase()[..3], "COM" | "LPT")
            && stem.as_bytes()[3].is_ascii_digit());

        if name.is_empty()
            || name == "."
            || name == ".."
            || reserved
            || name.ends_with(' ')
            || name.ends_with('.')
            || name.chars().any(|c| {
                matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') || c.is_control()
            })
        {
            return Err(LockerError::UnsafeName);
        }
        Ok(name)
    }
}

fn fixed<const N: usize>(value: &[u8], field: &'static str) -> Result<[u8; N]> {
    value.try_into().map_err(|_| LockerError::Malformed(field))
}

/// Counts UTF-16 code units, so a bound the Dart side enforces means the same
/// thing here.
fn utf16_len(value: &str) -> usize {
    value.chars().map(char::len_utf16).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> CoreHeader {
        CoreHeader {
            container_version: 1,
            chunk_size: CHUNK_SIZE,
            nonce_prefix: [1, 2, 3, 4, 5, 6, 7],
            content_salt: [9; SALT_LEN],
            plaintext_len: 100_000,
        }
    }

    #[test]
    fn the_header_round_trips_and_pins_its_bytes() {
        let encoded = header().encode();
        assert_eq!(
            phone_auth_protocol::encoding::to_hex(&encoded),
            concat!(
                "8601011a000100004701020304050607582009090909090909090909090909",
                "090909090909090909090909090909090909091a000186a0"
            )
        );
        assert_eq!(CoreHeader::decode(&encoded).expect("decode"), header());
    }

    #[test]
    fn an_empty_file_still_has_one_chunk() {
        let mut header = header();
        header.plaintext_len = 0;
        assert_eq!(header.chunk_count(), 1);
        header.plaintext_len = 1;
        assert_eq!(header.chunk_count(), 1);
        header.plaintext_len = u64::from(CHUNK_SIZE);
        assert_eq!(header.chunk_count(), 1);
        header.plaintext_len = u64::from(CHUNK_SIZE) + 1;
        assert_eq!(header.chunk_count(), 2);
    }

    #[test]
    fn a_metadata_nonce_can_never_be_a_chunk_nonce() {
        let header = header();
        let metadata = header.metadata_nonce();
        for index in [0, 1, 2, MAX_CHUNK_INDEX] {
            assert_ne!(header.chunk_nonce(index, false), metadata);
            assert_ne!(header.chunk_nonce(index, true), metadata);
        }
        assert_ne!(header.chunk_nonce(0, false), header.chunk_nonce(0, true));
        assert_ne!(header.chunk_nonce(0, true), header.chunk_nonce(1, true));
    }

    #[test]
    fn a_foreign_version_or_cipher_fails_closed() {
        let mut writer = Writer::new();
        writer.array(CORE_FIELDS);
        writer.uint(2);
        writer.uint(1);
        writer.uint(u64::from(CHUNK_SIZE));
        writer.bytes(&[0; NONCE_PREFIX_LEN]);
        writer.bytes(&[0; SALT_LEN]);
        writer.uint(0);
        assert!(matches!(
            CoreHeader::decode(&writer.into_bytes()),
            Err(LockerError::UnsupportedVersion(2))
        ));

        let mut writer = Writer::new();
        writer.array(CORE_FIELDS);
        writer.uint(1);
        writer.uint(7);
        writer.uint(u64::from(CHUNK_SIZE));
        writer.bytes(&[0; NONCE_PREFIX_LEN]);
        writer.bytes(&[0; SALT_LEN]);
        writer.uint(0);
        assert!(matches!(
            CoreHeader::decode(&writer.into_bytes()),
            Err(LockerError::Malformed("cipher"))
        ));
    }

    #[test]
    fn an_absurd_chunk_size_is_refused_before_it_is_believed() {
        for size in [
            0,
            1,
            MIN_CHUNK_SIZE - 1,
            MIN_CHUNK_SIZE + 1,
            MAX_CHUNK_SIZE * 2,
        ] {
            let candidate = CoreHeader {
                chunk_size: size,
                ..header()
            };
            assert!(candidate.validate().is_err(), "chunk size {size}");
        }
    }

    #[test]
    fn the_binding_changes_with_every_header_field() {
        let base = binding_of(&header().encode());
        let mut other = header();
        other.nonce_prefix[0] ^= 1;
        assert_ne!(binding_of(&other.encode()), base);
        let mut other = header();
        other.plaintext_len += 1;
        assert_ne!(binding_of(&other.encode()), base);
    }

    /// Pinned because the phone computes this value independently, in Kotlin.
    /// `LockerKeyStoreTest` asserts the same bytes; if either side moves, one
    /// of the two tests fails rather than every container silently refusing to
    /// open on a phone.
    #[test]
    fn the_wrapper_additional_data_is_pinned_for_the_phone() {
        let binding: [u8; 32] = core::array::from_fn(|index| index as u8);
        assert_eq!(
            phone_auth_protocol::encoding::to_hex(&wrapper_aad(
                &binding,
                WrapperKind::Phone,
                "locker-cred-1"
            )),
            "1e4fbb889c27e1d7ed6dfc9989f638393416c0c2b84648cefa70f1af63241d20"
        );
        // Kind and id both change it, which is the point of including them.
        assert_ne!(
            wrapper_aad(&binding, WrapperKind::Phone, "locker-cred-1"),
            wrapper_aad(&binding, WrapperKind::Recovery, "locker-cred-1")
        );
        assert_ne!(
            wrapper_aad(&binding, WrapperKind::Phone, "locker-cred-1"),
            wrapper_aad(&binding, WrapperKind::Phone, "locker-cred-2")
        );
    }

    #[test]
    fn wrappers_round_trip_and_reject_a_wrong_shaped_one() {
        let wrappers = vec![
            Wrapper {
                kind: WrapperKind::Phone,
                id: "cred-1".into(),
                salt: Vec::new(),
                nonce: Vec::new(),
                ciphertext: vec![1; 60],
            },
            Wrapper {
                kind: WrapperKind::Recovery,
                id: String::new(),
                salt: vec![2; SALT_LEN],
                nonce: vec![3; NONCE_LEN],
                ciphertext: vec![4; 48],
            },
        ];
        let encoded = encode_wrappers(&wrappers).expect("encode");
        // `Wrapper` has no `Debug`, so this compares rather than asserts equal.
        assert!(decode_wrappers(&encoded).expect("decode") == wrappers);

        let bad = vec![Wrapper {
            salt: vec![0; SALT_LEN],
            ..wrappers[0].clone()
        }];
        assert!(
            encode_wrappers(&bad).is_err(),
            "a phone wrapper has no salt"
        );

        assert!(encode_wrappers(&[]).is_err(), "no wrapper means no way in");
        let too_many = vec![wrappers[1].clone(); MAX_WRAPPERS + 1];
        assert!(encode_wrappers(&too_many).is_err());
    }

    #[test]
    fn metadata_round_trips() {
        let metadata = Metadata {
            original_name: "tax return.pdf".into(),
            mode: 0o600,
            modified_at_ms: 1_787_745_600_000,
            original_len: 100_000,
        };
        let encoded = metadata.encode().expect("encode");
        assert_eq!(Metadata::decode(&encoded).expect("decode"), metadata);
        assert_eq!(metadata.safe_file_name().expect("name"), "tax return.pdf");
    }

    #[test]
    fn a_name_that_could_escape_its_directory_is_refused() {
        for name in [
            "../escape",
            "..\\escape",
            "/etc/passwd",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "..",
            ".",
            "",
            "trailing ",
            "trailing.",
            "nul",
            "COM1.txt",
            "bell\u{7}",
        ] {
            let metadata = Metadata {
                original_name: name.into(),
                mode: 0,
                modified_at_ms: 0,
                original_len: 0,
            };
            assert!(
                metadata.safe_file_name().is_err(),
                "`{name}` must not be written"
            );
        }
    }
}
