//! The SSH wire encodings a phone-held key has to speak.
//!
//! `SYS-02`. An SSH server and an `ssh` client agree on byte layouts defined
//! by RFC 4251 and RFC 5656, and there is no negotiating them: a public key
//! blob that is one byte off is a key the server does not recognise, and a
//! signature blob that is one byte off is a login that fails with no useful
//! message on either side.
//!
//! The credentials this project already pairs are ECDSA P-256, which is
//! exactly `ecdsa-sha2-nistp256`. So nothing new is signed and no new key
//! kind is generated — what was missing is the encoding, and that is all this
//! module is.
//!
//! # What is deliberately not here
//!
//! No socket, no agent protocol state, no policy. This module turns values
//! into bytes and back. Everything about *whether* to sign belongs to the
//! agent, where the user can be asked.

use crate::{ProtocolError, Result};

/// The key type name, as it appears on the wire and in `authorized_keys`.
pub const ECDSA_P256_NAME: &str = "ecdsa-sha2-nistp256";

/// The curve identifier RFC 5656 pairs with that name.
pub const ECDSA_P256_CURVE: &str = "nistp256";

/// An uncompressed P-256 point: `0x04 || X || Y`.
pub const UNCOMPRESSED_POINT_LEN: usize = 65;

/// One coordinate of a P-256 signature.
const SCALAR_LEN: usize = 32;

/// A cap on any length-prefixed field read from a socket.
///
/// SSH strings carry a 32-bit length, which is a number the peer chose. A
/// reader that believes one is four gigabytes away from an out-of-memory.
pub const MAX_FIELD_BYTES: usize = 64 * 1024;

/// Writes SSH's length-prefixed strings.
///
/// Separate from [`Writer`] because the framings disagree: CBOR is the
/// protocol between this project's own pieces, and this is the one OpenSSH
/// defined. Sharing a writer between them would be one `put_u32` away from
/// emitting the wrong shape into the wrong channel.
#[derive(Default)]
pub struct SshWriter {
    bytes: Vec<u8>,
}

impl SshWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn u32(&mut self, value: u32) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_be_bytes());
        self
    }

    pub fn u8(&mut self, value: u8) -> &mut Self {
        self.bytes.push(value);
        self
    }

    /// A `string`: a 32-bit big-endian length followed by that many bytes.
    pub fn string(&mut self, value: &[u8]) -> &mut Self {
        self.u32(value.len() as u32);
        self.bytes.extend_from_slice(value);
        self
    }

    pub fn text(&mut self, value: &str) -> &mut Self {
        self.string(value.as_bytes())
    }

    /// An `mpint`: a signed big-endian integer with no leading zero bytes,
    /// and a leading zero *added* when the high bit would otherwise make a
    /// positive number read as negative.
    ///
    /// This is the field most often got wrong, and getting it wrong produces a
    /// signature that verifies about half the time — which looks like a flaky
    /// network rather than a bug.
    pub fn mpint(&mut self, value: &[u8]) -> &mut Self {
        let trimmed = match value.iter().position(|byte| *byte != 0) {
            Some(first) => &value[first..],
            None => &[][..],
        };
        if trimmed.is_empty() {
            return self.u32(0);
        }
        if trimmed[0] & 0x80 != 0 {
            self.u32(trimmed.len() as u32 + 1);
            self.bytes.push(0);
            self.bytes.extend_from_slice(trimmed);
        } else {
            self.string(trimmed);
        }
        self
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Reads SSH's length-prefixed strings, refusing anything oversized.
pub struct SshReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> SshReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub fn u32(&mut self) -> Result<u32> {
        let end = self
            .position
            .checked_add(4)
            .ok_or(ProtocolError::UnexpectedEnd)?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(ProtocolError::UnexpectedEnd)?;
        self.position = end;
        Ok(u32::from_be_bytes(slice.try_into().expect("four bytes")))
    }

    pub fn u8(&mut self) -> Result<u8> {
        let byte = *self
            .bytes
            .get(self.position)
            .ok_or(ProtocolError::UnexpectedEnd)?;
        self.position += 1;
        Ok(byte)
    }

    /// Checked against the input's own length before slicing, so a declared
    /// four gigabytes fails on the input being short rather than by reserving
    /// four gigabytes first.
    pub fn string(&mut self) -> Result<&'a [u8]> {
        let length = self.u32()? as usize;
        if length > MAX_FIELD_BYTES {
            return Err(ProtocolError::PayloadSize(length));
        }
        let end = self
            .position
            .checked_add(length)
            .ok_or(ProtocolError::UnexpectedEnd)?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(ProtocolError::UnexpectedEnd)?;
        self.position = end;
        Ok(slice)
    }

    pub fn text(&mut self) -> Result<&'a str> {
        core::str::from_utf8(self.string()?).map_err(|_| ProtocolError::InvalidText("sshText"))
    }

    pub fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.position..]
    }

    /// Refuses trailing bytes, for the same reason every decoder in this
    /// project does: two byte strings that mean the same thing would be two
    /// messages one signature covers.
    pub fn finish(self) -> Result<()> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(ProtocolError::NotCanonical)
        }
    }
}

/// The `ecdsa-sha2-nistp256` public key blob, as it appears in an agent's
/// identity list and, base64-encoded, in `authorized_keys`.
///
/// `point` is the uncompressed form: `0x04 || X || Y`, 65 bytes. A paired
/// credential's SPKI carries exactly those bytes at its tail, which is why no
/// new key ever has to be generated for SSH.
pub fn encode_public_key(point: &[u8]) -> Result<Vec<u8>> {
    if point.len() != UNCOMPRESSED_POINT_LEN || point[0] != 0x04 {
        return Err(ProtocolError::FieldLength {
            field: "sshPublicKeyPoint",
            expected: UNCOMPRESSED_POINT_LEN,
            actual: point.len(),
        });
    }
    let mut writer = SshWriter::new();
    writer
        .text(ECDSA_P256_NAME)
        .text(ECDSA_P256_CURVE)
        .string(point);
    Ok(writer.into_bytes())
}

/// The point inside a public key blob.
pub fn decode_public_key(blob: &[u8]) -> Result<Vec<u8>> {
    let mut reader = SshReader::new(blob);
    if reader.text()? != ECDSA_P256_NAME {
        return Err(ProtocolError::InvalidOperation);
    }
    if reader.text()? != ECDSA_P256_CURVE {
        return Err(ProtocolError::InvalidOperation);
    }
    let point = reader.string()?;
    reader.finish()?;
    if point.len() != UNCOMPRESSED_POINT_LEN || point[0] != 0x04 {
        return Err(ProtocolError::FieldLength {
            field: "sshPublicKeyPoint",
            expected: UNCOMPRESSED_POINT_LEN,
            actual: point.len(),
        });
    }
    Ok(point.to_vec())
}

/// The signature blob, from a raw `r || s` pair.
///
/// ECDSA signatures reach this project as 64 raw bytes — the form a P-256
/// signing operation produces and the form the phone returns. SSH wants them
/// as two `mpint`s inside a nested string, which is the conversion this
/// performs and the one that is easy to get subtly wrong.
pub fn encode_signature(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() != SCALAR_LEN * 2 {
        return Err(ProtocolError::FieldLength {
            field: "sshSignature",
            expected: SCALAR_LEN * 2,
            actual: raw.len(),
        });
    }
    let mut inner = SshWriter::new();
    inner.mpint(&raw[..SCALAR_LEN]).mpint(&raw[SCALAR_LEN..]);

    let mut writer = SshWriter::new();
    writer.text(ECDSA_P256_NAME).string(inner.as_bytes());
    Ok(writer.into_bytes())
}

/// The `r || s` pair inside a signature blob, zero-padded back to 32 bytes
/// each.
pub fn decode_signature(blob: &[u8]) -> Result<Vec<u8>> {
    let mut reader = SshReader::new(blob);
    if reader.text()? != ECDSA_P256_NAME {
        return Err(ProtocolError::InvalidOperation);
    }
    let inner = reader.string()?;
    reader.finish()?;

    let mut parts = SshReader::new(inner);
    let r = parts.string()?;
    let s = parts.string()?;
    parts.finish()?;

    let mut raw = Vec::with_capacity(SCALAR_LEN * 2);
    for scalar in [r, s] {
        // An mpint may carry a leading zero to keep it positive, and may be
        // short when its top bytes were zero. Both become a fixed 32 bytes.
        let trimmed = match scalar.iter().position(|byte| *byte != 0) {
            Some(first) => &scalar[first..],
            None => &[][..],
        };
        if trimmed.len() > SCALAR_LEN {
            return Err(ProtocolError::FieldLength {
                field: "sshSignatureScalar",
                expected: SCALAR_LEN,
                actual: trimmed.len(),
            });
        }
        raw.extend(core::iter::repeat_n(0u8, SCALAR_LEN - trimmed.len()));
        raw.extend_from_slice(trimmed);
    }
    Ok(raw)
}

/// The `authorized_keys` line for a public key blob.
///
/// Emitted so a user can paste one line into a server rather than working out
/// how to derive it, which is the step where people give up and generate an
/// ordinary key instead — defeating the point of the phone holding it.
pub fn authorized_keys_line(blob: &[u8], comment: &str) -> String {
    let comment = comment.replace(['\n', '\r'], " ");
    format!("{ECDSA_P256_NAME} {} {comment}", base64(blob))
}

/// Standard base64, which is what `authorized_keys` uses. Written here rather
/// than pulled in because the project's own encoding module is base64**url**,
/// and the two differ in exactly the two characters that would make a key line
/// look right and not work.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let triple = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(ALPHABET[(triple >> 18) as usize & 63] as char);
        out.push(ALPHABET[(triple >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(triple >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[triple as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// The P-256 point at the tail of an SPKI-encoded public key.
///
/// Paired credentials store SPKI, and the last 65 bytes of a P-256 SPKI are
/// the uncompressed point. Checked rather than assumed: a key of another curve
/// would otherwise be silently reinterpreted as this one.
pub fn point_from_spki(spki: &[u8]) -> Result<Vec<u8>> {
    if spki.len() < UNCOMPRESSED_POINT_LEN {
        return Err(ProtocolError::FieldLength {
            field: "spki",
            expected: UNCOMPRESSED_POINT_LEN,
            actual: spki.len(),
        });
    }
    let point = &spki[spki.len() - UNCOMPRESSED_POINT_LEN..];
    if point[0] != 0x04 {
        return Err(ProtocolError::InvalidOperation);
    }
    Ok(point.to_vec())
}

// --- the operation the phone serves -----------------------------------------
//
// Signing goes over the same `ApplicationFrame` the vault and locker use. What
// crosses is the SSH blob itself, because a server accepts a signature over
// exactly those bytes and nothing else.
//
// That makes this the most powerful operation in the protocol: a request to
// sign bytes the desktop chose. Three things bound it, and all three matter.
//
//   1. It uses a credential whose purpose is `Ssh` and no other. A signature
//      made here is never one the `sudo` or vault path would produce.
//   2. **The phone re-parses the blob itself.** The desktop's reading is used
//      to draw a prompt; the phone's reading is what decides. Without that,
//      a compromised desktop has a blind signing oracle for a key it cannot
//      otherwise reach.
//   3. What it signs must be a `publickey` userauth request. Anything else is
//      refused, so the oracle cannot be pointed at arbitrary bytes.

use crate::cbor::{Reader, Writer};
use crate::MAX_APPLICATION_PAYLOAD_BYTES;

/// `ssh.sign`: the phone signs one SSH authentication request.
pub const OPERATION_SIGN: &str = "ssh.sign";

/// This module's own schema number, versioned separately from the vault's.
pub const SSH_SCHEMA: u64 = 1;

const SIGN_REQUEST_FIELDS: u64 = 4;
const SIGN_RESPONSE_FIELDS: u64 = 2;

/// A signature over an SSH authentication request is 64 raw bytes.
pub const SIGNATURE_LEN: usize = 64;

/// The largest blob worth signing.
///
/// A userauth request is a few hundred bytes. A cap well above that and well
/// below the frame limit means an oversized one is refused as nonsense rather
/// than carried to the phone to be refused there.
pub const MAX_SIGN_DATA_BYTES: usize = 2048;

/// `ssh.sign`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignRequest {
    /// The computer asking, shown on the phone.
    pub verifier_name: String,
    /// What the phone should show as the destination: an OpenSSH-style
    /// fingerprint, or empty when the client did not name one.
    ///
    /// Advisory, and the phone treats it as such. It is the desktop's claim
    /// about where a connection is going, and the phone cannot check it — so
    /// it is displayed as what the computer said, never as a fact.
    pub destination: String,
    /// The exact bytes to sign.
    pub data: Vec<u8>,
}

impl SignRequest {
    pub fn validate(&self) -> Result<()> {
        check_name(&self.verifier_name)?;
        if self.destination.len() > 128 {
            return Err(ProtocolError::FieldTooLong {
                field: "destination",
                max: 128,
                actual: self.destination.len(),
            });
        }
        if self.data.is_empty() || self.data.len() > MAX_SIGN_DATA_BYTES {
            return Err(ProtocolError::PayloadSize(self.data.len()));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.array(SIGN_REQUEST_FIELDS);
        writer.uint(SSH_SCHEMA);
        writer.text(&self.verifier_name);
        writer.text(&self.destination);
        writer.bytes(&self.data);
        writer.into_bytes()
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut reader = open_ssh(payload, SIGN_REQUEST_FIELDS)?;
        let decoded = Self {
            verifier_name: reader.text()?.to_owned(),
            destination: reader.text()?.to_owned(),
            data: reader.bytes()?.to_vec(),
        };
        finish_ssh(reader, &decoded.encode(), payload)?;
        decoded.validate()?;
        Ok(decoded)
    }
}

/// The phone's answer: a raw ECDSA signature, for the desktop to wrap in
/// SSH's own encoding.
///
/// Raw rather than pre-wrapped so that the encoding lives in one place. Two
/// implementations of the `mpint` rule would be one implementation too many.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignResponse {
    pub signature: Vec<u8>,
}

impl SignResponse {
    pub fn validate(&self) -> Result<()> {
        if self.signature.len() != SIGNATURE_LEN {
            return Err(ProtocolError::FieldLength {
                field: "signature",
                expected: SIGNATURE_LEN,
                actual: self.signature.len(),
            });
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.array(SIGN_RESPONSE_FIELDS);
        writer.uint(SSH_SCHEMA);
        writer.bytes(&self.signature);
        writer.into_bytes()
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut reader = open_ssh(payload, SIGN_RESPONSE_FIELDS)?;
        let decoded = Self {
            signature: reader.bytes()?.to_vec(),
        };
        finish_ssh(reader, &decoded.encode(), payload)?;
        decoded.validate()?;
        Ok(decoded)
    }
}

/// The account an SSH authentication request is for, read from the blob.
///
/// The phone runs this on the bytes it is about to sign, which is the check
/// that keeps `ssh.sign` from being a blind signing oracle: a blob that is not
/// a `publickey` userauth request has no account to show and is not signed.
pub fn account_in_request(data: &[u8]) -> Option<(String, String)> {
    let mut reader = SshReader::new(data);
    let _session_id = reader.string().ok()?;
    // SSH_MSG_USERAUTH_REQUEST.
    if reader.u8().ok()? != 50 {
        return None;
    }
    let user = reader.text().ok()?.to_owned();
    let service = reader.text().ok()?.to_owned();
    if reader.text().ok()? != "publickey" {
        return None;
    }
    Some((user, service))
}

fn check_name(value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(ProtocolError::FieldEmpty("verifierName"));
    }
    if value.chars().count() > 64 {
        return Err(ProtocolError::FieldTooLong {
            field: "verifierName",
            max: 64,
            actual: value.chars().count(),
        });
    }
    Ok(())
}

fn open_ssh(payload: &[u8], fields: u64) -> Result<Reader<'_>> {
    if payload.is_empty() || payload.len() > MAX_APPLICATION_PAYLOAD_BYTES {
        return Err(ProtocolError::PayloadSize(payload.len()));
    }
    let mut reader = Reader::new(payload);
    let len = reader.array()?;
    if len != fields {
        return Err(ProtocolError::FrameShape {
            expected: fields,
            actual: len,
        });
    }
    let schema = reader.uint()?;
    if schema != SSH_SCHEMA {
        return Err(ProtocolError::UnsupportedVersion(schema));
    }
    Ok(reader)
}

/// The canonical-encoding check every payload in this project performs: two
/// byte strings that mean the same thing would be two requests one approval
/// covers.
fn finish_ssh(reader: Reader<'_>, reencoded: &[u8], payload: &[u8]) -> Result<()> {
    reader.finish()?;
    if reencoded != payload {
        return Err(ProtocolError::NotCanonical);
    }
    Ok(())
}
