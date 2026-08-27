//! Hex and base64url helpers.
//!
//! Small enough to keep in-tree rather than take two dependencies that would
//! also have to be audited for the initrd build.

use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(&'static str);

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for DecodeError {}

pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}

pub fn from_hex(value: &str) -> Result<Vec<u8>, DecodeError> {
    if value.len() % 2 != 0 {
        return Err(DecodeError("hex string has an odd length"));
    }
    let bytes = value.as_bytes();
    (0..bytes.len())
        .step_by(2)
        .map(|i| {
            let hi = hex_digit(bytes[i])?;
            let lo = hex_digit(bytes[i + 1])?;
            Ok((hi << 4) | lo)
        })
        .collect()
}

fn hex_digit(byte: u8) -> Result<u8, DecodeError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(DecodeError("invalid hex digit")),
    }
}

const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Unpadded base64url, matching what the Dart side produces with
/// `base64Url.encode` after stripping `=`.
pub fn to_base64url(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let units = chunk.len() + 1;
        for i in 0..units {
            let shift = 18 - 6 * i;
            out.push(BASE64URL[((n >> shift) & 0x3f) as usize] as char);
        }
    }
    out
}

pub fn from_base64url(value: &str) -> Result<Vec<u8>, DecodeError> {
    let mut out = Vec::with_capacity(value.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for ch in value.chars() {
        if ch == '=' {
            break;
        }
        let index = BASE64URL
            .iter()
            .position(|&c| c as char == ch)
            .ok_or(DecodeError("invalid base64url character"))?;
        acc = (acc << 6) | index as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    // Leftover bits must be zero padding, never dropped data.
    if bits > 0 && (acc & ((1 << bits) - 1)) != 0 {
        return Err(DecodeError("base64url has non-zero trailing bits"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let bytes: Vec<u8> = (0..=255).collect();
        assert_eq!(from_hex(&to_hex(&bytes)), Ok(bytes));
    }

    #[test]
    fn hex_rejects_malformed_input() {
        assert!(from_hex("abc").is_err());
        assert!(from_hex("zz").is_err());
    }

    #[test]
    fn base64url_round_trips_every_length_class() {
        for len in 0..64 {
            let bytes: Vec<u8> = (0..len).map(|i: u8| i.wrapping_mul(7)).collect();
            let encoded = to_base64url(&bytes);
            assert!(
                !encoded.contains('=') && !encoded.contains('+') && !encoded.contains('/'),
                "encoding must be unpadded base64url"
            );
            assert_eq!(from_base64url(&encoded), Ok(bytes), "length {len}");
        }
    }

    #[test]
    fn base64url_matches_known_vectors() {
        // RFC 4648 test vectors, translated to the url alphabet and unpadded.
        assert_eq!(to_base64url(b"f"), "Zg");
        assert_eq!(to_base64url(b"fo"), "Zm8");
        assert_eq!(to_base64url(b"foo"), "Zm9v");
        assert_eq!(to_base64url(b"foobar"), "Zm9vYmFy");
        assert_eq!(to_base64url(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn base64url_rejects_foreign_alphabets() {
        assert!(from_base64url("Zm9v+g").is_err());
        assert!(from_base64url("Zm9v/g").is_err());
    }
}
