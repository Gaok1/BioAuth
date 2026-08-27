//! Canonical CBOR primitives for PhoneAuth frames.
//!
//! Only the subset the protocol actually uses is implemented: definite-length
//! arrays, unsigned/negative integers, text strings and byte strings. Maps are
//! absent on purpose — the wire format uses fixed-order arrays so that no key
//! ordering ambiguity can exist between the Dart authenticator and this
//! verifier.
//!
//! The reader is strict: a head whose argument is not encoded in the shortest
//! possible form is rejected rather than normalised. Two encodings of the same
//! value would otherwise both parse while only one of them matches the bytes
//! that were signed.

use core::fmt;

const MAJOR_UINT: u8 = 0;
const MAJOR_NEGINT: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CborError {
    /// Ran out of bytes while reading a head or payload.
    Truncated,
    /// Trailing bytes remained after the top-level item.
    TrailingBytes,
    /// A head used a longer argument encoding than necessary.
    NonCanonicalInteger,
    /// Indefinite lengths, floats, tags and simple values are not accepted.
    UnsupportedItem,
    /// The item was well formed but not of the expected major type.
    UnexpectedType,
    /// A length or integer did not fit the target Rust type.
    OutOfRange,
    /// A text string was not valid UTF-8.
    InvalidUtf8,
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Truncated => "truncated CBOR item",
            Self::TrailingBytes => "trailing bytes after CBOR item",
            Self::NonCanonicalInteger => "non-canonical integer encoding",
            Self::UnsupportedItem => "unsupported CBOR item",
            Self::UnexpectedType => "unexpected CBOR major type",
            Self::OutOfRange => "CBOR value out of range",
            Self::InvalidUtf8 => "CBOR text string is not valid UTF-8",
        };
        f.write_str(message)
    }
}

impl std::error::Error for CborError {}

type Result<T> = core::result::Result<T, CborError>;

/// Appends canonical CBOR items to a byte buffer.
#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Writes a major type with its argument in the shortest form that fits.
    fn head(&mut self, major: u8, argument: u64) {
        let major = major << 5;
        match argument {
            0..=23 => self.buf.push(major | argument as u8),
            24..=0xff => {
                self.buf.push(major | 24);
                self.buf.push(argument as u8);
            }
            0x100..=0xffff => {
                self.buf.push(major | 25);
                self.buf.extend_from_slice(&(argument as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                self.buf.push(major | 26);
                self.buf.extend_from_slice(&(argument as u32).to_be_bytes());
            }
            _ => {
                self.buf.push(major | 27);
                self.buf.extend_from_slice(&argument.to_be_bytes());
            }
        }
    }

    pub fn array(&mut self, len: u64) {
        self.head(MAJOR_ARRAY, len);
    }

    pub fn uint(&mut self, value: u64) {
        self.head(MAJOR_UINT, value);
    }

    /// Writes a signed integer. Negative values use major type 1, where the
    /// argument encodes `-1 - value`.
    pub fn int(&mut self, value: i64) {
        if value < 0 {
            self.head(MAJOR_NEGINT, (-1 - value) as u64);
        } else {
            self.head(MAJOR_UINT, value as u64);
        }
    }

    pub fn text(&mut self, value: &str) {
        self.head(MAJOR_TEXT, value.len() as u64);
        self.buf.extend_from_slice(value.as_bytes());
    }

    pub fn bytes(&mut self, value: &[u8]) {
        self.head(MAJOR_BYTES, value.len() as u64);
        self.buf.extend_from_slice(value);
    }
}

/// Reads canonical CBOR items from a byte slice.
#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(len).ok_or(CborError::OutOfRange)?;
        let slice = self.buf.get(self.pos..end).ok_or(CborError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    /// Reads one head, rejecting non-shortest arguments and every item shape
    /// the protocol does not use.
    fn head(&mut self) -> Result<(u8, u64)> {
        let initial = *self.take(1)?.first().ok_or(CborError::Truncated)?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        let argument = match additional {
            0..=23 => u64::from(additional),
            24 => {
                let value = u64::from(self.take(1)?[0]);
                if value < 24 {
                    return Err(CborError::NonCanonicalInteger);
                }
                value
            }
            25 => {
                let bytes: [u8; 2] = self.take(2)?.try_into().map_err(|_| CborError::Truncated)?;
                let value = u64::from(u16::from_be_bytes(bytes));
                if value <= 0xff {
                    return Err(CborError::NonCanonicalInteger);
                }
                value
            }
            26 => {
                let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| CborError::Truncated)?;
                let value = u64::from(u32::from_be_bytes(bytes));
                if value <= 0xffff {
                    return Err(CborError::NonCanonicalInteger);
                }
                value
            }
            27 => {
                let bytes: [u8; 8] = self.take(8)?.try_into().map_err(|_| CborError::Truncated)?;
                let value = u64::from_be_bytes(bytes);
                if value <= 0xffff_ffff {
                    return Err(CborError::NonCanonicalInteger);
                }
                value
            }
            // 28..=30 are reserved; 31 is indefinite length.
            _ => return Err(CborError::UnsupportedItem),
        };
        Ok((major, argument))
    }

    fn expect(&mut self, major: u8) -> Result<u64> {
        let (actual, argument) = self.head()?;
        if actual != major {
            return Err(CborError::UnexpectedType);
        }
        Ok(argument)
    }

    pub fn array(&mut self) -> Result<u64> {
        self.expect(MAJOR_ARRAY)
    }

    pub fn uint(&mut self) -> Result<u64> {
        self.expect(MAJOR_UINT)
    }

    /// Reads a signed integer from either integer major type.
    pub fn int(&mut self) -> Result<i64> {
        let (major, argument) = self.head()?;
        match major {
            MAJOR_UINT => i64::try_from(argument).map_err(|_| CborError::OutOfRange),
            MAJOR_NEGINT => i64::try_from(argument)
                .map(|value| -1 - value)
                .map_err(|_| CborError::OutOfRange),
            _ => Err(CborError::UnexpectedType),
        }
    }

    pub fn text(&mut self) -> Result<&'a str> {
        let len = usize::try_from(self.expect(MAJOR_TEXT)?).map_err(|_| CborError::OutOfRange)?;
        core::str::from_utf8(self.take(len)?).map_err(|_| CborError::InvalidUtf8)
    }

    pub fn bytes(&mut self) -> Result<&'a [u8]> {
        let len = usize::try_from(self.expect(MAJOR_BYTES)?).map_err(|_| CborError::OutOfRange)?;
        self.take(len)
    }

    /// Fails unless every byte of the input has been consumed.
    pub fn finish(self) -> Result<()> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(CborError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(f: impl FnOnce(&mut Writer)) -> Vec<u8> {
        let mut writer = Writer::new();
        f(&mut writer);
        writer.into_bytes()
    }

    #[test]
    fn integer_heads_use_the_shortest_form() {
        assert_eq!(encoded(|w| w.uint(0)), [0x00]);
        assert_eq!(encoded(|w| w.uint(23)), [0x17]);
        assert_eq!(encoded(|w| w.uint(24)), [0x18, 0x18]);
        assert_eq!(encoded(|w| w.uint(255)), [0x18, 0xff]);
        assert_eq!(encoded(|w| w.uint(256)), [0x19, 0x01, 0x00]);
        assert_eq!(encoded(|w| w.uint(65_536)), [0x1a, 0x00, 0x01, 0x00, 0x00]);
        assert_eq!(
            encoded(|w| w.uint(4_294_967_296)),
            [0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn negative_integers_round_trip() {
        for value in [-1_i64, -24, -25, -256, -1_000_000, i64::MIN + 1] {
            let bytes = encoded(|w| w.int(value));
            assert_eq!(Reader::new(&bytes).int(), Ok(value), "value {value}");
        }
    }

    #[test]
    fn reader_rejects_padded_integer_arguments() {
        // 23 encoded in a one-byte argument instead of inline.
        assert_eq!(
            Reader::new(&[0x18, 0x17]).uint(),
            Err(CborError::NonCanonicalInteger)
        );
        // 255 encoded in a two-byte argument.
        assert_eq!(
            Reader::new(&[0x19, 0x00, 0xff]).uint(),
            Err(CborError::NonCanonicalInteger)
        );
    }

    #[test]
    fn reader_rejects_indefinite_length_items() {
        assert_eq!(
            Reader::new(&[0x9f, 0xff]).array(),
            Err(CborError::UnsupportedItem)
        );
    }

    #[test]
    fn reader_rejects_trailing_bytes() {
        let bytes = [0x01, 0x02];
        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.uint(), Ok(1));
        assert_eq!(reader.finish(), Err(CborError::TrailingBytes));
    }

    #[test]
    fn text_and_bytes_round_trip() {
        let bytes = encoded(|w| {
            w.array(2);
            w.text("nixos-rebuild switch");
            w.bytes(&[0xde, 0xad, 0xbe, 0xef]);
        });
        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.array(), Ok(2));
        assert_eq!(reader.text(), Ok("nixos-rebuild switch"));
        assert_eq!(reader.bytes(), Ok(&[0xde, 0xad, 0xbe, 0xef][..]));
        assert_eq!(reader.finish(), Ok(()));
    }
}
