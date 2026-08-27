//! Length-prefixed framing over a byte stream.
//!
//! TCP delivers a stream, not messages. Every frame the protocol defines has a
//! definite length, so a four-byte big-endian prefix is enough to recover
//! message boundaries — and the explicit length is what lets a reader refuse an
//! oversized frame before allocating for it.

use std::io::{self, Read, Write};

/// Largest frame this will read. Covers a handshake hello, which is the
/// biggest thing on the wire.
pub const MAX_FRAME: usize = 8192;

/// Bytes the length prefix occupies.
const PREFIX: usize = 4;

pub fn write_frame(stream: &mut impl Write, frame: &[u8]) -> io::Result<()> {
    if frame.is_empty() || frame.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refusing to write a {}-byte frame", frame.len()),
        ));
    }
    let mut buffer = Vec::with_capacity(PREFIX + frame.len());
    buffer.extend_from_slice(&(frame.len() as u32).to_be_bytes());
    buffer.extend_from_slice(frame);

    // One write call so a frame cannot be split across a failure, leaving a
    // length prefix on the wire with no body behind it.
    stream.write_all(&buffer)?;
    stream.flush()
}

pub fn read_frame(stream: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut prefix = [0u8; PREFIX];
    stream.read_exact(&mut prefix)?;
    let len = u32::from_be_bytes(prefix) as usize;

    // Checked before allocating: a peer that claims four gigabytes must not be
    // able to make this process ask for them.
    if len == 0 || len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("peer announced a {len}-byte frame"),
        ));
    }
    let mut frame = vec![0u8; len];
    stream.read_exact(&mut frame)?;
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frames_round_trip() {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, b"first").expect("write");
        write_frame(&mut buffer, b"second").expect("write");

        let mut cursor = Cursor::new(buffer);
        assert_eq!(read_frame(&mut cursor).expect("read"), b"first");
        assert_eq!(read_frame(&mut cursor).expect("read"), b"second");
    }

    #[test]
    fn a_maximum_sized_frame_round_trips() {
        let frame = vec![0xab; MAX_FRAME];
        let mut buffer = Vec::new();
        write_frame(&mut buffer, &frame).expect("write");
        assert_eq!(read_frame(&mut Cursor::new(buffer)).expect("read"), frame);
    }

    #[test]
    fn oversized_and_empty_frames_are_refused_on_write() {
        let mut buffer = Vec::new();
        assert!(write_frame(&mut buffer, &[]).is_err());
        assert!(write_frame(&mut buffer, &vec![0u8; MAX_FRAME + 1]).is_err());
        assert!(buffer.is_empty(), "nothing may reach the wire");
    }

    #[test]
    fn an_announced_length_beyond_the_maximum_is_refused_before_allocating() {
        // Only the prefix is present: if the reader tried to allocate first it
        // would ask for four gigabytes on this input.
        let announced = u32::MAX.to_be_bytes().to_vec();
        assert!(read_frame(&mut Cursor::new(announced)).is_err());
    }

    #[test]
    fn a_zero_length_frame_is_refused() {
        let announced = 0u32.to_be_bytes().to_vec();
        assert!(read_frame(&mut Cursor::new(announced)).is_err());
    }

    #[test]
    fn a_truncated_body_is_an_error_not_a_short_frame() {
        let mut buffer = 8u32.to_be_bytes().to_vec();
        buffer.extend_from_slice(b"only4");
        assert!(read_frame(&mut Cursor::new(buffer)).is_err());
    }

    #[test]
    fn a_truncated_prefix_is_an_error() {
        assert!(read_frame(&mut Cursor::new(vec![0u8, 1])).is_err());
    }
}
