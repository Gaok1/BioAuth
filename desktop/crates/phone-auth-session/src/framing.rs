//! Length-prefixed framing over a reliable byte stream.

use std::io::{self, Read, Write};

/// Largest handshake or encrypted record accepted before allocation.
pub const MAX_FRAME: usize = 8192;
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
    stream.write_all(&buffer)?;
    stream.flush()
}

pub fn read_frame(stream: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut prefix = [0u8; PREFIX];
    stream.read_exact(&mut prefix)?;
    let len = u32::from_be_bytes(prefix) as usize;
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

/// Reads across short socket timeouts without losing a partial frame.
pub fn read_frame_resumable(stream: &mut impl Read, pending: &mut Vec<u8>) -> io::Result<Vec<u8>> {
    fill_to(stream, pending, PREFIX)?;
    let len = u32::from_be_bytes(pending[..PREFIX].try_into().expect("four-byte prefix")) as usize;
    if len == 0 || len > MAX_FRAME {
        pending.clear();
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("peer announced a {len}-byte frame"),
        ));
    }
    fill_to(stream, pending, PREFIX + len)?;
    let frame = pending[PREFIX..PREFIX + len].to_vec();
    pending.drain(..PREFIX + len);
    Ok(frame)
}

fn fill_to(stream: &mut impl Read, pending: &mut Vec<u8>, target: usize) -> io::Result<()> {
    while pending.len() < target {
        let mut chunk = [0u8; 1024];
        let wanted = (target - pending.len()).min(chunk.len());
        let read = stream.read(&mut chunk[..wanted])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed inside a frame",
            ));
        }
        pending.extend_from_slice(&chunk[..read]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frames_round_trip_and_reject_unbounded_lengths() {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, b"first").unwrap();
        write_frame(&mut buffer, b"second").unwrap();
        let mut cursor = Cursor::new(buffer);
        assert_eq!(read_frame(&mut cursor).unwrap(), b"first");
        assert_eq!(read_frame(&mut cursor).unwrap(), b"second");
        assert!(write_frame(&mut Vec::new(), &[]).is_err());
        assert!(write_frame(&mut Vec::new(), &vec![0; MAX_FRAME + 1]).is_err());
        assert!(read_frame(&mut Cursor::new(u32::MAX.to_be_bytes())).is_err());
        assert!(read_frame(&mut Cursor::new(0u32.to_be_bytes())).is_err());
    }

    #[test]
    fn resumable_read_keeps_bytes_across_a_timeout() {
        struct TimeoutOnce {
            bytes: Cursor<Vec<u8>>,
            calls: usize,
        }
        impl Read for TimeoutOnce {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                self.calls += 1;
                if self.calls == 2 {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "poll"));
                }
                self.bytes.read(buffer)
            }
        }
        let mut bytes = 5u32.to_be_bytes().to_vec();
        bytes.extend_from_slice(b"hello");
        let mut reader = TimeoutOnce {
            bytes: Cursor::new(bytes),
            calls: 0,
        };
        let mut pending = Vec::new();
        assert_eq!(
            read_frame_resumable(&mut reader, &mut pending)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert!(!pending.is_empty());
        assert_eq!(
            read_frame_resumable(&mut reader, &mut pending).unwrap(),
            b"hello"
        );
    }
}
