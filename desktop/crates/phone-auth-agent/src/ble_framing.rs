//! Bounded PhoneAuth framing over BLE characteristic values.
//!
//! Android and BlueZ expose one characteristic value at a time. The six-byte
//! header here is shared with `mobile/lib/core/bluetooth/ble_frame_codec.dart`:
//! frame id, chunk index and chunk count, all big-endian `u16` values.

use std::collections::{BTreeMap, HashMap};
use std::io;

use crate::framing::MAX_FRAME;

const HEADER_BYTES: usize = 6;
const MAX_CHUNKS: usize = 1024;
const MAX_PARTIAL_FRAMES: usize = 4;

pub struct BleFrameEncoder {
    next_frame_id: u16,
}

impl BleFrameEncoder {
    pub fn new() -> Self {
        Self { next_frame_id: 0 }
    }

    pub fn encode(&mut self, frame: &[u8], att_payload_bytes: usize) -> io::Result<Vec<Vec<u8>>> {
        if frame.is_empty() || frame.len() > MAX_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("refusing to write a {}-byte BLE frame", frame.len()),
            ));
        }
        let data_bytes = att_payload_bytes
            .checked_sub(HEADER_BYTES)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "BLE MTU is too small"))?;
        if data_bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "BLE MTU is too small",
            ));
        }
        let total = frame.len().div_ceil(data_bytes);
        if total > MAX_CHUNKS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "BLE frame needs too many chunks",
            ));
        }

        let frame_id = self.next_frame_id;
        self.next_frame_id = self.next_frame_id.wrapping_add(1);
        Ok(frame
            .chunks(data_bytes)
            .enumerate()
            .map(|(index, part)| {
                let mut chunk = Vec::with_capacity(HEADER_BYTES + part.len());
                chunk.extend_from_slice(&frame_id.to_be_bytes());
                chunk.extend_from_slice(&(index as u16).to_be_bytes());
                chunk.extend_from_slice(&(total as u16).to_be_bytes());
                chunk.extend_from_slice(part);
                chunk
            })
            .collect())
    }
}

impl Default for BleFrameEncoder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default)]
pub struct BleFrameDecoder {
    partial: HashMap<u16, PartialFrame>,
}

impl BleFrameDecoder {
    pub fn add_chunk(&mut self, chunk: &[u8]) -> io::Result<Option<Vec<u8>>> {
        if chunk.len() <= HEADER_BYTES {
            return Err(invalid("BLE chunk has no payload"));
        }
        let frame_id = u16::from_be_bytes([chunk[0], chunk[1]]);
        let index = u16::from_be_bytes([chunk[2], chunk[3]]) as usize;
        let total = u16::from_be_bytes([chunk[4], chunk[5]]) as usize;
        if total == 0 || total > MAX_CHUNKS || index >= total {
            return Err(invalid("BLE chunk header is invalid"));
        }
        if !self.partial.contains_key(&frame_id) && self.partial.len() >= MAX_PARTIAL_FRAMES {
            return Err(invalid("too many partial BLE frames"));
        }

        let frame = self
            .partial
            .entry(frame_id)
            .or_insert_with(|| PartialFrame::new(total));
        if frame.total != total || frame.chunks.contains_key(&index) {
            self.partial.remove(&frame_id);
            return Err(invalid("inconsistent or duplicate BLE chunk"));
        }
        frame.bytes += chunk.len() - HEADER_BYTES;
        if frame.bytes > MAX_FRAME {
            self.partial.remove(&frame_id);
            return Err(invalid("BLE frame exceeds the size limit"));
        }
        frame.chunks.insert(index, chunk[HEADER_BYTES..].to_vec());
        if frame.chunks.len() != total {
            return Ok(None);
        }

        let frame = self.partial.remove(&frame_id).expect("frame exists");
        let mut bytes = Vec::with_capacity(frame.bytes);
        for index in 0..total {
            bytes.extend_from_slice(
                frame
                    .chunks
                    .get(&index)
                    .ok_or_else(|| invalid("BLE frame is missing a chunk"))?,
            );
        }
        Ok(Some(bytes))
    }
}

struct PartialFrame {
    total: usize,
    chunks: BTreeMap<usize, Vec<u8>>,
    bytes: usize,
}

impl PartialFrame {
    fn new(total: usize) -> Self {
        Self {
            total,
            chunks: BTreeMap::new(),
            bytes: 0,
        }
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_mobile_big_endian_header_and_round_trips() {
        let mut encoder = BleFrameEncoder::new();
        let chunks = encoder.encode(b"abcdefghij", 10).expect("encode");
        assert_eq!(
            chunks,
            vec![
                vec![0, 0, 0, 0, 0, 3, b'a', b'b', b'c', b'd'],
                vec![0, 0, 0, 1, 0, 3, b'e', b'f', b'g', b'h'],
                vec![0, 0, 0, 2, 0, 3, b'i', b'j'],
            ]
        );

        let mut decoder = BleFrameDecoder::default();
        assert_eq!(decoder.add_chunk(&chunks[1]).expect("chunk"), None);
        assert_eq!(decoder.add_chunk(&chunks[0]).expect("chunk"), None);
        assert_eq!(
            decoder.add_chunk(&chunks[2]).expect("chunk"),
            Some(b"abcdefghij".to_vec())
        );
    }

    #[test]
    fn refuses_duplicate_chunks_and_bounded_memory_abuse() {
        let mut decoder = BleFrameDecoder::default();
        let chunk = [0, 1, 0, 0, 0, 2, 0xaa];
        assert_eq!(decoder.add_chunk(&chunk).expect("first"), None);
        assert!(decoder.add_chunk(&chunk).is_err());

        for frame_id in 0..MAX_PARTIAL_FRAMES {
            let chunk = [0, frame_id as u8, 0, 0, 0, 2, 0xaa];
            decoder.add_chunk(&chunk).expect("bounded partial frame");
        }
        assert!(decoder.add_chunk(&[0, 9, 0, 0, 0, 2, 0xaa]).is_err());
    }

    #[test]
    fn refuses_empty_oversized_and_impossible_frames() {
        let mut encoder = BleFrameEncoder::new();
        assert!(encoder.encode(&[], 23).is_err());
        assert!(encoder.encode(&vec![0; MAX_FRAME + 1], 23).is_err());
        assert!(encoder.encode(b"x", HEADER_BYTES).is_err());

        let mut decoder = BleFrameDecoder::default();
        assert!(decoder.add_chunk(&[0; HEADER_BYTES]).is_err());
        assert!(decoder.add_chunk(&[0, 0, 0, 1, 0, 1, 0xaa]).is_err());
    }
}
