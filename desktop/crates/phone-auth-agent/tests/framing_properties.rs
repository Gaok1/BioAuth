//! Property tests over the two framings that read bytes off a wire.
//!
//! Both sit in front of everything else: the length-prefixed socket framing
//! that carries every session, and the BLE reassembler that rebuilds a frame
//! from characteristic writes. Neither has authenticated anything yet, so both
//! are reachable by anyone who can reach the transport.
//!
//! The properties are about resources rather than correctness. A decoder that
//! trusts a length header is one packet away from an out-of-memory; a
//! reassembler that keeps every partial frame it is handed is one loop away
//! from the same thing. `MAX_FRAME`, `MAX_CHUNKS` and `MAX_PARTIAL_FRAMES`
//! exist for that, and these tests are what says so.

use std::io::Cursor;

use phone_auth_agent::ble_framing::{BleFrameDecoder, BleFrameEncoder};
use phone_auth_agent::framing::{read_frame, write_frame, MAX_FRAME};
use proptest::prelude::*;

proptest! {
    #[test]
    fn a_written_frame_reads_back(frame in prop::collection::vec(any::<u8>(), 1..4096)) {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, &frame).expect("within MAX_FRAME");

        let read = read_frame(&mut Cursor::new(buffer)).expect("our own frame");

        prop_assert_eq!(read, frame);
    }

    /// The length prefix is a number the peer chose. Announcing four gigabytes
    /// and sending four bytes must fail on the announcement, not after the
    /// allocation.
    #[test]
    fn an_announced_length_over_the_cap_is_refused(
        announced in (MAX_FRAME as u32 + 1)..u32::MAX,
        body in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let mut stream = announced.to_be_bytes().to_vec();
        stream.extend_from_slice(&body);

        prop_assert!(read_frame(&mut Cursor::new(stream)).is_err());
    }

    /// Truncation is an error, never a short frame. A caller that received
    /// half a frame and treated it as whole would be parsing attacker-chosen
    /// padding as protocol.
    #[test]
    fn a_truncated_frame_is_refused(
        frame in prop::collection::vec(any::<u8>(), 2..1024),
        keep in 0usize..100,
    ) {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, &frame).expect("within MAX_FRAME");
        let keep = (buffer.len() * keep / 100).min(buffer.len() - 1);

        prop_assert!(read_frame(&mut Cursor::new(buffer[..keep].to_vec())).is_err());
    }

    #[test]
    fn read_frame_never_panics_on_arbitrary_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        let result = read_frame(&mut Cursor::new(bytes));
        prop_assert!(result.is_ok() || result.is_err());
    }

    /// Chunks arriving in any order rebuild the same frame. BLE gives no
    /// ordering guarantee across writes, so an assembler that only worked
    /// in-order would work on a desk and fail in a pocket.
    #[test]
    fn chunks_reassemble_in_any_order(
        frame in prop::collection::vec(any::<u8>(), 1..2048),
        mtu in 8usize..64,
        seed in any::<u64>(),
    ) {
        let mut chunks = BleFrameEncoder::new()
            .encode(&frame, mtu)
            .expect("within the chunk cap");

        // A cheap deterministic shuffle. `rand` is not a dependency here and
        // this only has to be a permutation, not a good one.
        let mut state = seed | 1;
        for index in (1..chunks.len()).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            chunks.swap(index, (state >> 33) as usize % (index + 1));
        }

        let mut decoder = BleFrameDecoder::default();
        let mut rebuilt = None;
        for chunk in &chunks {
            if let Some(complete) = decoder.add_chunk(chunk).expect("our own chunks") {
                rebuilt = Some(complete);
            }
        }

        prop_assert_eq!(rebuilt, Some(frame));
    }

    #[test]
    fn the_reassembler_never_panics_on_arbitrary_chunks(
        chunks in prop::collection::vec(
            prop::collection::vec(any::<u8>(), 0..64),
            0..32,
        ),
    ) {
        let mut decoder = BleFrameDecoder::default();
        for chunk in &chunks {
            // Reaching the end is the property: a peer writing nonsense to a
            // characteristic must not take the agent down with it.
            let _ = decoder.add_chunk(chunk);
        }
    }

    /// A peer that opens a new partial frame and never finishes it, forever,
    /// must be refused rather than accumulated. Without the cap this loop is
    /// how the agent runs out of memory.
    #[test]
    fn unfinished_frames_cannot_accumulate(frame_ids in prop::collection::vec(any::<u16>(), 64..128)) {
        let mut decoder = BleFrameDecoder::default();
        let mut refusals = 0;

        for frame_id in frame_ids {
            // One chunk of a two-chunk frame: opens a partial and never
            // completes it.
            let mut chunk = Vec::new();
            chunk.extend_from_slice(&frame_id.to_be_bytes());
            chunk.extend_from_slice(&0u16.to_be_bytes());
            chunk.extend_from_slice(&2u16.to_be_bytes());
            chunk.extend_from_slice(&[0u8; 16]);
            if decoder.add_chunk(&chunk).is_err() {
                refusals += 1;
            }
        }

        prop_assert!(refusals > 0, "partial frames accumulated without limit");
    }

    /// Chunks whose payloads add up past the frame cap must be refused before
    /// the last one arrives, not after the buffer already holds them.
    #[test]
    fn an_oversized_frame_is_refused_while_it_is_being_assembled(
        payload in 32usize..256,
    ) {
        let total = (MAX_FRAME / payload) + 2;
        prop_assume!(total <= 1024);

        let mut decoder = BleFrameDecoder::default();
        let mut refused = false;
        for index in 0..total {
            let mut chunk = Vec::new();
            chunk.extend_from_slice(&7u16.to_be_bytes());
            chunk.extend_from_slice(&(index as u16).to_be_bytes());
            chunk.extend_from_slice(&(total as u16).to_be_bytes());
            chunk.extend(std::iter::repeat_n(0u8, payload));
            if decoder.add_chunk(&chunk).is_err() {
                refused = true;
                break;
            }
        }

        prop_assert!(refused, "a frame over the cap was assembled in full");
    }
}
