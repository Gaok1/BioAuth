//! SSH encodings, against bytes an SSH implementation would accept.
//!
//! There is no negotiating these layouts. A public key blob one byte off is a
//! key the server does not recognise; a signature blob one byte off is a login
//! that fails with no useful message on either side. So the assertions here
//! are on exact bytes rather than on round-tripping — a round trip proves the
//! two halves of *this* code agree, which is precisely what is not in doubt.

use phone_auth_protocol::ssh::{
    authorized_keys_line, decode_public_key, decode_signature, encode_public_key, encode_signature,
    point_from_spki, SshReader, SshWriter, ECDSA_P256_NAME, UNCOMPRESSED_POINT_LEN,
};

/// A P-256 point with recognisable coordinates, so a mis-slice is visible in a
/// failure message rather than being a wall of similar bytes.
fn point() -> Vec<u8> {
    let mut point = vec![0x04];
    point.extend(std::iter::repeat_n(0xAA, 32));
    point.extend(std::iter::repeat_n(0xBB, 32));
    point
}

#[test]
fn a_public_key_blob_has_the_layout_openssh_reads() {
    let blob = encode_public_key(&point()).expect("a valid point");

    let mut reader = SshReader::new(&blob);
    assert_eq!(reader.text().expect("type"), "ecdsa-sha2-nistp256");
    assert_eq!(reader.text().expect("curve"), "nistp256");
    assert_eq!(reader.string().expect("point"), point().as_slice());
    reader.finish().expect("nothing trailing");

    // The exact prefix, because the field order is the part that cannot be
    // discovered by trying.
    assert_eq!(&blob[..4], &[0, 0, 0, 19], "type length");
    assert_eq!(&blob[4..23], b"ecdsa-sha2-nistp256");
}

#[test]
fn a_point_of_the_wrong_shape_is_refused() {
    assert!(encode_public_key(&[]).is_err());
    assert!(encode_public_key(&[0x04; 64]).is_err(), "too short");
    assert!(encode_public_key(&[0x04; 66]).is_err(), "too long");
    // A compressed point is a valid P-256 point and not this encoding.
    let mut compressed = vec![0x02];
    compressed.extend(std::iter::repeat_n(0xAA, 64));
    assert!(
        encode_public_key(&compressed).is_err(),
        "compressed accepted"
    );
}

/// The field this is easiest to get wrong. An `mpint` whose top bit is set
/// needs a leading zero, or a positive coordinate reads as negative and the
/// signature verifies about half the time — which looks like a flaky network.
#[test]
fn a_high_bit_coordinate_gets_its_leading_zero() {
    let mut raw = vec![0xFF; 32];
    raw.extend(std::iter::repeat_n(0x01, 32));

    let blob = encode_signature(&raw).expect("64 raw bytes");

    let mut reader = SshReader::new(&blob);
    assert_eq!(reader.text().expect("type"), ECDSA_P256_NAME);
    let inner = reader.string().expect("inner");
    reader.finish().expect("nothing trailing");

    let mut parts = SshReader::new(inner);
    let r = parts.string().expect("r");
    let s = parts.string().expect("s");
    parts.finish().expect("nothing trailing");

    assert_eq!(r.len(), 33, "a 0xFF.. coordinate needs a leading zero");
    assert_eq!(r[0], 0);
    assert_eq!(s.len(), 32, "a 0x01.. coordinate does not");
}

/// The other half of the same rule: leading zeros are stripped, because an
/// mpint carries no more bytes than it needs.
#[test]
fn leading_zeros_are_stripped_from_a_coordinate() {
    let mut raw = vec![0x00; 30];
    raw.extend([0x01, 0x02]);
    raw.extend(std::iter::repeat_n(0x03, 32));

    let blob = encode_signature(&raw).expect("64 raw bytes");
    let mut reader = SshReader::new(&blob);
    reader.text().expect("type");
    let mut parts = SshReader::new(reader.string().expect("inner"));

    assert_eq!(parts.string().expect("r"), &[0x01, 0x02]);
}

/// A signature is 64 raw bytes. Anything else is a different curve or a
/// truncated read, and signing with it would produce a login failure the user
/// has no way to diagnose.
#[test]
fn a_signature_of_the_wrong_length_is_refused() {
    for length in [0usize, 63, 65, 128] {
        assert!(
            encode_signature(&vec![0x01; length]).is_err(),
            "{length} bytes accepted"
        );
    }
}

/// Padding back to 32 bytes each is what makes a decoded signature usable
/// against a P-256 verifier, which wants fixed-width scalars.
#[test]
fn a_decoded_signature_is_padded_back_to_fixed_width() {
    let mut raw = vec![0xFF; 32];
    raw.extend(std::iter::repeat_n(0x01, 32));

    let decoded = decode_signature(&encode_signature(&raw).expect("encode")).expect("decode");

    assert_eq!(decoded, raw);
    assert_eq!(decoded.len(), 64);
}

#[test]
fn a_public_key_blob_decodes_to_the_point_that_went_in() {
    let blob = encode_public_key(&point()).expect("encode");

    assert_eq!(decode_public_key(&blob).expect("decode"), point());
}

#[test]
fn a_blob_of_another_key_type_is_refused() {
    let mut writer = SshWriter::new();
    writer.text("ssh-ed25519").text("nistp256").string(&point());

    assert!(decode_public_key(&writer.into_bytes()).is_err());
}

/// Trailing bytes are refused for the same reason every decoder in this
/// project refuses them: two byte strings that mean the same thing would be
/// two messages one signature covers.
#[test]
fn trailing_bytes_are_refused() {
    let mut blob = encode_public_key(&point()).expect("encode");
    blob.push(0);

    assert!(decode_public_key(&blob).is_err());
}

/// A length header is a number the peer chose. Reading one that claims four
/// gigabytes must fail on the input being short rather than by reserving it.
#[test]
fn a_huge_declared_length_does_not_allocate() {
    let mut frame = u32::MAX.to_be_bytes().to_vec();
    frame.extend_from_slice(b"short");

    let mut reader = SshReader::new(&frame);
    assert!(reader.string().is_err());
}

#[test]
fn a_truncated_field_is_refused_rather_than_read_short() {
    let mut frame = 8u32.to_be_bytes().to_vec();
    frame.extend_from_slice(b"only4");

    let mut reader = SshReader::new(&frame);
    assert!(reader.string().is_err());
}

/// The line a user pastes into a server. Getting it wrong is the step where
/// people give up and generate an ordinary key instead, which defeats the
/// whole point of the phone holding it.
#[test]
fn an_authorized_keys_line_has_three_fields_and_standard_base64() {
    let blob = encode_public_key(&point()).expect("encode");

    let line = authorized_keys_line(&blob, "phone@laptop");

    let fields: Vec<&str> = line.split(' ').collect();
    assert_eq!(fields.len(), 3, "line: {line}");
    assert_eq!(fields[0], "ecdsa-sha2-nistp256");
    assert_eq!(fields[2], "phone@laptop");
    // Standard base64, not base64url: `+` and `/`, and padded. The project's
    // own encoder is base64url, and the two differ in exactly the characters
    // that would make a key line look right and not work.
    assert!(
        !fields[1].contains('-'),
        "base64url leaked in: {}",
        fields[1]
    );
    assert!(
        !fields[1].contains('_'),
        "base64url leaked in: {}",
        fields[1]
    );
    assert_eq!(fields[1].len() % 4, 0, "not padded");
}

/// A comment with a newline would end the line early and turn the rest into
/// whatever the next line of `authorized_keys` means.
#[test]
fn a_comment_cannot_break_out_of_its_line() {
    let blob = encode_public_key(&point()).expect("encode");

    let line = authorized_keys_line(&blob, "phone\nssh-rsa AAAA... attacker");

    assert!(!line.contains('\n'), "a newline survived into the line");
}

/// Paired credentials store SPKI, and its tail is the point. Checked rather
/// than assumed, or a key on another curve is silently reinterpreted as this
/// one — which is a key that would never verify and no message saying why.
#[test]
fn a_point_is_taken_from_the_tail_of_an_spki() {
    let mut spki = vec![0x30, 0x59, 0x30, 0x13];
    spki.extend(point());

    assert_eq!(point_from_spki(&spki).expect("point"), point());

    let mut wrong = vec![0x30, 0x59];
    wrong.extend(std::iter::repeat_n(0x00, UNCOMPRESSED_POINT_LEN));
    assert!(point_from_spki(&wrong).is_err(), "a non-0x04 tail accepted");
    assert!(
        point_from_spki(&[0x30, 0x59]).is_err(),
        "a short SPKI accepted"
    );
}

/// An all-zero coordinate is not a signature, but the encoder must not produce
/// a malformed field for one either — a zero mpint is an empty string.
#[test]
fn a_zero_coordinate_encodes_as_an_empty_mpint() {
    let mut writer = SshWriter::new();
    writer.mpint(&[0u8; 32]);

    assert_eq!(writer.into_bytes(), vec![0, 0, 0, 0]);
}
