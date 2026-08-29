/// Session attach: which credential the phone opened this session with.
///
/// A paired phone runs one connection per credential, because the credential a
/// session was opened with decides which key signs on it — a desktop naming a
/// different credential in a request is refused rather than served from another
/// key. So the desktop has to know which of the phone's sessions is which
/// before it picks one to send a request down. Without it a vault request went
/// out over the login session about as often as not, and came back as a denial
/// nobody made.
///
/// Sent immediately after a *non-pairing* handshake, inside the encrypted
/// channel. It is a routing hint and nothing more: it grants no authority, and
/// naming a credential this phone does not hold only arranges for requests it
/// will refuse. Mirrors `desktop/crates/phone-auth-protocol/src/attach.rs`.
library;

import 'dart:typed_data';

import 'cbor.dart';

const int _attachType = 5;
const int _protocolVersion = 1;
const int _attachFrameLength = 4;

class SessionAttach {
  const SessionAttach({required this.credentialId});

  final String credentialId;

  Uint8List encode() {
    if (credentialId.isEmpty || credentialId.length > 64) {
      throw ArgumentError.value(
        credentialId,
        'credentialId',
        'a session attach names exactly one credential',
      );
    }
    final writer = CborWriter()
      ..array(_attachFrameLength)
      ..uint(_attachType)
      ..uint(_protocolVersion)
      ..text(credentialId)
      // Reserved for a future field; keeping the arity fixed means adding one
      // is a version bump rather than a silent shape change.
      ..uint(0);
    return writer.takeBytes();
  }
}
