/// Shared fixtures for the handshake tests.
///
/// The hello encoders here are written straight from
/// `docs/protocol-handshake.md` rather than reused from `lib/`. That is the
/// point: the transcript vector then checks two independent encoders against a
/// third value, instead of checking one encoder against itself.
library;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:phone_auth/core/protocol/cbor.dart';
import 'package:phone_auth/core/transport/session_identity_crypto.dart';

const String vectorSessionId = 'session-1';
const String vectorVerifierId = 'desktop-1';
const String vectorDeviceId = 'phone-1';
const int vectorExpiresAtMs = 1787745660000;

const String _transcriptDomain = 'PhoneAuth/handshake-transcript/v1';

/// 91 bytes starting at 0xa0 and wrapping, as the shared vectors specify.
final Uint8List vectorServerSpki = Uint8List.fromList(
  List<int>.generate(91, (index) => (0xa0 + index) & 0xff),
);

/// 91 bytes starting at 0x50, as the shared vectors specify.
final Uint8List vectorClientSpki = Uint8List.fromList(
  List<int>.generate(91, (index) => (0x50 + index) & 0xff),
);

final Uint8List vectorClientToServer = fromHex(
  '8dfa481719332738c6ba26756da8c2b30fa5dde7fb300c343aee6553cf655539',
);
final Uint8List vectorServerToClient = fromHex(
  '7ebbd0e4c9f0c0b1129ecb14324eeadafcf53483e85752ee6205a139f865b43c',
);
final Uint8List vectorExporter = fromHex(
  'eb2501574690d2f829f0f625cf1789e5c3203b8d402d2e6fe6fee9d911cc5522',
);

/// `[16, 1, session_id, nonce, verifier_id, expires_at_ms, identity_spki,
/// ephemeral]`
Uint8List serverHelloBody({
  String sessionId = vectorSessionId,
  Uint8List? nonce,
  String verifierId = vectorVerifierId,
  int expiresAtMs = vectorExpiresAtMs,
  Uint8List? identitySpki,
  Uint8List? ephemeral,
}) {
  final writer = CborWriter()
    ..array(8)
    ..uint(16)
    ..uint(1)
    ..text(sessionId)
    ..bytes(nonce ?? ascendingBytes(32))
    ..text(verifierId)
    ..int64(expiresAtMs)
    ..bytes(identitySpki ?? vectorServerSpki)
    ..bytes(ephemeral ?? repeated(0x11, 32));
  return writer.takeBytes();
}

/// `[17, 1, session_id, nonce, verifier_id, expires_at_ms, device_id,
/// server_ephemeral, ephemeral, identity_spki]`
Uint8List clientHelloBody({
  String sessionId = vectorSessionId,
  Uint8List? nonce,
  String verifierId = vectorVerifierId,
  int expiresAtMs = vectorExpiresAtMs,
  String deviceId = vectorDeviceId,
  Uint8List? serverEphemeral,
  Uint8List? ephemeral,
  Uint8List? identitySpki,
}) {
  final writer = CborWriter()
    ..array(10)
    ..uint(17)
    ..uint(1)
    ..text(sessionId)
    ..bytes(nonce ?? ascendingBytes(32))
    ..text(verifierId)
    ..int64(expiresAtMs)
    ..text(deviceId)
    ..bytes(serverEphemeral ?? repeated(0x11, 32))
    ..bytes(ephemeral ?? repeated(0x22, 32))
    ..bytes(identitySpki ?? vectorClientSpki);
  return writer.takeBytes();
}

Uint8List signatureEnvelope(Uint8List body, Uint8List signature) {
  final writer = CborWriter()
    ..array(2)
    ..bytes(body)
    ..bytes(signature);
  return writer.takeBytes();
}

/// `SHA-256(domain ‖ u64be(len) ‖ body ‖ u64be(len) ‖ body)`
Future<Uint8List> transcriptHash(Uint8List server, Uint8List client) async {
  final input = BytesBuilder(copy: false)..add(_transcriptDomain.codeUnits);
  for (final field in [server, client]) {
    final length = ByteData(8)..setUint64(0, field.length, Endian.big);
    input
      ..add(length.buffer.asUint8List())
      ..add(field);
  }
  return Uint8List.fromList((await Sha256().hash(input.takeBytes())).bytes);
}

/// A signing identity for tests.
///
/// Uses Ed25519 with raw public keys rather than P-256 SPKI: the handshake
/// treats identity bytes as opaque and delegates every signature operation, so
/// substituting the algorithm exercises the same code paths without needing a
/// keystore. The real algorithm is pinned on the native side.
class TestIdentity implements SessionIdentityCrypto {
  TestIdentity._(this._keyPair, this._publicKey);

  final SimpleKeyPair _keyPair;
  final SimplePublicKey _publicKey;
  static final Ed25519 _algorithm = Ed25519();

  static Future<TestIdentity> create() async {
    final pair = await _algorithm.newKeyPair();
    return TestIdentity._(pair, await pair.extractPublicKey());
  }

  @override
  Future<Uint8List> publicKey() async => Uint8List.fromList(_publicKey.bytes);

  @override
  Future<Uint8List> sign(Uint8List transcript) async => Uint8List.fromList(
    (await _algorithm.sign(transcript, keyPair: _keyPair)).bytes,
  );

  @override
  Future<bool> verify({
    required Uint8List publicKey,
    required Uint8List transcript,
    required Uint8List signature,
  }) => _algorithm.verify(
    transcript,
    signature: Signature(
      signature,
      publicKey: SimplePublicKey(publicKey, type: KeyPairType.ed25519),
    ),
  );
}

Uint8List ascendingBytes(int length) =>
    Uint8List.fromList(List<int>.generate(length, (index) => index & 0xff));

Uint8List repeated(int byte, int length) =>
    Uint8List.fromList(List<int>.filled(length, byte & 0xff));

Uint8List fromHex(String hex) {
  final bytes = Uint8List(hex.length ~/ 2);
  for (var index = 0; index < bytes.length; index++) {
    bytes[index] = int.parse(
      hex.substring(index * 2, index * 2 + 2),
      radix: 16,
    );
  }
  return bytes;
}

String toHex(List<int> bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
