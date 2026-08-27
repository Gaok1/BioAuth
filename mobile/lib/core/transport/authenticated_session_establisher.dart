import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:cbor/simple.dart';
import 'package:cryptography/cryptography.dart';

import '../session/session_binding.dart';
import 'auth_transport.dart';
import 'secure_session_establisher.dart';
import 'session_identity_crypto.dart';

const _protocolVersion = 1;
const _serverHelloType = 16;
const _clientHelloType = 17;
const _kdfDomain = 'PhoneAuth/secure-session/v1';
const _maxHandshakeLifetime = Duration(minutes: 2);

/// Authenticated ephemeral X25519 handshake with pinned P-256 identities.
///
/// Long-lived private keys never enter Dart: signatures and verification are
/// delegated to the platform Keystore. Dart only owns this session's ephemeral
/// X25519 key and derived traffic keys.
class AuthenticatedSessionEstablisher implements SecureSessionEstablisher {
  AuthenticatedSessionEstablisher({
    required this.deviceId,
    required SessionIdentityCrypto identity,
    DateTime Function()? clock,
  }) : _identity = identity,
       _clock = clock ?? DateTime.now;

  final String deviceId;
  final SessionIdentityCrypto _identity;
  final DateTime Function() _clock;

  @override
  Future<SecureTransportSession> establish(
    RawTransportLink link,
    SessionBootstrap bootstrap,
  ) async {
    if (deviceId.isEmpty) throw StateError('Device identity is missing');

    final incoming = StreamIterator(link.incomingFrames);
    final hasServerHello = await incoming.moveNext().timeout(
      const Duration(seconds: 15),
    );
    if (!hasServerHello) {
      throw StateError('Secure-session link closed during handshake');
    }
    final serverFrame = incoming.current;
    final server = _ServerHello.decode(serverFrame);
    server.validateAgainst(bootstrap);
    if (!await _identity.verify(
      publicKey: bootstrap.verifierIdentityPublicKey,
      transcript: server.unsigned,
      signature: server.signature,
    )) {
      throw StateError('Verifier handshake signature is invalid');
    }
    final now = _clock().toUtc();
    if (!now.isBefore(server.expiresAt) ||
        server.expiresAt.isAfter(now.add(_maxHandshakeLifetime))) {
      throw StateError('Secure-session server hello expired');
    }

    final x25519 = X25519();
    final clientKeyPair = await x25519.newKeyPair();
    final clientPublicKey = await clientKeyPair.extractPublicKey();
    final identityPublicKey = await _identity.publicKey();
    final clientUnsigned = _ClientHello.unsignedBytes(
      server: server,
      deviceId: deviceId,
      clientEphemeralKey: Uint8List.fromList(clientPublicKey.bytes),
      clientIdentityKey: identityPublicKey,
    );
    final clientSignature = await _identity.sign(clientUnsigned);
    await link.send(_ClientHello.encode(clientUnsigned, clientSignature));

    final sharedSecret = await x25519.sharedSecretKey(
      keyPair: clientKeyPair,
      remotePublicKey: SimplePublicKey(
        server.ephemeralKey,
        type: KeyPairType.x25519,
      ),
    );
    final transcriptHash = await _transcriptHash(
      server.unsigned,
      clientUnsigned,
    );
    final keyMaterial = await Hkdf(hmac: Hmac.sha256(), outputLength: 96)
        .deriveKey(
          secretKey: sharedSecret,
          nonce: transcriptHash,
          info: utf8.encode(_kdfDomain),
        );
    final bytes = keyMaterial.bytes;
    final binding = await deriveSessionBinding(
      SessionBindingInputs(
        transportName: link.rawSecurityProperties.transportName,
        sessionId: server.sessionId,
        verifierHandshakeKey: server.ephemeralKey,
        peerHandshakeKey: Uint8List.fromList(clientPublicKey.bytes),
        transcriptSecret: Uint8List.fromList(bytes.sublist(64, 96)),
      ),
    );
    return _EncryptedSession(
      link: link,
      incoming: _remaining(incoming),
      binding: binding,
      sendKey: SecretKeyData(bytes.sublist(0, 32)),
      receiveKey: SecretKeyData(bytes.sublist(32, 64)),
    );
  }
}

class _ServerHello {
  _ServerHello({
    required this.sessionId,
    required this.nonce,
    required this.verifierId,
    required this.ephemeralKey,
    required this.expiresAt,
    required this.unsigned,
    required this.signature,
  });

  final String sessionId;
  final Uint8List nonce;
  final String verifierId;
  final Uint8List ephemeralKey;
  final DateTime expiresAt;
  final Uint8List unsigned;
  final Uint8List signature;

  static _ServerHello decode(Uint8List frame) {
    final envelope = _decodeList(frame, 2);
    final unsigned = _bytes(envelope[0]);
    final signature = _bytes(envelope[1]);
    if (!_equal(frame, _encode([unsigned, signature]))) {
      throw const FormatException('Non-canonical server hello envelope');
    }
    final values = _decodeList(unsigned, 7);
    if (_integer(values[0]) != _serverHelloType ||
        _integer(values[1]) != _protocolVersion) {
      throw const FormatException('Unsupported secure-session server hello');
    }
    final sessionId = _string(values[2]);
    final nonce = _bytes(values[3]);
    final verifierId = _string(values[4]);
    final ephemeralKey = _bytes(values[5]);
    final expiresAt = DateTime.fromMillisecondsSinceEpoch(
      _integer(values[6]),
      isUtc: true,
    );
    if (!_equal(
      unsigned,
      _encode([
        _serverHelloType,
        _protocolVersion,
        sessionId,
        nonce,
        verifierId,
        ephemeralKey,
        expiresAt.millisecondsSinceEpoch,
      ]),
    )) {
      throw const FormatException('Non-canonical server hello transcript');
    }
    return _ServerHello(
      sessionId: sessionId,
      nonce: nonce,
      verifierId: verifierId,
      ephemeralKey: ephemeralKey,
      expiresAt: expiresAt,
      unsigned: unsigned,
      signature: signature,
    );
  }

  void validateAgainst(SessionBootstrap bootstrap) {
    final expectedNonce = bootstrap.nonce;
    final expectedEphemeral = bootstrap.ephemeralPublicKey;
    if (verifierId != bootstrap.verifierId ||
        ephemeralKey.length != 32 ||
        (bootstrap.sessionId != null && sessionId != bootstrap.sessionId) ||
        (expectedNonce != null && !_equal(nonce, expectedNonce)) ||
        (expectedEphemeral != null &&
            !_equal(ephemeralKey, expectedEphemeral)) ||
        (bootstrap.expiresAt != null &&
            expiresAt != bootstrap.expiresAt!.toUtc())) {
      throw StateError('Server hello does not match the trusted bootstrap');
    }
  }
}

class _ClientHello {
  static Uint8List unsignedBytes({
    required _ServerHello server,
    required String deviceId,
    required Uint8List clientEphemeralKey,
    required Uint8List clientIdentityKey,
  }) => _encode([
    _clientHelloType,
    _protocolVersion,
    server.sessionId,
    server.nonce,
    server.verifierId,
    deviceId,
    server.ephemeralKey,
    clientEphemeralKey,
    clientIdentityKey,
    server.expiresAt.millisecondsSinceEpoch,
  ]);

  static Uint8List encode(Uint8List unsigned, Uint8List signature) {
    return _encode([unsigned, signature]);
  }
}

class _EncryptedSession implements SecureTransportSession {
  _EncryptedSession({
    required RawTransportLink link,
    required Stream<Uint8List> incoming,
    required Uint8List binding,
    required SecretKey sendKey,
    required SecretKey receiveKey,
  }) : _link = link,
       _binding = Uint8List.fromList(binding),
       _sendKey = sendKey,
       _receiveKey = receiveKey {
    _incoming = incoming.asyncMap(_decrypt).asBroadcastStream();
  }

  final RawTransportLink _link;
  final Uint8List _binding;
  final SecretKey _sendKey;
  final SecretKey _receiveKey;
  late final Stream<Uint8List> _incoming;
  final Chacha20 _cipher = Chacha20.poly1305Aead();
  int _sendCounter = 0;
  int _receiveCounter = 0;
  bool _closed = false;

  @override
  String get originLabel => '${_link.originLabel} â€¢ authenticated';

  @override
  Uint8List get sessionBinding => Uint8List.fromList(_binding);

  @override
  TransportSecurityProperties get securityProperties =>
      TransportSecurityProperties(
        transportName: _link.rawSecurityProperties.transportName,
        confidential: true,
        peerAuthenticated: true,
        requiresNetwork: _link.rawSecurityProperties.requiresNetwork,
        proximitySignal: _link.rawSecurityProperties.proximitySignal,
        expectedLatency: _link.rawSecurityProperties.expectedLatency,
      );

  @override
  Stream<Uint8List> get incomingFrames => _incoming;

  @override
  Future<void> send(Uint8List frame) async {
    if (_closed) throw StateError('Secure session is closed');
    final counter = _sendCounter++;
    final nonce = _nonce(counter);
    final box = await _cipher.encrypt(
      frame,
      secretKey: _sendKey,
      nonce: nonce,
      aad: _binding,
    );
    final encoded = BytesBuilder(copy: false)
      ..add(_counterBytes(counter))
      ..add(box.cipherText)
      ..add(box.mac.bytes);
    await _link.send(encoded.takeBytes());
  }

  Future<Uint8List> _decrypt(Uint8List frame) async {
    if (frame.length < 24) {
      throw const FormatException('Truncated secure frame');
    }
    final counter = ByteData.sublistView(frame, 0, 8).getUint64(0);
    if (counter != _receiveCounter) {
      throw StateError('Replayed or out-of-order secure frame');
    }
    final clear = await _cipher.decrypt(
      SecretBox(
        frame.sublist(8, frame.length - 16),
        nonce: _nonce(counter),
        mac: Mac(frame.sublist(frame.length - 16)),
      ),
      secretKey: _receiveKey,
      aad: _binding,
    );
    _receiveCounter++;
    return Uint8List.fromList(clear);
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await _link.close();
  }
}

Stream<Uint8List> _remaining(StreamIterator<Uint8List> iterator) async* {
  while (await iterator.moveNext()) {
    yield iterator.current;
  }
}

Future<Uint8List> _transcriptHash(Uint8List first, Uint8List second) async {
  final bytes = BytesBuilder(copy: false)
    ..add(_counterBytes(first.length))
    ..add(first)
    ..add(_counterBytes(second.length))
    ..add(second);
  return Uint8List.fromList((await Sha256().hash(bytes.takeBytes())).bytes);
}

Uint8List _nonce(int counter) {
  final nonce = Uint8List(12);
  ByteData.sublistView(nonce).setUint64(4, counter);
  return nonce;
}

Uint8List _counterBytes(int value) {
  final bytes = Uint8List(8);
  ByteData.sublistView(bytes).setUint64(0, value);
  return bytes;
}

const _cbor = CborSimpleCodec(parseDateTime: false);

Uint8List _encode(List<Object?> values) =>
    Uint8List.fromList(_cbor.encode(values));

List<Object?> _decodeList(Uint8List frame, int length) {
  if (frame.isEmpty || frame.length > 8192) {
    throw const FormatException('Invalid handshake frame size');
  }
  final decoded = _cbor.decode(frame);
  if (decoded is! List || decoded.length != length) {
    throw const FormatException('Invalid handshake frame');
  }
  final values = List<Object?>.from(decoded);
  return values;
}

int _integer(Object? value) {
  if (value is! int) throw const FormatException('Expected integer');
  return value;
}

String _string(Object? value) {
  if (value is! String || value.isEmpty) {
    throw const FormatException('Expected non-empty string');
  }
  return value;
}

Uint8List _bytes(Object? value) {
  if (value is Uint8List) return Uint8List.fromList(value);
  if (value is List<int>) return Uint8List.fromList(value);
  throw const FormatException('Expected byte string');
}

bool _equal(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var difference = 0;
  for (var i = 0; i < a.length; i++) {
    difference |= a[i] ^ b[i];
  }
  return difference == 0;
}
