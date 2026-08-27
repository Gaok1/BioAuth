/// The authenticator's half of the two-message handshake.
///
/// ```text
///   verifier (server)                        authenticator (client)
///         │  QR: session id, nonce, SHA-256(identity)  │
///         │ ─────────────  out of band  ──────────────▶│
///         │  ServerHello: bootstrap, identity, ephem.  │
///         │  ────────────  signed  ───────────────────▶│  checks the hash
///         │  ClientHello: echo, device id, identity,   │  from the QR
///         │◀──────────  ephemeral, signed  ────────────│
///      X25519 ─▶ HKDF(salt = transcript) ─▶ keys, exporter
/// ```
///
/// The reference is `ClientHandshake::respond` in
/// `desktop/crates/phone-auth-session/src/handshake.rs`, and the wire format is
/// specified in `docs/protocol-handshake.md`. Long-lived private keys never
/// enter Dart: signatures and verification are delegated to the platform
/// Keystore. Dart only owns this session's ephemeral X25519 key and the derived
/// traffic keys.
library;

import 'dart:async';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../protocol/cbor.dart';
import '../session/key_schedule.dart';
import '../session/secure_channel.dart';
import '../session/session_binding.dart';
import 'auth_transport.dart';
import 'pairing_bootstrap.dart';
import 'secure_session_establisher.dart';
import 'session_identity_crypto.dart';

const int _handshakeVersion = 1;
const int _serverHelloType = 16;
const int _clientHelloType = 17;
const int _maxHandshakeFrame = 8192;
const String _transcriptDomain = 'PhoneAuth/handshake-transcript/v1';
const Duration _helloTimeout = Duration(seconds: 15);

class HandshakeException implements Exception {
  const HandshakeException(this.message);

  final String message;

  @override
  String toString() => 'HandshakeException: $message';
}

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
  Future<SecureSessionOutcome> establish(
    RawTransportLink link,
    VerifierExpectation expectation,
  ) async {
    if (deviceId.isEmpty || deviceId.length > 64) {
      throw const HandshakeException('invalid device identifier');
    }

    final incoming = StreamIterator(link.incomingFrames);
    if (!await incoming.moveNext().timeout(_helloTimeout)) {
      throw const HandshakeException('link closed during handshake');
    }
    final (serverBody, serverSignature) = _decodeEnvelope(incoming.current);
    final server = _ServerHello.decode(serverBody);

    // Authenticate the verifier before deriving anything with its key.
    final wasPairing = switch (expectation) {
      PairedVerifier(:final identitySpki) => () {
        if (!_equal(server.identitySpki, identitySpki)) {
          throw const HandshakeException('verifier identity mismatch');
        }
        return false;
      }(),
      ScannedVerifier(:final bootstrap) => await _matchesBootstrap(
        server,
        bootstrap,
      ),
    };

    // The deadline is inside the signed hello either way, so a stale session is
    // refused whether or not a code was scanned.
    if (_clock().toUtc().millisecondsSinceEpoch >= server.expiresAtMs) {
      throw const HandshakeException('server hello has expired');
    }
    if (!await _identity.verify(
      publicKey: server.identitySpki,
      transcript: serverBody,
      signature: serverSignature,
    )) {
      throw const HandshakeException('verifier handshake signature is invalid');
    }

    final x25519 = X25519();
    final ephemeralPair = await x25519.newKeyPair();
    final ephemeral = Uint8List.fromList(
      (await ephemeralPair.extractPublicKey()).bytes,
    );
    final clientBody = _encodeClientHello(
      sessionId: server.sessionId,
      nonce: server.nonce,
      verifierId: server.verifierId,
      expiresAtMs: server.expiresAtMs,
      deviceId: deviceId,
      serverEphemeral: server.ephemeral,
      ephemeral: ephemeral,
      identitySpki: await _identity.publicKey(),
    );
    await link.send(
      _encodeEnvelope(clientBody, await _identity.sign(clientBody)),
    );

    final schedule = await KeySchedule.derive(
      sharedSecret: await x25519.sharedSecretKey(
        keyPair: ephemeralPair,
        remotePublicKey: SimplePublicKey(
          server.ephemeral,
          type: KeyPairType.x25519,
        ),
      ),
      transcriptHash: await _transcriptHash(serverBody, clientBody),
    );

    final transportName = link.rawSecurityProperties.transportName;
    final channel = SecureChannel(
      role: Role.client,
      schedule: schedule,
      binding: await deriveSessionBinding(
        SessionBindingInputs(
          transportName: transportName,
          sessionId: server.sessionId,
          serverEphemeral: server.ephemeral,
          clientEphemeral: ephemeral,
          exporter: schedule.exporter,
        ),
      ),
    );

    return SecureSessionOutcome(
      session: _EncryptedSession(
        link: link,
        channel: channel,
        incoming: incoming,
      ),
      verifierIdentitySpki: server.identitySpki,
      verifierId: server.verifierId,
      sessionId: server.sessionId,
      verificationCode: await verificationCode(schedule.exporter),
      wasPairing: wasPairing,
    );
  }

  /// Checks a first-contact hello against the scanned code, which is the only
  /// thing vouching for the verifier at this point.
  Future<bool> _matchesBootstrap(
    _ServerHello server,
    PairingBootstrap bootstrap,
  ) async {
    if (server.sessionId != bootstrap.sessionId ||
        server.verifierId != bootstrap.verifierId ||
        server.expiresAtMs != bootstrap.expiresAtMs ||
        !_equal(server.nonce, bootstrap.nonce)) {
      throw const HandshakeException(
        'server hello does not match the scanned code',
      );
    }
    if (!_equal(
      await hashIdentity(server.identitySpki),
      bootstrap.verifierIdentityHash,
    )) {
      throw const HandshakeException(
        'server hello does not match the scanned code',
      );
    }
    return true;
  }
}

class _ServerHello {
  _ServerHello({
    required this.sessionId,
    required this.nonce,
    required this.verifierId,
    required this.expiresAtMs,
    required this.identitySpki,
    required this.ephemeral,
  });

  final String sessionId;
  final Uint8List nonce;
  final String verifierId;
  final int expiresAtMs;
  final Uint8List identitySpki;
  final Uint8List ephemeral;

  /// `[16, 1, session_id, nonce, verifier_id, expires_at_ms, identity_spki,
  /// ephemeral]`
  static _ServerHello decode(Uint8List body) {
    final reader = CborReader(body);
    if (reader.array() != 8 ||
        reader.uint() != _serverHelloType ||
        reader.uint() != _handshakeVersion) {
      throw const HandshakeException('invalid server hello');
    }
    final hello = _ServerHello(
      sessionId: reader.text(),
      nonce: reader.bytes(),
      verifierId: reader.text(),
      expiresAtMs: reader.int64(),
      identitySpki: reader.bytes(),
      ephemeral: reader.bytes(),
    );
    reader.finish();
    if (hello.nonce.length != 32 || hello.ephemeral.length != 32) {
      throw const HandshakeException('invalid server hello key material');
    }
    if (hello.sessionId.isEmpty || hello.verifierId.isEmpty) {
      throw const HandshakeException('invalid server hello identifiers');
    }
    if (hello.identitySpki.isEmpty || hello.identitySpki.length > 512) {
      throw const HandshakeException('invalid verifier identity');
    }
    return hello;
  }
}

/// `[17, 1, session_id, nonce, verifier_id, expires_at_ms, device_id,
/// server_ephemeral, ephemeral, identity_spki]`
///
/// Echoing the server's ephemeral is what stops a captured ClientHello from
/// being presented to a different handshake: every handshake has a fresh
/// ephemeral, so the echo will not match.
Uint8List _encodeClientHello({
  required String sessionId,
  required Uint8List nonce,
  required String verifierId,
  required int expiresAtMs,
  required String deviceId,
  required Uint8List serverEphemeral,
  required Uint8List ephemeral,
  required Uint8List identitySpki,
}) {
  final writer = CborWriter()
    ..array(10)
    ..uint(_clientHelloType)
    ..uint(_handshakeVersion)
    ..text(sessionId)
    ..bytes(nonce)
    ..text(verifierId)
    ..int64(expiresAtMs)
    ..text(deviceId)
    ..bytes(serverEphemeral)
    ..bytes(ephemeral)
    ..bytes(identitySpki);
  return writer.takeBytes();
}

Uint8List _encodeEnvelope(Uint8List body, Uint8List signature) {
  final writer = CborWriter()
    ..array(2)
    ..bytes(body)
    ..bytes(signature);
  return writer.takeBytes();
}

(Uint8List, Uint8List) _decodeEnvelope(Uint8List frame) {
  if (frame.isEmpty || frame.length > _maxHandshakeFrame) {
    throw const HandshakeException('invalid handshake frame size');
  }
  final reader = CborReader(frame);
  if (reader.array() != 2) {
    throw const HandshakeException('invalid handshake envelope');
  }
  final body = reader.bytes();
  final signature = reader.bytes();
  reader.finish();
  return (body, signature);
}

/// Hashes both hello bodies, length-prefixed and domain-separated.
///
/// The bodies, not the envelopes: ECDSA is randomised, so including the
/// signatures would make the transcript depend on a value neither side can
/// predict, without adding anything — each body already covers the other side's
/// contribution.
Future<Uint8List> _transcriptHash(Uint8List server, Uint8List client) async {
  final input = BytesBuilder(copy: false)..add(_transcriptDomain.codeUnits);
  for (final field in [server, client]) {
    final length = ByteData(8)..setUint64(0, field.length, Endian.big);
    input
      ..add(length.buffer.asUint8List())
      ..add(field);
  }
  final digest = await Sha256().hash(input.takeBytes());
  return Uint8List.fromList(digest.bytes);
}

class _EncryptedSession implements SecureTransportSession {
  _EncryptedSession({
    required RawTransportLink link,
    required SecureChannel channel,
    required StreamIterator<Uint8List> incoming,
  }) : _link = link,
       _channel = channel,
       _handshakeFrames = incoming {
    _incoming = _remaining(
      incoming,
    ).asyncMap(_channel.open).asBroadcastStream();
  }

  final RawTransportLink _link;
  final SecureChannel _channel;

  /// The iterator the handshake read its hello through.
  ///
  /// Held so [close] can cancel it. A [StreamIterator] leaves its subscription
  /// paused between `moveNext` calls, and closing the underlying controller
  /// while a paused listener is attached never completes — which turns an
  /// ordinary hang-up into a hang.
  final StreamIterator<Uint8List> _handshakeFrames;

  late final Stream<Uint8List> _incoming;
  bool _closed = false;

  @override
  String get originLabel => '${_link.originLabel} • authenticated';

  @override
  Uint8List get sessionBinding => _channel.sessionBinding;

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
    if (_closed) throw const HandshakeException('secure session is closed');
    await _link.send(await _channel.seal(frame));
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await _handshakeFrames.cancel();
    await _link.close();
  }
}

Stream<Uint8List> _remaining(StreamIterator<Uint8List> iterator) async* {
  while (await iterator.moveNext()) {
    yield iterator.current;
  }
}

bool _equal(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var difference = 0;
  for (var index = 0; index < a.length; index++) {
    difference |= a[index] ^ b[index];
  }
  return difference == 0;
}
