/// A desktop verifier that speaks the real wire protocol over a real socket.
///
/// Written against `docs/protocol-handshake.md` and
/// `desktop/crates/phone-auth-agent/src/qr_network.rs`, not against the Dart
/// client. That is the whole value of it: an in-process shortcut would leave
/// the handshake, the framing and the record layer unexercised — which is
/// exactly where the two implementations have to agree.
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:phone_auth/core/protocol/auth_response.dart';
import 'package:phone_auth/core/protocol/application_frame.dart';
import 'package:phone_auth/core/protocol/cbor.dart';
import 'package:phone_auth/core/protocol/enrolment.dart';
import 'package:phone_auth/core/protocol/protocol_codec.dart';
import 'package:phone_auth/core/session/key_schedule.dart';
import 'package:phone_auth/core/session/secure_channel.dart';
import 'package:phone_auth/core/session/session_binding.dart';
import 'package:phone_auth/core/transport/length_prefixed_framer.dart';
import 'package:phone_auth/core/transport/pairing_bootstrap.dart';
import 'package:phone_auth/core/transport/qr_network_transport.dart';
import 'package:phone_auth/domain/authentication_request.dart';

import 'handshake_fixtures.dart';

class FakeDesktop {
  FakeDesktop._(this._socket, this.identity, this.verifierId)
    : _connections = StreamIterator(_socket);

  final ServerSocket _socket;

  /// One iterator for the life of the listener. `ServerSocket.first` would
  /// cancel the subscription — and close the listener — after one connection,
  /// and a phone reconnects for every request.
  final StreamIterator<Socket> _connections;

  final TestIdentity identity;
  final String verifierId;

  static Future<FakeDesktop> bind({String verifierId = 'desktop-1'}) async {
    return FakeDesktop._(
      await ServerSocket.bind(InternetAddress.loopbackIPv4, 0),
      await TestIdentity.create(),
      verifierId,
    );
  }

  String get endpoint => '${_socket.address.address}:${_socket.port}';

  Future<void> close() async {
    await _connections.cancel();
    await _socket.close();
  }

  /// A bootstrap committing to this desktop's identity key.
  Future<PairingBootstrap> bootstrap({
    String sessionId = 'session-1',
    Duration lifetime = const Duration(minutes: 2),
    CredentialPurpose purpose = CredentialPurpose.authorization,
  }) async => PairingBootstrap(
    purpose: purpose,
    sessionId: sessionId,
    nonce: ascendingBytes(32),
    verifierId: verifierId,
    verifierIdentityHash: await hashIdentity(await identity.publicKey()),
    endpoint: endpoint,
    expiresAtMs: DateTime.now().toUtc().add(lifetime).millisecondsSinceEpoch,
  );

  /// Accepts one connection and runs the handshake.
  Future<DesktopSession> accept(PairingBootstrap bootstrap) async {
    if (!await _connections.moveNext().timeout(const Duration(seconds: 10))) {
      throw StateError('no phone connected');
    }
    final socket = _connections.current;
    final frames = FrameReader(socket);

    final ephemeralPair = await X25519().newKeyPair();
    final ephemeral = Uint8List.fromList(
      (await ephemeralPair.extractPublicKey()).bytes,
    );
    final serverBody = serverHelloBody(
      sessionId: bootstrap.sessionId,
      nonce: bootstrap.nonce,
      verifierId: bootstrap.verifierId,
      expiresAtMs: bootstrap.expiresAtMs,
      identitySpki: await identity.publicKey(),
      ephemeral: ephemeral,
    );
    socket.add(
      encodeFrame(
        signatureEnvelope(serverBody, await identity.sign(serverBody)),
      ),
    );
    await socket.flush();

    final envelope = CborReader(await frames.next());
    if (envelope.array() != 2) throw StateError('bad envelope');
    final clientBody = envelope.bytes();
    final signature = envelope.bytes();
    envelope.finish();

    final fields = CborReader(clientBody);
    // Mirrors the verifier: both shapes are read, and only the newer one says
    // whether the phone means to pair or to resume.
    final fieldCount = fields.array();
    final carriesIntent = switch ((fieldCount, fields.uint(), fields.uint())) {
      (11, 17, 2) => true,
      (10, 17, 1) => false,
      _ => throw StateError('bad client hello'),
    };
    if (fields.text() != bootstrap.sessionId) {
      throw StateError('session id mismatch');
    }
    if (toHex(fields.bytes()) != toHex(bootstrap.nonce)) {
      throw StateError('nonce mismatch');
    }
    if (fields.text() != bootstrap.verifierId) {
      throw StateError('verifier id mismatch');
    }
    if (fields.int64() != bootstrap.expiresAtMs) {
      throw StateError('expiry mismatch');
    }
    final deviceId = fields.text();
    if (toHex(fields.bytes()) != toHex(ephemeral)) {
      // Without this echo a captured client hello could be presented to a
      // different handshake.
      throw StateError('server ephemeral echo mismatch');
    }
    final clientEphemeral = fields.bytes();
    final clientIdentity = fields.bytes();
    if (carriesIntent) fields.uint();
    fields.finish();

    if (!await identity.verify(
      publicKey: clientIdentity,
      transcript: clientBody,
      signature: signature,
    )) {
      throw StateError('client signature is invalid');
    }

    final schedule = await KeySchedule.derive(
      sharedSecret: await X25519().sharedSecretKey(
        keyPair: ephemeralPair,
        remotePublicKey: SimplePublicKey(
          clientEphemeral,
          type: KeyPairType.x25519,
        ),
      ),
      transcriptHash: await transcriptHash(serverBody, clientBody),
    );
    final binding = await deriveSessionBinding(
      SessionBindingInputs(
        transportName: qrNetworkTransportName,
        sessionId: bootstrap.sessionId,
        serverEphemeral: ephemeral,
        clientEphemeral: clientEphemeral,
        exporter: schedule.exporter,
      ),
    );

    return DesktopSession(
      socket: socket,
      frames: frames,
      channel: SecureChannel(
        role: Role.server,
        schedule: schedule,
        binding: binding,
      ),
      binding: binding,
      verificationCode: await verificationCode(schedule.exporter),
      deviceId: deviceId,
      clientIdentitySpki: clientIdentity,
    );
  }
}

class DesktopSession {
  DesktopSession({
    required this.socket,
    required FrameReader frames,
    required this.channel,
    required this.binding,
    required this.verificationCode,
    required this.deviceId,
    required this.clientIdentitySpki,
  }) : _frames = frames;

  final Socket socket;
  final FrameReader _frames;
  final SecureChannel channel;
  final Uint8List binding;
  final String verificationCode;
  final String deviceId;
  final Uint8List clientIdentitySpki;

  static const _codec = PhoneAuthProtocolCodec();

  /// Reads the enrolment a pairing phone sends immediately after the handshake.
  Future<Enrolment> readEnrolment() async =>
      Enrolment.decode(await channel.open(await _frames.next()));

  /// Reads the credential a resuming phone declares before anything else.
  ///
  /// The real desktop reads this before parking the session, because it holds
  /// one session per credential and has to know which is which. A fake that
  /// skipped it would read the attach frame as the answer to the first
  /// request, which is what this method exists to stop.
  Future<String> readAttach() async {
    final reader = CborReader(await channel.open(await _frames.next()));
    if (reader.array() != 4) throw StateError('bad attach frame');
    if (reader.uint() != 5) throw StateError('not a session attach');
    if (reader.uint() != 1) throw StateError('unknown protocol version');
    final credentialId = reader.text();
    if (reader.uint() != 0) throw StateError('reserved field is not zero');
    reader.finish();
    return credentialId;
  }

  /// Sends one authorization request and waits for the answer.
  Future<AuthResponse> requestAuthorization(
    AuthenticationRequest request,
  ) async {
    socket.add(encodeFrame(await channel.seal(_codec.encodeRequest(request))));
    await socket.flush();
    return _codec.decodeResponse(await channel.open(await _frames.next()));
  }

  Future<ApplicationFrame> requestApplication(ApplicationFrame request) async {
    socket.add(encodeFrame(await channel.seal(request.encode())));
    await socket.flush();
    return ApplicationFrame.decode(await channel.open(await _frames.next()));
  }

  Future<void> close() async => socket.destroy();
}

/// Pulls length-prefixed frames off a socket, one await at a time.
class FrameReader {
  FrameReader(Socket socket) {
    _subscription = socket.listen(
      (chunk) {
        for (final frame in _framer.addChunk(chunk)) {
          _queue.add(frame);
        }
      },
      onError: _queue.addError,
      onDone: () {
        if (!_queue.isClosed) _queue.close();
      },
    );
    _iterator = StreamIterator(_queue.stream);
  }

  final LengthPrefixedFramer _framer = LengthPrefixedFramer();
  final StreamController<Uint8List> _queue = StreamController<Uint8List>();
  late final StreamSubscription<Uint8List> _subscription;
  late final StreamIterator<Uint8List> _iterator;

  Future<Uint8List> next() async {
    if (!await _iterator.moveNext().timeout(const Duration(seconds: 10))) {
      throw StateError('the phone closed the connection');
    }
    return _iterator.current;
  }

  Future<void> cancel() => _subscription.cancel();
}
