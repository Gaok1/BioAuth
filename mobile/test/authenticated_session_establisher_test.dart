import 'dart:async';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/protocol/cbor.dart';
import 'package:phone_auth/core/session/key_schedule.dart';
import 'package:phone_auth/core/session/secure_channel.dart';
import 'package:phone_auth/core/session/session_binding.dart';
import 'package:phone_auth/core/transport/auth_transport.dart';
import 'package:phone_auth/core/transport/authenticated_session_establisher.dart';
import 'package:phone_auth/core/transport/pairing_bootstrap.dart';
import 'package:phone_auth/core/transport/qr_network_transport.dart';
import 'package:phone_auth/core/transport/secure_session_establisher.dart';

import 'support/handshake_fixtures.dart';

void main() {
  final now = DateTime.utc(2026, 8, 26, 12);
  final expiresAtMs = now
      .add(const Duration(minutes: 1))
      .millisecondsSinceEpoch;

  Future<PairingBootstrap> bootstrapFor(
    TestIdentity verifier, {
    String sessionId = 'session-1',
    int? expiry,
  }) async => PairingBootstrap(
    sessionId: sessionId,
    nonce: ascendingBytes(32),
    verifierId: 'desktop-1',
    verifierIdentityHash: await hashIdentity(await verifier.publicKey()),
    endpoint: '192.168.1.10:8765',
    expiresAtMs: expiry ?? expiresAtMs,
  );

  test('a scanned handshake encrypts both directions', () async {
    final phone = await TestIdentity.create();
    final desktop = await TestIdentity.create();
    final bootstrap = await bootstrapFor(desktop);
    final links = testLinks();

    final establishing = AuthenticatedSessionEstablisher(
      deviceId: 'phone-1',
      identity: phone,
      clock: () => now,
    ).establish(links.phone, ScannedVerifier(bootstrap));

    final server = await _ServerPeer.handshake(
      link: links.server,
      bootstrap: bootstrap,
      identity: desktop,
      expectedPeerIdentity: await phone.publicKey(),
    );
    final outcome = await establishing;

    final fromServer = outcome.session.incomingFrames.first;
    await server.send(Uint8List.fromList([1, 2, 3]));
    expect(await fromServer, [1, 2, 3]);

    final fromPhone = server.receive();
    await outcome.session.send(Uint8List.fromList([4, 5, 6]));
    expect(await fromPhone, [4, 5, 6]);

    expect(outcome.session.sessionBinding, server.binding);
    expect(outcome.verificationCode, server.code);
    expect(outcome.verifierIdentitySpki, await desktop.publicKey());
    expect(outcome.verifierId, 'desktop-1');
    expect(outcome.sessionId, 'session-1');
    expect(outcome.wasPairing, isTrue);
    expect(outcome.session.securityProperties.confidential, isTrue);
    expect(outcome.session.securityProperties.peerAuthenticated, isTrue);
  });

  test('the client hello it sends is the encoding the desktop expects', () async {
    // Independent encoders: the fixture is written from the specification, the
    // establisher from the same specification. If they disagree, the transcript
    // differs and every derived key with it.
    final phone = await TestIdentity.create();
    final desktop = await TestIdentity.create();
    final bootstrap = await bootstrapFor(desktop);
    final links = testLinks();

    unawaited(
      AuthenticatedSessionEstablisher(
            deviceId: 'phone-1',
            identity: phone,
            clock: () => now,
          )
          .establish(links.phone, ScannedVerifier(bootstrap))
          .catchError((Object _) => throw StateError('unused')),
    );

    final serverBody = serverHelloBody(
      nonce: bootstrap.nonce,
      expiresAtMs: bootstrap.expiresAtMs,
      identitySpki: await desktop.publicKey(),
      ephemeral: repeated(0x11, 32),
    );
    await links.server.send(
      signatureEnvelope(serverBody, await desktop.sign(serverBody)),
    );

    final frame = await links.server.incomingFrames.first;
    final reader = CborReader(frame);
    expect(reader.array(), 2);
    final body = reader.bytes();

    // Everything except the phone's own fresh ephemeral is predictable.
    final fields = CborReader(body);
    expect(fields.array(), 10);
    expect(fields.uint(), 17);
    expect(fields.uint(), 1);
    expect(fields.text(), 'session-1');
    expect(fields.bytes(), bootstrap.nonce);
    expect(fields.text(), 'desktop-1');
    expect(fields.int64(), bootstrap.expiresAtMs);
    expect(fields.text(), 'phone-1');
    expect(fields.bytes(), repeated(0x11, 32), reason: 'server echo');
    expect(fields.bytes(), hasLength(32), reason: 'client ephemeral');
    expect(fields.bytes(), await phone.publicKey());
    fields.finish();
  });

  test(
    'a hello signed by a key the code does not commit to is refused',
    () async {
      final phone = await TestIdentity.create();
      final pinned = await TestIdentity.create();
      final attacker = await TestIdentity.create();
      final bootstrap = await bootstrapFor(pinned);
      final links = testLinks();

      final establishing = AuthenticatedSessionEstablisher(
        deviceId: 'phone-1',
        identity: phone,
        clock: () => now,
      ).establish(links.phone, ScannedVerifier(bootstrap));
      final refused = expectLater(
        establishing,
        throwsA(isA<HandshakeException>()),
      );

      // A relay that photographed the code can produce a well-formed hello. What
      // it cannot do is match the identity commitment the code carries.
      final body = serverHelloBody(
        nonce: bootstrap.nonce,
        expiresAtMs: bootstrap.expiresAtMs,
        identitySpki: await attacker.publicKey(),
      );
      await links.server.send(
        signatureEnvelope(body, await attacker.sign(body)),
      );

      await refused;
    },
  );

  test(
    'a hello whose fields differ from the scanned code is refused',
    () async {
      final phone = await TestIdentity.create();
      final desktop = await TestIdentity.create();
      final bootstrap = await bootstrapFor(desktop);
      final links = testLinks();

      final establishing = AuthenticatedSessionEstablisher(
        deviceId: 'phone-1',
        identity: phone,
        clock: () => now,
      ).establish(links.phone, ScannedVerifier(bootstrap));
      final refused = expectLater(
        establishing,
        throwsA(isA<HandshakeException>()),
      );

      final body = serverHelloBody(
        sessionId: 'a-different-session',
        nonce: bootstrap.nonce,
        expiresAtMs: bootstrap.expiresAtMs,
        identitySpki: await desktop.publicKey(),
      );
      await links.server.send(
        signatureEnvelope(body, await desktop.sign(body)),
      );

      await refused;
    },
  );

  test('an expired hello is refused even with a valid signature', () async {
    final phone = await TestIdentity.create();
    final desktop = await TestIdentity.create();
    final bootstrap = await bootstrapFor(
      desktop,
      expiry: now.subtract(const Duration(minutes: 1)).millisecondsSinceEpoch,
    );
    final links = testLinks();

    final establishing = AuthenticatedSessionEstablisher(
      deviceId: 'phone-1',
      identity: phone,
      clock: () => now,
    ).establish(links.phone, ScannedVerifier(bootstrap));
    final refused = expectLater(
      establishing,
      throwsA(isA<HandshakeException>()),
    );

    final body = serverHelloBody(
      nonce: bootstrap.nonce,
      expiresAtMs: bootstrap.expiresAtMs,
      identitySpki: await desktop.publicKey(),
    );
    await links.server.send(signatureEnvelope(body, await desktop.sign(body)));

    await refused;
  });

  test('a paired phone takes the session parameters from the hello', () async {
    // There is no scanned code to compare against; the stored key having
    // signed the hello is what makes its session id and nonce trustworthy.
    final phone = await TestIdentity.create();
    final desktop = await TestIdentity.create();
    final bootstrap = await bootstrapFor(desktop, sessionId: 'fresh-session');
    final links = testLinks();

    final establishing = AuthenticatedSessionEstablisher(
      deviceId: 'phone-1',
      identity: phone,
      clock: () => now,
    ).establish(links.phone, PairedVerifier(await desktop.publicKey()));

    final server = await _ServerPeer.handshake(
      link: links.server,
      bootstrap: bootstrap,
      identity: desktop,
      expectedPeerIdentity: await phone.publicKey(),
    );
    final outcome = await establishing;

    expect(outcome.sessionId, 'fresh-session');
    expect(outcome.wasPairing, isFalse);
    expect(outcome.session.sessionBinding, server.binding);
  });

  test('a paired phone refuses an identity it did not store', () async {
    final phone = await TestIdentity.create();
    final stored = await TestIdentity.create();
    final stranger = await TestIdentity.create();
    final bootstrap = await bootstrapFor(stranger);
    final links = testLinks();

    final establishing = AuthenticatedSessionEstablisher(
      deviceId: 'phone-1',
      identity: phone,
      clock: () => now,
    ).establish(links.phone, PairedVerifier(await stored.publicKey()));
    final refused = expectLater(
      establishing,
      throwsA(isA<HandshakeException>()),
    );

    final body = serverHelloBody(
      nonce: bootstrap.nonce,
      expiresAtMs: bootstrap.expiresAtMs,
      identitySpki: await stranger.publicKey(),
    );
    await links.server.send(signatureEnvelope(body, await stranger.sign(body)));

    await refused;
  });

  test('a hello with a valid body but a forged signature is refused', () async {
    final phone = await TestIdentity.create();
    final desktop = await TestIdentity.create();
    final forger = await TestIdentity.create();
    final bootstrap = await bootstrapFor(desktop);
    final links = testLinks();

    final establishing = AuthenticatedSessionEstablisher(
      deviceId: 'phone-1',
      identity: phone,
      clock: () => now,
    ).establish(links.phone, ScannedVerifier(bootstrap));
    final refused = expectLater(
      establishing,
      throwsA(isA<HandshakeException>()),
    );

    final body = serverHelloBody(
      nonce: bootstrap.nonce,
      expiresAtMs: bootstrap.expiresAtMs,
      identitySpki: await desktop.publicKey(),
    );
    await links.server.send(signatureEnvelope(body, await forger.sign(body)));

    await refused;
  });
}

/// The desktop's half, driven by hand.
class _ServerPeer {
  _ServerPeer({
    required this.binding,
    required this.code,
    required SecureChannel channel,
    required _TestRawLink link,
    required StreamIterator<Uint8List> incoming,
  }) : _channel = channel,
       _link = link,
       _incoming = incoming;

  final Uint8List binding;
  final String code;
  final SecureChannel _channel;
  final _TestRawLink _link;
  final StreamIterator<Uint8List> _incoming;

  static Future<_ServerPeer> handshake({
    required _TestRawLink link,
    required PairingBootstrap bootstrap,
    required TestIdentity identity,
    required Uint8List expectedPeerIdentity,
  }) async {
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
    await link.send(
      signatureEnvelope(serverBody, await identity.sign(serverBody)),
    );

    final incoming = StreamIterator(link.incomingFrames);
    expect(await incoming.moveNext(), isTrue);
    final envelope = CborReader(incoming.current);
    expect(envelope.array(), 2);
    final clientBody = envelope.bytes();
    final signature = envelope.bytes();
    envelope.finish();

    final fields = CborReader(clientBody);
    expect(fields.array(), 10);
    expect(fields.uint(), 17);
    expect(fields.uint(), 1);
    expect(fields.text(), bootstrap.sessionId);
    expect(fields.bytes(), bootstrap.nonce);
    expect(fields.text(), bootstrap.verifierId);
    expect(fields.int64(), bootstrap.expiresAtMs);
    fields.text(); // device id
    expect(fields.bytes(), ephemeral, reason: 'the server ephemeral echo');
    final clientEphemeral = fields.bytes();
    final clientIdentity = fields.bytes();
    fields.finish();

    expect(clientIdentity, expectedPeerIdentity);
    expect(
      await identity.verify(
        publicKey: clientIdentity,
        transcript: clientBody,
        signature: signature,
      ),
      isTrue,
    );

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

    return _ServerPeer(
      binding: binding,
      code: await verificationCode(schedule.exporter),
      channel: SecureChannel(
        role: Role.server,
        schedule: schedule,
        binding: binding,
      ),
      link: link,
      incoming: incoming,
    );
  }

  Future<void> send(Uint8List clear) async =>
      _link.send(await _channel.seal(clear));

  Future<Uint8List> receive() async {
    expect(await _incoming.moveNext(), isTrue);
    return _channel.open(_incoming.current);
  }
}

({_TestRawLink phone, _TestRawLink server}) testLinks() {
  final phoneIncoming = StreamController<Uint8List>();
  final serverIncoming = StreamController<Uint8List>();
  return (
    phone: _TestRawLink(phoneIncoming, serverIncoming),
    server: _TestRawLink(serverIncoming, phoneIncoming),
  );
}

class _TestRawLink implements RawTransportLink {
  _TestRawLink(this._incoming, this._outgoing);

  final StreamController<Uint8List> _incoming;
  final StreamController<Uint8List> _outgoing;

  @override
  Stream<Uint8List> get incomingFrames => _incoming.stream;

  @override
  String get originLabel => 'in-process test link';

  @override
  TransportSecurityProperties get rawSecurityProperties =>
      const TransportSecurityProperties(
        transportName: qrNetworkTransportName,
        confidential: false,
        peerAuthenticated: false,
        requiresNetwork: true,
        proximitySignal: false,
        expectedLatency: Duration(milliseconds: 1),
      );

  @override
  Future<void> send(Uint8List frame) async {
    _outgoing.add(Uint8List.fromList(frame));
  }

  @override
  Future<void> close() async {
    if (!_incoming.isClosed) await _incoming.close();
  }
}
