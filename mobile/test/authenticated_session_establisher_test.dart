import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:cbor/simple.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/session/session_binding.dart';
import 'package:phone_auth/core/transport/auth_transport.dart';
import 'package:phone_auth/core/transport/authenticated_session_establisher.dart';
import 'package:phone_auth/core/transport/secure_session_establisher.dart';
import 'package:phone_auth/core/transport/session_identity_crypto.dart';

void main() {
  test('authenticated handshake encrypts both directions', () async {
    final clientIdentity = await _TestIdentity.create();
    final serverIdentity = await _TestIdentity.create();
    final serverKeys = await X25519().newKeyPair();
    final serverPublic = await serverKeys.extractPublicKey();
    final links = _links();
    final bootstrap = SessionBootstrap(
      sessionId: 'session-1',
      verifierId: 'desktop-1',
      nonce: Uint8List.fromList(List<int>.generate(32, (i) => i)),
      ephemeralPublicKey: Uint8List.fromList(serverPublic.bytes),
      verifierIdentityPublicKey: await serverIdentity.publicKey(),
      expiresAt: DateTime.utc(2026, 8, 26, 12, 1),
    );
    final establisher = AuthenticatedSessionEstablisher(
      deviceId: 'phone-1',
      identity: clientIdentity,
      clock: () => DateTime.utc(2026, 8, 26, 12),
    );

    final establishing = establisher.establish(links.mobile, bootstrap);
    final server = await _ServerPeer.handshake(
      link: links.server,
      bootstrap: bootstrap,
      identity: serverIdentity,
      serverKeys: serverKeys,
      expectedClientIdentity: await clientIdentity.publicKey(),
    );
    final mobile = await establishing;

    final fromServer = mobile.incomingFrames.first;
    await server.send(Uint8List.fromList([1, 2, 3]));
    expect(await fromServer, [1, 2, 3]);

    final fromMobile = server.receive();
    await mobile.send(Uint8List.fromList([4, 5, 6]));
    expect(await fromMobile, [4, 5, 6]);
    expect(mobile.sessionBinding, server.binding);
    expect(mobile.securityProperties.confidential, isTrue);
    expect(mobile.securityProperties.peerAuthenticated, isTrue);
  });

  test('rejects a server signature not made by the pinned verifier', () async {
    final clientIdentity = await _TestIdentity.create();
    final pinnedIdentity = await _TestIdentity.create();
    final attackerIdentity = await _TestIdentity.create();
    final serverKeys = await X25519().newKeyPair();
    final serverPublic = await serverKeys.extractPublicKey();
    final links = _links();
    final bootstrap = SessionBootstrap(
      sessionId: 'session-1',
      verifierId: 'desktop-1',
      nonce: Uint8List(32),
      ephemeralPublicKey: Uint8List.fromList(serverPublic.bytes),
      verifierIdentityPublicKey: await pinnedIdentity.publicKey(),
      expiresAt: DateTime.utc(2026, 8, 26, 12, 1),
    );
    final establishing = AuthenticatedSessionEstablisher(
      deviceId: 'phone-1',
      identity: clientIdentity,
      clock: () => DateTime.utc(2026, 8, 26, 12),
    ).establish(links.mobile, bootstrap);

    await links.server.send(await _serverHello(bootstrap, attackerIdentity));
    await expectLater(establishing, throwsStateError);
  });

  test('rejects an expired signed server hello', () async {
    final identity = await _TestIdentity.create();
    final serverIdentity = await _TestIdentity.create();
    final links = _links();
    final bootstrap = SessionBootstrap(
      sessionId: 'expired',
      verifierId: 'desktop-1',
      nonce: Uint8List(32),
      ephemeralPublicKey: Uint8List(32),
      verifierIdentityPublicKey: await serverIdentity.publicKey(),
      expiresAt: DateTime.utc(2026, 8, 26, 11, 59),
    );
    final establishing = AuthenticatedSessionEstablisher(
      deviceId: 'phone-1',
      identity: identity,
      clock: () => DateTime.utc(2026, 8, 26, 12),
    ).establish(links.mobile, bootstrap);

    await links.server.send(await _serverHello(bootstrap, serverIdentity));
    await expectLater(establishing, throwsStateError);
  });
}

class _TestIdentity implements SessionIdentityCrypto {
  _TestIdentity(this._keyPair, this._publicKey);

  final SimpleKeyPair _keyPair;
  final SimplePublicKey _publicKey;
  final Ed25519 _algorithm = Ed25519();

  static Future<_TestIdentity> create() async {
    final algorithm = Ed25519();
    final pair = await algorithm.newKeyPair();
    return _TestIdentity(pair, await pair.extractPublicKey());
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

class _ServerPeer {
  _ServerPeer({
    required this.link,
    required StreamIterator<Uint8List> incoming,
    required this.binding,
    required SecretKey sendKey,
    required SecretKey receiveKey,
  }) : _sendKey = sendKey,
       _receiveKey = receiveKey,
       _incoming = incoming;

  final _TestRawLink link;
  final Uint8List binding;
  final SecretKey _sendKey;
  final SecretKey _receiveKey;
  final StreamIterator<Uint8List> _incoming;
  final Chacha20 _cipher = Chacha20.poly1305Aead();
  int _sendCounter = 0;
  int _receiveCounter = 0;

  static Future<_ServerPeer> handshake({
    required _TestRawLink link,
    required SessionBootstrap bootstrap,
    required _TestIdentity identity,
    required KeyPair serverKeys,
    required Uint8List expectedClientIdentity,
  }) async {
    final serverUnsigned = _encode([
      16,
      1,
      bootstrap.sessionId,
      bootstrap.nonce,
      bootstrap.verifierId,
      bootstrap.ephemeralPublicKey,
      bootstrap.expiresAt!.millisecondsSinceEpoch,
    ]);
    await link.send(
      _encode([serverUnsigned, await identity.sign(serverUnsigned)]),
    );
    final incoming = StreamIterator(link.incomingFrames);
    expect(await incoming.moveNext(), isTrue);
    final clientFrame = incoming.current;
    final envelope = _decode(clientFrame);
    expect(envelope, hasLength(2));
    final clientUnsigned = _bytes(envelope[0]);
    final client = _decode(clientUnsigned);
    expect(client, hasLength(10));
    final clientIdentity = _bytes(client[8]);
    expect(clientIdentity, expectedClientIdentity);
    expect(
      await _verifyWithKey(clientIdentity, clientUnsigned, _bytes(envelope[1])),
      isTrue,
    );
    final clientEphemeral = _bytes(client[7]);
    final shared = await X25519().sharedSecretKey(
      keyPair: serverKeys,
      remotePublicKey: SimplePublicKey(
        clientEphemeral,
        type: KeyPairType.x25519,
      ),
    );
    final transcriptHash = await _hashTranscript(
      serverUnsigned,
      clientUnsigned,
    );
    final material = await Hkdf(hmac: Hmac.sha256(), outputLength: 96)
        .deriveKey(
          secretKey: shared,
          nonce: transcriptHash,
          info: utf8.encode('PhoneAuth/secure-session/v1'),
        );
    final bytes = material.bytes;
    final binding = await deriveSessionBinding(
      SessionBindingInputs(
        transportName: 'Bluetooth LE',
        sessionId: bootstrap.sessionId!,
        verifierHandshakeKey: bootstrap.ephemeralPublicKey!,
        peerHandshakeKey: clientEphemeral,
        transcriptSecret: Uint8List.fromList(bytes.sublist(64, 96)),
      ),
    );
    return _ServerPeer(
      link: link,
      incoming: incoming,
      binding: binding,
      sendKey: SecretKeyData(bytes.sublist(32, 64)),
      receiveKey: SecretKeyData(bytes.sublist(0, 32)),
    );
  }

  Future<void> send(Uint8List clear) async {
    final counter = _sendCounter++;
    final box = await _cipher.encrypt(
      clear,
      secretKey: _sendKey,
      nonce: _nonce(counter),
      aad: binding,
    );
    await link.send(
      Uint8List.fromList([
        ..._u64(counter),
        ...box.cipherText,
        ...box.mac.bytes,
      ]),
    );
  }

  Future<Uint8List> receive() async {
    expect(await _incoming.moveNext(), isTrue);
    final frame = _incoming.current;
    final counter = ByteData.sublistView(frame, 0, 8).getUint64(0);
    expect(counter, _receiveCounter++);
    return Uint8List.fromList(
      await _cipher.decrypt(
        SecretBox(
          frame.sublist(8, frame.length - 16),
          nonce: _nonce(counter),
          mac: Mac(frame.sublist(frame.length - 16)),
        ),
        secretKey: _receiveKey,
        aad: binding,
      ),
    );
  }
}

Future<bool> _verifyWithKey(
  Uint8List publicKey,
  Uint8List transcript,
  Uint8List signature,
) => Ed25519().verify(
  transcript,
  signature: Signature(
    signature,
    publicKey: SimplePublicKey(publicKey, type: KeyPairType.ed25519),
  ),
);

Future<Uint8List> _serverHello(
  SessionBootstrap bootstrap,
  _TestIdentity identity,
) async {
  final unsigned = _encode([
    16,
    1,
    bootstrap.sessionId,
    bootstrap.nonce,
    bootstrap.verifierId,
    bootstrap.ephemeralPublicKey,
    bootstrap.expiresAt!.millisecondsSinceEpoch,
  ]);
  return _encode([unsigned, await identity.sign(unsigned)]);
}

({_TestRawLink mobile, _TestRawLink server}) _links() {
  final mobileIncoming = StreamController<Uint8List>();
  final serverIncoming = StreamController<Uint8List>();
  return (
    mobile: _TestRawLink(mobileIncoming, serverIncoming),
    server: _TestRawLink(serverIncoming, mobileIncoming),
  );
}

class _TestRawLink implements RawTransportLink {
  _TestRawLink(this._incoming, this._outgoing);

  final StreamController<Uint8List> _incoming;
  final StreamController<Uint8List> _outgoing;

  @override
  Stream<Uint8List> get incomingFrames => _incoming.stream;

  @override
  String get originLabel => 'BLE test';

  @override
  TransportSecurityProperties get rawSecurityProperties =>
      const TransportSecurityProperties(
        transportName: 'Bluetooth LE',
        confidential: false,
        peerAuthenticated: false,
        requiresNetwork: false,
        proximitySignal: true,
        expectedLatency: Duration(milliseconds: 1),
      );

  @override
  Future<void> send(Uint8List frame) async {
    _outgoing.add(Uint8List.fromList(frame));
  }

  @override
  Future<void> close() async {
    await _incoming.close();
  }
}

const _cbor = CborSimpleCodec(parseDateTime: false);

Uint8List _encode(List<Object?> values) =>
    Uint8List.fromList(_cbor.encode(values));

List<Object?> _decode(Uint8List bytes) =>
    List<Object?>.from(_cbor.decode(bytes) as List);

Uint8List _bytes(Object? value) => Uint8List.fromList(value as List<int>);

Future<Uint8List> _hashTranscript(Uint8List a, Uint8List b) async =>
    Uint8List.fromList(
      (await Sha256().hash([
        ..._u64(a.length),
        ...a,
        ..._u64(b.length),
        ...b,
      ])).bytes,
    );

Uint8List _u64(int value) {
  final bytes = Uint8List(8);
  ByteData.sublistView(bytes).setUint64(0, value);
  return bytes;
}

Uint8List _nonce(int counter) {
  final bytes = Uint8List(12);
  ByteData.sublistView(bytes).setUint64(4, counter);
  return bytes;
}
