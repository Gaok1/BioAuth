import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/transport/auth_transport.dart';
import 'package:phone_auth/core/transport/pairing_bootstrap.dart';
import 'package:phone_auth/core/transport/secure_session_establisher.dart';
import 'package:phone_auth/core/transport/usb_cable_transport.dart';

void main() {
  final identity = Uint8List.fromList(List<int>.filled(32, 7));
  const saved = TransportPeer(
    transportId: '192.168.1.50:8765',
    displayName: 'desktop-1',
  );

  UsbCableTransport build(
    _RecordingLink link, {
    List<CableLink> links = const [],
    Set<String> answering = const {},
    List<String>? probed,
  }) {
    return UsbCableTransport(
      link: link,
      links: () async => links,
      probe: (host, port, timeout) async {
        probed?.add('$host:$port');
        return answering.contains('$host:$port');
      },
    );
  }

  test('the tether interfaces are the only ones taken for a cable', () {
    expect(isUsbLinkName('rndis0'), isTrue);
    expect(isUsbLinkName('ncm0'), isTrue);
    expect(isUsbLinkName('usb0'), isTrue);

    // Sweeping either of these would be a port scan of the network the user
    // happens to be on, which is exactly what the cable exists to avoid.
    expect(isUsbLinkName('wlan0'), isFalse);
    expect(isUsbLinkName('ap0'), isFalse);
    expect(isUsbLinkName('eth0'), isFalse);
  });

  test('the search starts next to the phone and works outwards', () {
    final hosts = subnetHosts(
      const CableLink(address: '192.168.42.129', prefixLength: 24),
    );

    // The gateway hands out the address next to its own, so the computer is
    // usually the first address tried and the search costs nothing.
    expect(hosts.take(4), [
      '192.168.42.130',
      '192.168.42.128',
      '192.168.42.131',
      '192.168.42.127',
    ]);
    expect(hosts, hasLength(253));
    expect(hosts, isNot(contains('192.168.42.129')));
    expect(hosts, isNot(contains('192.168.42.0')));
    expect(hosts, isNot(contains('192.168.42.255')));
  });

  test('a link narrower than a subnet is still swept, whole', () {
    // A /30 is four addresses: network, two hosts, broadcast.
    final hosts = subnetHosts(
      const CableLink(address: '10.0.0.1', prefixLength: 30),
    );
    expect(hosts, ['10.0.0.2']);
  });

  test('a link too wide to be a cable is not swept at all', () {
    // 65k addresses is not a cable, and probing them is not a search.
    expect(
      subnetHosts(const CableLink(address: '172.16.4.9', prefixLength: 16)),
      isEmpty,
    );
  });

  test('the cable answers before the address saved at pairing', () async {
    final link = _RecordingLink(succeedsFor: {'192.168.42.130:8765'});
    final transport = build(
      link,
      links: const [CableLink(address: '192.168.42.129', prefixLength: 24)],
      answering: {'192.168.42.130:8765'},
    );

    final outcome = await transport.connect(saved, PairedVerifier(identity));

    expect(outcome.verifierId, 'desktop-1');
    expect(link.dialled, ['192.168.42.130:8765']);
  });

  test('nothing on the cable means the saved address, not a failure', () async {
    final probed = <String>[];
    final link = _RecordingLink(succeedsFor: {saved.transportId});
    final transport = build(link, probed: probed);

    await transport.connect(saved, PairedVerifier(identity));

    // No USB link at all: nothing is probed and the ordinary path is
    // untouched.
    expect(probed, isEmpty);
    expect(link.dialled, [saved.transportId]);
  });

  test(
    'an address that answers but is not the computer is not fatal',
    () async {
      final link = _RecordingLink(succeedsFor: {saved.transportId});
      final transport = build(
        link,
        links: const [CableLink(address: '192.168.42.129', prefixLength: 24)],
        answering: {'192.168.42.130:8765'},
      );

      await transport.connect(saved, PairedVerifier(identity));

      // Something accepted TCP and then failed the handshake. The saved address
      // is still tried, and the authorization still happens.
      expect(link.dialled, ['192.168.42.130:8765', saved.transportId]);
    },
  );

  test('pairing stays on the endpoint the code committed to', () async {
    final probed = <String>[];
    final link = _RecordingLink(succeedsFor: {saved.transportId});
    final transport = build(
      link,
      links: const [CableLink(address: '192.168.42.129', prefixLength: 24)],
      answering: {'192.168.42.130:8765'},
      probed: probed,
    );

    await transport.connect(saved, ScannedVerifier(_bootstrap()));

    expect(probed, isEmpty);
    expect(link.dialled, [saved.transportId]);
  });
}

PairingBootstrap _bootstrap() => PairingBootstrap(
  sessionId: 'session-1',
  nonce: Uint8List.fromList(List<int>.filled(32, 1)),
  verifierId: 'desktop-1',
  verifierIdentityHash: Uint8List.fromList(List<int>.filled(32, 2)),
  endpoint: '192.168.1.50:8765',
  expiresAtMs: DateTime.now().millisecondsSinceEpoch + 60000,
);

/// Records every endpoint dialled and answers only for the ones it was told.
class _RecordingLink implements AuthTransport {
  _RecordingLink({required this.succeedsFor});

  final Set<String> succeedsFor;
  final List<String> dialled = [];

  @override
  TransportSecurityProperties get securityProperties => _properties;

  @override
  Future<void> start() async {}

  @override
  Future<void> stop() async {}

  @override
  Stream<TransportPeer> discoverPeers() => const Stream<TransportPeer>.empty();

  @override
  Future<SecureSessionOutcome> connect(
    TransportPeer peer,
    VerifierExpectation expectation,
  ) async {
    dialled.add(peer.transportId);
    if (!succeedsFor.contains(peer.transportId)) {
      throw const SocketException('no route');
    }
    return SecureSessionOutcome(
      session: _NullSession(),
      verifierIdentitySpki: Uint8List.fromList([9]),
      verifierId: peer.displayName,
      sessionId: 'session-1',
      verificationCode: '000000',
      wasPairing: false,
    );
  }
}

class _NullSession implements SecureTransportSession {
  @override
  String get originLabel => 'test';

  @override
  Uint8List get sessionBinding => Uint8List(32);

  @override
  TransportSecurityProperties get securityProperties => _properties;

  @override
  Stream<Uint8List> get incomingFrames => const Stream<Uint8List>.empty();

  @override
  Future<void> send(Uint8List frame) async {}

  @override
  Future<void> close() async {}
}

/// The name is the half that matters: it is hashed into the session binding,
/// so the cable must report exactly what the LAN transport reports.
const TransportSecurityProperties _properties = TransportSecurityProperties(
  transportName: 'QrNetworkTransport',
  confidential: false,
  peerAuthenticated: false,
  requiresNetwork: true,
  proximitySignal: false,
  expectedLatency: Duration(milliseconds: 80),
);
