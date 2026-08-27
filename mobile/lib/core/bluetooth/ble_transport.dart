import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:phone_auth_native/phone_auth_native.dart';

import '../transport/auth_transport.dart';
import '../transport/secure_session_establisher.dart';
import 'ble_frame_codec.dart';

/// Both sides must report this exact string: it is hashed into the session
/// binding, so a mismatch makes every request fail with no other symptom.
const String bleTransportName = 'BleTransport';

class BleTransport implements AuthTransport {
  BleTransport({
    required SecureSessionEstablisher sessionEstablisher,
    BleClient? client,
    BlePermissionGate? permissionGate,
  }) : _sessionEstablisher = sessionEstablisher,
       _client = client ?? NativeBleClient(),
       _permissionGate = permissionGate ?? const NativeBlePermissionGate();

  final SecureSessionEstablisher _sessionEstablisher;
  final BleClient _client;
  final BlePermissionGate _permissionGate;
  final _peers = StreamController<TransportPeer>.broadcast();
  StreamSubscription<BlePeer>? _scanSubscription;

  @override
  TransportSecurityProperties get securityProperties =>
      const TransportSecurityProperties(
        // Hashed into the session binding, so it must be the exact string the
        // desktop reports. See docs/protocol-handshake.md.
        transportName: bleTransportName,
        confidential: false,
        peerAuthenticated: false,
        requiresNetwork: false,
        proximitySignal: true,
        expectedLatency: Duration(milliseconds: 250),
      );

  @override
  Future<void> start() async {
    if (_scanSubscription != null) return;
    if (!await _permissionGate.ensureGranted()) {
      throw StateError('Permissão Bluetooth negada');
    }
    _scanSubscription = _client.scan().listen(
      (peer) => _peers.add(
        TransportPeer(
          transportId: peer.connectionId,
          displayName: peer.displayName,
        ),
      ),
      onError: _peers.addError,
    );
  }

  @override
  Future<void> stop() async {
    await _scanSubscription?.cancel();
    _scanSubscription = null;
  }

  @override
  Stream<TransportPeer> discoverPeers() => _peers.stream;

  @override
  Future<SecureSessionOutcome> connect(
    TransportPeer peer,
    VerifierExpectation expectation,
  ) async {
    final rawLink = await _client.connect(peer.transportId);
    try {
      return await _sessionEstablisher.establish(rawLink, expectation);
    } on Object {
      await rawLink.close();
      rethrow;
    }
  }
}

abstract interface class BlePermissionGate {
  Future<bool> ensureGranted();
}

class NativeBlePermissionGate implements BlePermissionGate {
  const NativeBlePermissionGate({
    PhoneAuthBlePermissions permissions = const PhoneAuthBlePermissions(),
  }) : _permissions = permissions;

  final PhoneAuthBlePermissions _permissions;

  @override
  Future<bool> ensureGranted() async {
    if (defaultTargetPlatform != TargetPlatform.android) return true;
    return _permissions.request();
  }
}

class BlePeer {
  const BlePeer({required this.connectionId, required this.displayName});

  final String connectionId;
  final String displayName;
}

abstract interface class BleClient {
  Stream<BlePeer> scan();

  Future<RawTransportLink> connect(String connectionId);
}

class NativeBleClient implements BleClient {
  NativeBleClient({PhoneAuthBle? ble}) : _ble = ble ?? const PhoneAuthBle();

  final PhoneAuthBle _ble;

  static const serviceId = '7e57a001-b5a3-4d2f-9f55-41f0dd2f4e41';
  static const requestCharacteristicId = '7e57a002-b5a3-4d2f-9f55-41f0dd2f4e41';
  static const responseCharacteristicId =
      '7e57a003-b5a3-4d2f-9f55-41f0dd2f4e41';

  @override
  Stream<BlePeer> scan() async* {
    await _ble.startScan(serviceUuid: serviceId);
    try {
      await for (final device in _ble.scanResults) {
        yield BlePeer(
          connectionId: device.connectionId,
          displayName: device.name.isEmpty ? 'PhoneAuth verifier' : device.name,
        );
      }
    } finally {
      await _ble.stopScan();
    }
  }

  @override
  Future<RawTransportLink> connect(String connectionId) async {
    await _ble.connect(
      connectionId: connectionId,
      serviceUuid: serviceId,
      requestCharacteristicUuid: requestCharacteristicId,
      responseCharacteristicUuid: responseCharacteristicId,
    );
    final mtu = await _ble.requestMtu(247).catchError((_) => 23);
    return _NativeBleLink(ble: _ble, mtu: mtu);
  }
}

class _NativeBleLink implements RawTransportLink {
  _NativeBleLink({required PhoneAuthBle ble, required int mtu})
    : _ble = ble,
      _attPayloadBytes = (mtu - 3).clamp(20, 244) {
    _events = _ble.events.listen((event) {
      if (event case BleNotification(:final value)) {
        final frame = _codec.addChunk(value);
        if (frame != null) _incoming.add(frame);
      } else if (event is BleDisconnected && !_incoming.isClosed) {
        _incoming.close();
      }
    }, onError: _incoming.addError);
  }

  final PhoneAuthBle _ble;
  final int _attPayloadBytes;
  final BleFrameCodec _codec = BleFrameCodec();
  final StreamController<Uint8List> _incoming = StreamController<Uint8List>();
  late final StreamSubscription<BleEvent> _events;
  bool _closed = false;

  @override
  String get originLabel => 'Bluetooth LE • secure handshake required';

  @override
  TransportSecurityProperties get rawSecurityProperties =>
      const TransportSecurityProperties(
        // Hashed into the session binding, so it must be the exact string the
        // desktop reports. See docs/protocol-handshake.md.
        transportName: bleTransportName,
        confidential: false,
        peerAuthenticated: false,
        requiresNetwork: false,
        proximitySignal: true,
        expectedLatency: Duration(milliseconds: 250),
      );

  @override
  Stream<Uint8List> get incomingFrames => _incoming.stream;

  @override
  Future<void> send(Uint8List frame) async {
    if (_closed) throw StateError('BLE link is closed');
    for (final chunk in _codec.encode(
      frame,
      attPayloadBytes: _attPayloadBytes,
    )) {
      await _ble.write(chunk);
    }
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await _events.cancel();
    await _ble.disconnect();
    if (!_incoming.isClosed) await _incoming.close();
  }
}
