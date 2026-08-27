import 'package:flutter/services.dart';

class PhoneAuthBle {
  const PhoneAuthBle();

  static const _methods = MethodChannel('phone_auth_native');
  static const _scanEvents = EventChannel('phone_auth_native/ble_scan');
  static const _connectionEvents = EventChannel('phone_auth_native/ble_events');

  Stream<BleScanResult> get scanResults => _scanEvents
      .receiveBroadcastStream()
      .map((event) => BleScanResult.fromMap(_map(event)));

  Stream<BleEvent> get events => _connectionEvents.receiveBroadcastStream().map(
    (event) => BleEvent.fromMap(_map(event)),
  );

  Future<void> startScan({required String serviceUuid}) =>
      _methods.invokeMethod<void>('bleStartScan', {'serviceUuid': serviceUuid});

  Future<void> stopScan() => _methods.invokeMethod<void>('bleStopScan');

  Future<void> connect({
    required String connectionId,
    required String serviceUuid,
    required String requestCharacteristicUuid,
    required String responseCharacteristicUuid,
  }) => _methods.invokeMethod<void>('bleConnect', {
    'connectionId': connectionId,
    'serviceUuid': serviceUuid,
    'requestCharacteristicUuid': requestCharacteristicUuid,
    'responseCharacteristicUuid': responseCharacteristicUuid,
  });

  Future<int> requestMtu(int mtu) async =>
      await _methods.invokeMethod<int>('bleRequestMtu', {'mtu': mtu}) ?? 23;

  Future<void> write(Uint8List value) =>
      _methods.invokeMethod<void>('bleWrite', {'value': value});

  Future<void> disconnect() => _methods.invokeMethod<void>('bleDisconnect');

  static Map<Object?, Object?> _map(Object? value) {
    if (value is! Map<Object?, Object?>) {
      throw const FormatException('Evento BLE nativo inválido');
    }
    return value;
  }
}

class BleScanResult {
  const BleScanResult({
    required this.connectionId,
    required this.name,
    required this.rssi,
  });

  factory BleScanResult.fromMap(Map<Object?, Object?> map) {
    final connectionId = map['connectionId'];
    final name = map['name'];
    final rssi = map['rssi'];
    if (connectionId is! String || name is! String || rssi is! int) {
      throw const FormatException('Resultado de scan BLE inválido');
    }
    return BleScanResult(connectionId: connectionId, name: name, rssi: rssi);
  }

  final String connectionId;
  final String name;
  final int rssi;
}

sealed class BleEvent {
  const BleEvent();

  factory BleEvent.fromMap(Map<Object?, Object?> map) {
    return switch (map['type']) {
      'notification' => BleNotification(_bytes(map['value'])),
      'disconnected' => const BleDisconnected(),
      _ => throw const FormatException('Tipo de evento BLE inválido'),
    };
  }

  static Uint8List _bytes(Object? value) {
    if (value is! Uint8List) {
      throw const FormatException('Notificação BLE inválida');
    }
    return Uint8List.fromList(value);
  }
}

class BleNotification extends BleEvent {
  BleNotification(Uint8List value) : value = Uint8List.fromList(value);

  final Uint8List value;
}

class BleDisconnected extends BleEvent {
  const BleDisconnected();
}
