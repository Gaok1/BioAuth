import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'phone_auth_native.dart';
import 'phone_auth_native_platform_interface.dart';

class MethodChannelPhoneAuthNative extends PhoneAuthNativePlatform {
  @visibleForTesting
  final methodChannel = const MethodChannel('phone_auth_native');

  @override
  Future<DevicePublicKey> generateKey() async => _publicKey(
    await methodChannel.invokeMapMethod<String, Object?>('generateKey'),
  );

  @override
  Future<DevicePublicKey> getPublicKey() async => _publicKey(
    await methodChannel.invokeMapMethod<String, Object?>('getPublicKey'),
  );

  @override
  Future<DevicePublicKey> generateSshKey() async => _publicKey(
    await methodChannel.invokeMapMethod<String, Object?>('generateSshKey'),
  );

  @override
  Future<SignatureResult> signSsh({
    required Uint8List payload,
    required AuthenticationContext context,
  }) async => _signature(
    await methodChannel.invokeMapMethod<String, Object?>('signSsh', {
      'payload': payload,
      'context': context.toMap(),
    }),
  );

  @override
  Future<DevicePublicKey> generateSessionIdentityKey() async => _publicKey(
    await methodChannel.invokeMapMethod<String, Object?>(
      'generateSessionIdentityKey',
    ),
  );

  @override
  Future<DevicePublicKey> getSessionIdentityPublicKey() async => _publicKey(
    await methodChannel.invokeMapMethod<String, Object?>(
      'getSessionIdentityPublicKey',
    ),
  );

  @override
  Future<SignatureResult> sign({
    required Uint8List payload,
    required AuthenticationContext context,
  }) async {
    final response = await methodChannel.invokeMapMethod<String, Object?>(
      'sign',
      {'payload': payload, 'context': context.toMap()},
    );
    final signature = response?['signature'];
    final algorithm = response?['algorithm'];
    if (signature is! Uint8List || algorithm is! String) {
      throw const FormatException('Resposta de assinatura nativa inválida');
    }
    return SignatureResult(signature: signature, algorithm: algorithm);
  }

  @override
  Future<SignatureResult> signSessionIdentity(Uint8List transcript) async {
    final response = await methodChannel.invokeMapMethod<String, Object?>(
      'signSessionIdentity',
      {'transcript': transcript},
    );
    return _signature(response);
  }

  @override
  Future<bool> verifySessionIdentity({
    required Uint8List publicKey,
    required Uint8List transcript,
    required Uint8List signature,
  }) async =>
      await methodChannel.invokeMethod<bool>('verifySessionIdentity', {
        'publicKey': publicKey,
        'transcript': transcript,
        'signature': signature,
      }) ??
      false;

  @override
  Future<SecurityCapabilities> getSecurityCapabilities() async {
    final response = await methodChannel.invokeMapMethod<String, Object?>(
      'getSecurityCapabilities',
    );
    if (response == null) {
      throw const FormatException('Capacidades nativas ausentes');
    }
    final availabilityName = response['biometricAvailability'];
    final availability = BiometricAvailability.values.where(
      (value) => value.name == availabilityName,
    );
    return SecurityCapabilities(
      keyExists: _bool(response, 'keyExists'),
      hardwareBacked: _bool(response, 'hardwareBacked'),
      strongBoxBacked: _bool(response, 'strongBoxBacked'),
      biometrics: BiometricCapabilities(
        availability: availability.firstOrNull ?? BiometricAvailability.unknown,
        strongBiometrics: _bool(response, 'strongBiometrics'),
      ),
    );
  }

  @override
  Future<LockerKeyStatus> generateLockerKey() async => _lockerStatus(
    await methodChannel.invokeMapMethod<String, Object?>('generateLockerKey'),
  );

  @override
  Future<LockerKeyStatus> getLockerKeyStatus() async => _lockerStatus(
    await methodChannel.invokeMapMethod<String, Object?>('lockerKeyStatus'),
  );

  @override
  Future<Uint8List> wrapLockerKey({
    required Uint8List binding,
    required String credentialId,
    required Uint8List dataKey,
    required String fileName,
    required String verifierName,
  }) async {
    final response = await methodChannel
        .invokeMapMethod<String, Object?>('lockerWrapKey', {
          'binding': binding,
          'credentialId': credentialId,
          'dataKey': dataKey,
          'fileName': fileName,
          'verifierName': verifierName,
        });
    final wrapper = response?['wrapper'];
    if (wrapper is! Uint8List || wrapper.isEmpty) {
      throw const FormatException('Wrapper de locker inválido');
    }
    return wrapper;
  }

  @override
  Future<Uint8List> unwrapLockerKey({
    required Uint8List binding,
    required String credentialId,
    required Uint8List wrapper,
    required String fileName,
    required String verifierName,
    bool rekeying = false,
  }) async {
    final response = await methodChannel
        .invokeMapMethod<String, Object?>('lockerUnwrapKey', {
          'binding': binding,
          'credentialId': credentialId,
          'wrapper': wrapper,
          'fileName': fileName,
          'verifierName': verifierName,
          'rekeying': rekeying,
        });
    final dataKey = response?['dataKey'];
    if (dataKey is! Uint8List || dataKey.length != 32) {
      throw const FormatException('Chave de locker inválida');
    }
    return dataKey;
  }

  LockerKeyStatus _lockerStatus(Map<String, Object?>? response) {
    if (response == null) {
      throw const FormatException('Estado da chave de locker ausente');
    }
    return LockerKeyStatus(
      keyExists: _bool(response, 'keyExists'),
      hardwareBacked: _bool(response, 'hardwareBacked'),
      strongBoxBacked: _bool(response, 'strongBoxBacked'),
      strongBiometrics: _bool(response, 'strongBiometrics'),
    );
  }

  DevicePublicKey _publicKey(Map<String, Object?>? response) {
    final bytes = response?['publicKey'];
    final algorithm = response?['algorithm'];
    if (bytes is! Uint8List || algorithm is! String) {
      throw const FormatException('Chave pública nativa inválida');
    }
    return DevicePublicKey(bytes: bytes, algorithm: algorithm);
  }

  SignatureResult _signature(Map<String, Object?>? response) {
    final signature = response?['signature'];
    final algorithm = response?['algorithm'];
    if (signature is! Uint8List || algorithm is! String) {
      throw const FormatException('Resposta de assinatura nativa invÃ¡lida');
    }
    return SignatureResult(signature: signature, algorithm: algorithm);
  }

  bool _bool(Map<String, Object?> response, String key) {
    final value = response[key];
    if (value is! bool) throw FormatException('Capacidade inválida: $key');
    return value;
  }
}
