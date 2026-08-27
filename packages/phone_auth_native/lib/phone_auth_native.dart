library;

export 'phone_auth_ble.dart';

import 'package:flutter/services.dart';

import 'phone_auth_native_platform_interface.dart';

abstract interface class SecureAuthenticator {
  Future<DevicePublicKey> generateKey();

  Future<DevicePublicKey> getPublicKey();

  Future<SignatureResult> sign({
    required Uint8List payload,
    required AuthenticationContext context,
  });

  Future<bool> isHardwareBacked();

  Future<BiometricCapabilities> getBiometricCapabilities();

  Future<SecurityCapabilities> getSecurityCapabilities();
}

/// Non-exportable identity used to authenticate secure-session handshakes.
///
/// This key is deliberately separate from the biometric authorization key:
/// opening a channel must not consume or bypass an authorization operation.
abstract interface class SessionIdentity {
  Future<DevicePublicKey> generateSessionIdentityKey();

  Future<DevicePublicKey> getSessionIdentityPublicKey();

  Future<SignatureResult> signSessionIdentity(Uint8List transcript);

  Future<bool> verifySessionIdentity({
    required Uint8List publicKey,
    required Uint8List transcript,
    required Uint8List signature,
  });
}

class PhoneAuthNative implements SecureAuthenticator, SessionIdentity {
  const PhoneAuthNative();

  @override
  Future<DevicePublicKey> generateKey() =>
      PhoneAuthNativePlatform.instance.generateKey();

  @override
  Future<DevicePublicKey> getPublicKey() =>
      PhoneAuthNativePlatform.instance.getPublicKey();

  @override
  Future<SignatureResult> sign({
    required Uint8List payload,
    required AuthenticationContext context,
  }) {
    if (payload.isEmpty || payload.length > 8192) {
      throw ArgumentError.value(
        payload.length,
        'payload.length',
        'O payload canônico deve conter de 1 a 8192 bytes',
      );
    }
    return PhoneAuthNativePlatform.instance.sign(
      payload: Uint8List.fromList(payload),
      context: context,
    );
  }

  @override
  Future<bool> isHardwareBacked() async =>
      (await getSecurityCapabilities()).hardwareBacked;

  @override
  Future<BiometricCapabilities> getBiometricCapabilities() async =>
      (await getSecurityCapabilities()).biometrics;

  @override
  Future<SecurityCapabilities> getSecurityCapabilities() =>
      PhoneAuthNativePlatform.instance.getSecurityCapabilities();

  @override
  Future<DevicePublicKey> generateSessionIdentityKey() =>
      PhoneAuthNativePlatform.instance.generateSessionIdentityKey();

  @override
  Future<DevicePublicKey> getSessionIdentityPublicKey() =>
      PhoneAuthNativePlatform.instance.getSessionIdentityPublicKey();

  @override
  Future<SignatureResult> signSessionIdentity(Uint8List transcript) {
    if (transcript.isEmpty || transcript.length > 8192) {
      throw ArgumentError.value(
        transcript.length,
        'transcript.length',
        'O transcript deve conter de 1 a 8192 bytes',
      );
    }
    return PhoneAuthNativePlatform.instance.signSessionIdentity(
      Uint8List.fromList(transcript),
    );
  }

  @override
  Future<bool> verifySessionIdentity({
    required Uint8List publicKey,
    required Uint8List transcript,
    required Uint8List signature,
  }) => PhoneAuthNativePlatform.instance.verifySessionIdentity(
    publicKey: Uint8List.fromList(publicKey),
    transcript: Uint8List.fromList(transcript),
    signature: Uint8List.fromList(signature),
  );
}

class DevicePublicKey {
  DevicePublicKey({required Uint8List bytes, required this.algorithm})
    : bytes = Uint8List.fromList(bytes);

  final Uint8List bytes;
  final String algorithm;
}

class AuthenticationContext {
  const AuthenticationContext({
    required this.title,
    required this.subtitle,
    required this.description,
  });

  final String title;
  final String subtitle;
  final String description;

  Map<String, String> toMap() => {
    'title': title,
    'subtitle': subtitle,
    'description': description,
  };
}

class SignatureResult {
  SignatureResult({required Uint8List signature, required this.algorithm})
    : signature = Uint8List.fromList(signature);

  final Uint8List signature;
  final String algorithm;
}

enum BiometricAvailability {
  available,
  noneEnrolled,
  unavailable,
  temporarilyUnavailable,
  unsupported,
  unknown,
}

class BiometricCapabilities {
  const BiometricCapabilities({
    required this.availability,
    required this.strongBiometrics,
  });

  final BiometricAvailability availability;
  final bool strongBiometrics;
}

class SecurityCapabilities {
  const SecurityCapabilities({
    required this.keyExists,
    required this.hardwareBacked,
    required this.strongBoxBacked,
    required this.biometrics,
  });

  final bool keyExists;
  final bool hardwareBacked;
  final bool strongBoxBacked;
  final BiometricCapabilities biometrics;
}

class PhoneAuthBlePermissions {
  const PhoneAuthBlePermissions();

  static const _channel = MethodChannel('phone_auth_native');

  Future<bool> request() async =>
      await _channel.invokeMethod<bool>('requestBlePermissions') ?? false;
}
