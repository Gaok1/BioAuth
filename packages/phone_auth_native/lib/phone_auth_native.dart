library;

export 'phone_auth_ble.dart';

import 'package:flutter/services.dart';

import 'phone_auth_native_platform_interface.dart';

abstract interface class SecureAuthenticator {
  /// Creates, or returns, the key for one purpose.
  ///
  /// A key per purpose, not one key wearing several names: an SSH signature
  /// and a `sudo` approval cover different bytes for different verifiers, and
  /// one key for both would mean a signature made for one is a signature the
  /// other accepts.
  Future<DevicePublicKey> generateKey({String purpose = 'authorization'});

  Future<DevicePublicKey> getPublicKey({String purpose = 'authorization'});

  /// Signs with the key for [purpose], behind the biometric prompt.
  Future<SignatureResult> sign({
    required Uint8List payload,
    required AuthenticationContext context,
    String purpose = 'authorization',
  });

  Future<bool> isHardwareBacked();

  Future<BiometricCapabilities> getBiometricCapabilities();

  /// How well protected the key for [purpose] is, and what biometrics exist.
  ///
  /// Takes the purpose like everything else on this interface: there is one key
  /// per purpose, so asking about "the" key without naming one describes
  /// whichever key the default happens to be, not the one the caller means.
  Future<SecurityCapabilities> getSecurityCapabilities({
    String purpose = 'authorization',
  });
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
  Future<DevicePublicKey> generateKey({String purpose = 'authorization'}) =>
      PhoneAuthNativePlatform.instance.generateKey(purpose: purpose);

  @override
  Future<DevicePublicKey> getPublicKey({String purpose = 'authorization'}) =>
      PhoneAuthNativePlatform.instance.getPublicKey(purpose: purpose);

  @override
  Future<SignatureResult> sign({
    required Uint8List payload,
    required AuthenticationContext context,
    String purpose = 'authorization',
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
      purpose: purpose,
    );
  }

  @override
  Future<bool> isHardwareBacked() async =>
      (await getSecurityCapabilities()).hardwareBacked;

  @override
  Future<BiometricCapabilities> getBiometricCapabilities() async =>
      (await getSecurityCapabilities()).biometrics;

  @override
  Future<SecurityCapabilities> getSecurityCapabilities({
    String purpose = 'authorization',
  }) => PhoneAuthNativePlatform.instance.getSecurityCapabilities(
    purpose: purpose,
  );

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

class LockerKeyStatus {
  const LockerKeyStatus({
    required this.keyExists,
    required this.hardwareBacked,
    required this.strongBoxBacked,
    required this.strongBiometrics,
  });

  final bool keyExists;
  final bool hardwareBacked;
  final bool strongBoxBacked;
  final bool strongBiometrics;

  /// Se o telefone pode servir de guardião de chaves de locker.
  ///
  /// Uma chave que não é de hardware não protege nada contra alguém com o
  /// aparelho, e sem biometria forte não existe o gesto por uso que a `DEC-04`
  /// exige.
  bool get usable => keyExists && hardwareBacked && strongBiometrics;
}

/// A metade da chave do File Locker que o app usa.
///
/// A chave é exclusiva do locker: nunca a de assinatura, nunca a do cofre. É
/// AES-GCM no Keystore, exige biometria forte a cada uso e é invalidada quando
/// a biometria é recadastrada.
class PhoneAuthLockerKey {
  const PhoneAuthLockerKey();

  Future<LockerKeyStatus> generate() =>
      PhoneAuthNativePlatform.instance.generateLockerKey();

  Future<LockerKeyStatus> status() =>
      PhoneAuthNativePlatform.instance.getLockerKeyStatus();

  Future<Uint8List> wrap({
    required Uint8List binding,
    required String credentialId,
    required Uint8List dataKey,
    required String fileName,
    required String verifierName,
  }) => PhoneAuthNativePlatform.instance.wrapLockerKey(
    binding: Uint8List.fromList(binding),
    credentialId: credentialId,
    dataKey: Uint8List.fromList(dataKey),
    fileName: fileName,
    verifierName: verifierName,
  );

  Future<Uint8List> unwrap({
    required Uint8List binding,
    required String credentialId,
    required Uint8List wrapper,
    required String fileName,
    required String verifierName,
    bool rekeying = false,
  }) => PhoneAuthNativePlatform.instance.unwrapLockerKey(
    binding: Uint8List.fromList(binding),
    credentialId: credentialId,
    wrapper: Uint8List.fromList(wrapper),
    fileName: fileName,
    verifierName: verifierName,
    rekeying: rekeying,
  );
}

class PhoneAuthBlePermissions {
  const PhoneAuthBlePermissions();

  static const _channel = MethodChannel('phone_auth_native');

  Future<bool> request() async =>
      await _channel.invokeMethod<bool>('requestBlePermissions') ?? false;
}

class PhoneAuthBackgroundSessions {
  const PhoneAuthBackgroundSessions();

  static const _channel = MethodChannel('phone_auth_native');

  Future<bool> setEnabled(bool enabled) async =>
      await _channel.invokeMethod<bool>('setBackgroundSessionsEnabled', {
        'enabled': enabled,
      }) ??
      false;
}

/// Copies a secret in the one way Android does not put it on screen.
///
/// From Android 13 a copy raises a preview showing what was copied, and the
/// only thing that suppresses it is a flag on the `ClipData` itself. Flutter's
/// `Clipboard.setData` does not set it, so every password this app copied was
/// displayed to the room and kept in clipboard history. The flag also keeps it
/// out of a keyboard's suggestion strip, which is the longer-lived half.
class PhoneAuthClipboard {
  const PhoneAuthClipboard();

  static const _channel = MethodChannel('phone_auth_native');

  Future<void> copySensitive(String value) =>
      _channel.invokeMethod<void>('copySensitive', value);
}

class PhoneAuthWebAuthnRelay {
  const PhoneAuthWebAuthnRelay();

  static const _channel = MethodChannel('phone_auth_native');

  Future<String> perform({
    required String requestId,
    required String operation,
    required String origin,
    required String optionsJson,
  }) async {
    final response = await _channel
        .invokeMapMethod<String, Object?>('performWebAuthn', {
          'requestId': requestId,
          'operation': operation,
          'origin': origin,
          'optionsJson': optionsJson,
        });
    final json = response?['responseJson'];
    if (json is! String || json.isEmpty) {
      throw const FormatException('Invalid native WebAuthn response');
    }
    return json;
  }

  Future<void> cancel(String requestId) =>
      _channel.invokeMethod<void>('cancelWebAuthn', {'requestId': requestId});
}

enum ManagedPasskeyStatus { available, missingKey, invalidKey, orphanKey }

class ManagedPasskey {
  const ManagedPasskey({
    required this.kind,
    required this.identifier,
    required this.rpId,
    required this.userName,
    required this.userDisplayName,
    required this.createdAt,
    required this.status,
  });

  final String kind;
  final String identifier;
  final String rpId;
  final String userName;
  final String userDisplayName;
  final DateTime? createdAt;
  final ManagedPasskeyStatus status;
}

class PhoneAuthPasskeys {
  const PhoneAuthPasskeys();

  static const _channel = MethodChannel('phone_auth_native');

  Future<List<ManagedPasskey>> list() async {
    final response = await _channel.invokeListMethod<Object?>('listPasskeys');
    return (response ?? const <Object?>[])
        .map((raw) {
          if (raw is! Map) {
            throw const FormatException('Invalid passkey summary');
          }
          final map = raw.cast<Object?, Object?>();
          String string(String key) {
            final value = map[key];
            if (value is! String) {
              throw const FormatException('Invalid passkey summary');
            }
            return value;
          }

          final statusName = string('status');
          final status = ManagedPasskeyStatus.values.where(
            (value) => value.name == statusName,
          );
          final createdAtMillis = map['createdAtMillis'];
          if (createdAtMillis is! int || status.isEmpty) {
            throw const FormatException('Invalid passkey summary');
          }
          return ManagedPasskey(
            kind: string('kind'),
            identifier: string('identifier'),
            rpId: string('rpId'),
            userName: string('userName'),
            userDisplayName: string('userDisplayName'),
            createdAt: createdAtMillis == 0
                ? null
                : DateTime.fromMillisecondsSinceEpoch(
                    createdAtMillis,
                    isUtc: true,
                  ),
            status: status.first,
          );
        })
        .toList(growable: false);
  }

  Future<void> delete(ManagedPasskey passkey) async {
    final deleted = await _channel.invokeMethod<bool>('deletePasskey', {
      'kind': passkey.kind,
      'identifier': passkey.identifier,
    });
    if (deleted != true) throw const FormatException('Passkey was not deleted');
  }
}
