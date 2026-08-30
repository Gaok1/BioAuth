import 'dart:typed_data';

import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'phone_auth_native.dart';
import 'phone_auth_native_method_channel.dart';

abstract class PhoneAuthNativePlatform extends PlatformInterface {
  PhoneAuthNativePlatform() : super(token: _token);

  static final Object _token = Object();
  static PhoneAuthNativePlatform _instance = MethodChannelPhoneAuthNative();

  static PhoneAuthNativePlatform get instance => _instance;

  static set instance(PhoneAuthNativePlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<DevicePublicKey> generateKey({String purpose = 'authorization'}) =>
      throw UnimplementedError('generateKey() has not been implemented.');

  Future<DevicePublicKey> getPublicKey({String purpose = 'authorization'}) =>
      throw UnimplementedError('getPublicKey() has not been implemented.');

  Future<SignatureResult> sign({
    required Uint8List payload,
    required AuthenticationContext context,
    String purpose = 'authorization',
  }) => throw UnimplementedError('sign() has not been implemented.');

  Future<SecurityCapabilities> getSecurityCapabilities({
    String purpose = 'authorization',
  }) => throw UnimplementedError(
    'getSecurityCapabilities() has not been implemented.',
  );

  Future<DevicePublicKey> generateSessionIdentityKey() =>
      throw UnimplementedError(
        'generateSessionIdentityKey() has not been implemented.',
      );

  Future<DevicePublicKey> getSessionIdentityPublicKey() =>
      throw UnimplementedError(
        'getSessionIdentityPublicKey() has not been implemented.',
      );

  Future<SignatureResult> signSessionIdentity(Uint8List transcript) =>
      throw UnimplementedError(
        'signSessionIdentity() has not been implemented.',
      );

  Future<bool> verifySessionIdentity({
    required Uint8List publicKey,
    required Uint8List transcript,
    required Uint8List signature,
  }) => throw UnimplementedError(
    'verifySessionIdentity() has not been implemented.',
  );

  /// Cria a chave dedicada do File Locker, separada da chave de assinatura.
  Future<LockerKeyStatus> generateLockerKey() =>
      throw UnimplementedError('generateLockerKey() has not been implemented.');

  Future<LockerKeyStatus> getLockerKeyStatus() => throw UnimplementedError(
    'getLockerKeyStatus() has not been implemented.',
  );

  /// Embrulha a chave de dados de um container novo, atrás de biometria forte.
  ///
  /// O retorno é opaco para o computador: só este telefone o abre de volta.
  Future<Uint8List> wrapLockerKey({
    required Uint8List binding,
    required String credentialId,
    required Uint8List dataKey,
    required String fileName,
    required String verifierName,
  }) => throw UnimplementedError('wrapLockerKey() has not been implemented.');

  /// Desembrulha a chave de dados de um container existente.
  Future<Uint8List> unwrapLockerKey({
    required Uint8List binding,
    required String credentialId,
    required Uint8List wrapper,
    required String fileName,
    required String verifierName,
    bool rekeying = false,
  }) => throw UnimplementedError('unwrapLockerKey() has not been implemented.');
}
