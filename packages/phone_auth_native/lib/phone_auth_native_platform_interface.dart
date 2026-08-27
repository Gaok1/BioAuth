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

  Future<DevicePublicKey> generateKey() =>
      throw UnimplementedError('generateKey() has not been implemented.');

  Future<DevicePublicKey> getPublicKey() =>
      throw UnimplementedError('getPublicKey() has not been implemented.');

  Future<SignatureResult> sign({
    required Uint8List payload,
    required AuthenticationContext context,
  }) => throw UnimplementedError('sign() has not been implemented.');

  Future<SecurityCapabilities> getSecurityCapabilities() =>
      throw UnimplementedError(
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
}
