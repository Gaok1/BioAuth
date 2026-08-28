import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth_native/phone_auth_native.dart';
import 'package:phone_auth_native/phone_auth_native_method_channel.dart';
import 'package:phone_auth_native/phone_auth_native_platform_interface.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockPhoneAuthNativePlatform
    with MockPlatformInterfaceMixin
    implements PhoneAuthNativePlatform {
  @override
  Future<DevicePublicKey> generateKey() async =>
      DevicePublicKey(bytes: Uint8List.fromList([1]), algorithm: 'test');

  @override
  Future<DevicePublicKey> getPublicKey() => generateKey();

  @override
  Future<SecurityCapabilities> getSecurityCapabilities() async =>
      const SecurityCapabilities(
        keyExists: true,
        hardwareBacked: true,
        strongBoxBacked: false,
        biometrics: BiometricCapabilities(
          availability: BiometricAvailability.available,
          strongBiometrics: true,
        ),
      );

  @override
  Future<SignatureResult> sign({
    required Uint8List payload,
    required AuthenticationContext context,
  }) async => SignatureResult(
    signature: Uint8List.fromList(payload.reversed.toList()),
    algorithm: 'test',
  );

  @override
  Future<DevicePublicKey> generateSessionIdentityKey() => generateKey();

  @override
  Future<DevicePublicKey> getSessionIdentityPublicKey() => generateKey();

  @override
  Future<SignatureResult> signSessionIdentity(Uint8List transcript) async =>
      SignatureResult(
        signature: Uint8List.fromList(transcript.reversed.toList()),
        algorithm: 'test',
      );

  @override
  Future<bool> verifySessionIdentity({
    required Uint8List publicKey,
    required Uint8List transcript,
    required Uint8List signature,
  }) async => signature.length == transcript.length;

  @override
  Future<LockerKeyStatus> generateLockerKey() => getLockerKeyStatus();

  @override
  Future<LockerKeyStatus> getLockerKeyStatus() async => const LockerKeyStatus(
    keyExists: true,
    hardwareBacked: true,
    strongBoxBacked: false,
    strongBiometrics: true,
  );

  @override
  Future<Uint8List> wrapLockerKey({
    required Uint8List binding,
    required String credentialId,
    required Uint8List dataKey,
    required String fileName,
    required String verifierName,
  }) async => Uint8List.fromList(dataKey);

  @override
  Future<Uint8List> unwrapLockerKey({
    required Uint8List binding,
    required String credentialId,
    required Uint8List wrapper,
    required String fileName,
    required String verifierName,
    bool rekeying = false,
  }) async => Uint8List.fromList(wrapper);
}

void main() {
  final initialPlatform = PhoneAuthNativePlatform.instance;

  tearDown(() => PhoneAuthNativePlatform.instance = initialPlatform);

  test('$MethodChannelPhoneAuthNative is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelPhoneAuthNative>());
  });

  test('facade never accepts an empty or oversized signing payload', () async {
    PhoneAuthNativePlatform.instance = MockPhoneAuthNativePlatform();
    const authenticator = PhoneAuthNative();
    const context = AuthenticationContext(
      title: 'Verifier',
      subtitle: 'service',
      description: 'action',
    );

    expect(
      () => authenticator.sign(payload: Uint8List(0), context: context),
      throwsArgumentError,
    );
    expect(
      () => authenticator.sign(payload: Uint8List(8193), context: context),
      throwsArgumentError,
    );
    expect(await authenticator.isHardwareBacked(), isTrue);
    expect(
      () => authenticator.signSessionIdentity(Uint8List(0)),
      throwsArgumentError,
    );
  });
}
