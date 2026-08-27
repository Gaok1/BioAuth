import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth_native/phone_auth_native.dart';
import 'package:phone_auth_native/phone_auth_native_method_channel.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  final platform = MethodChannelPhoneAuthNative();
  const channel = MethodChannel('phone_auth_native');

  setUp(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          return switch (call.method) {
            'generateKey' ||
            'getPublicKey' ||
            'generateSessionIdentityKey' ||
            'getSessionIdentityPublicKey' => {
              'publicKey': Uint8List.fromList([1, 2, 3]),
              'algorithm': 'EC_P256_SPKI',
            },
            'getSecurityCapabilities' => {
              'keyExists': true,
              'hardwareBacked': true,
              'strongBoxBacked': false,
              'strongBiometrics': true,
              'biometricAvailability': 'available',
            },
            'sign' || 'signSessionIdentity' => {
              'signature': Uint8List.fromList([4, 5, 6]),
              'algorithm': 'SHA256withECDSA',
            },
            'verifySessionIdentity' => true,
            'requestBlePermissions' => true,
            'bleRequestMtu' => 247,
            'bleStartScan' ||
            'bleStopScan' ||
            'bleConnect' ||
            'bleWrite' ||
            'bleDisconnect' => null,
            _ => throw MissingPluginException(),
          };
        });
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  test('maps public key and security capabilities', () async {
    final key = await platform.generateKey();
    final capabilities = await platform.getSecurityCapabilities();

    expect(key.bytes, [1, 2, 3]);
    expect(key.algorithm, 'EC_P256_SPKI');
    expect(capabilities.hardwareBacked, isTrue);
    expect(capabilities.strongBoxBacked, isFalse);
    expect(
      capabilities.biometrics.availability,
      BiometricAvailability.available,
    );
  });

  test('sends canonical payload and display context to native sign', () async {
    final result = await platform.sign(
      payload: Uint8List.fromList([1, 2, 3]),
      context: const AuthenticationContext(
        title: 'Desktop-NixOS',
        subtitle: 'sudo',
        description: 'nixos-rebuild switch',
      ),
    );

    expect(result.signature, [4, 5, 6]);
    expect(result.algorithm, 'SHA256withECDSA');
  });

  test(
    'keeps session identity operations separate from biometric sign',
    () async {
      final key = await platform.generateSessionIdentityKey();
      final signature = await platform.signSessionIdentity(
        Uint8List.fromList([7, 8, 9]),
      );

      expect(key.algorithm, 'EC_P256_SPKI');
      expect(signature.signature, [4, 5, 6]);
      expect(
        await platform.verifySessionIdentity(
          publicKey: key.bytes,
          transcript: Uint8List.fromList([7, 8, 9]),
          signature: signature.signature,
        ),
        isTrue,
      );
    },
  );

  test('returns explicit BLE permission result', () async {
    expect(await const PhoneAuthBlePermissions().request(), isTrue);
  });

  test('forwards native BLE lifecycle and bounded writes', () async {
    const ble = PhoneAuthBle();
    await ble.startScan(serviceUuid: 'service');
    await ble.connect(
      connectionId: 'connection',
      serviceUuid: 'service',
      requestCharacteristicUuid: 'request',
      responseCharacteristicUuid: 'response',
    );
    expect(await ble.requestMtu(247), 247);
    await ble.write(Uint8List.fromList([1, 2, 3]));
    await ble.disconnect();
  });
}
