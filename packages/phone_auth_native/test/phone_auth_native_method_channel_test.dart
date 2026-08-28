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
            'setBackgroundSessionsEnabled' => true,
            'performWebAuthn' => {'responseJson': '{"id":"credential"}'},
            'cancelWebAuthn' => null,
            'listPasskeys' => [
              {
                'kind': 'credential',
                'identifier': 'AQ',
                'rpId': 'example.com',
                'userName': 'alice',
                'userDisplayName': 'Alice',
                'createdAtMillis': 1787875200000,
                'status': 'available',
              },
            ],
            'deletePasskey' => true,
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

  test('controls the persistent background session service', () async {
    expect(await const PhoneAuthBackgroundSessions().setEnabled(true), isTrue);
  });

  test('forwards a desktop WebAuthn operation to Android', () async {
    expect(
      await const PhoneAuthWebAuthnRelay().perform(
        requestId: 'request-1',
        operation: 'get',
        origin: 'https://example.com',
        optionsJson: '{}',
      ),
      '{"id":"credential"}',
    );
    await const PhoneAuthWebAuthnRelay().cancel('request-1');
  });

  test('lists and deletes managed passkeys', () async {
    final manager = const PhoneAuthPasskeys();
    final passkey = (await manager.list()).single;

    expect(passkey.rpId, 'example.com');
    expect(passkey.userName, 'alice');
    expect(passkey.status, ManagedPasskeyStatus.available);
    await manager.delete(passkey);
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
