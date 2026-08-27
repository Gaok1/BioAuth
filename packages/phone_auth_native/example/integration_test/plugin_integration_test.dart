import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:phone_auth_native/phone_auth_native.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('Android returns strong-biometric security metadata', (
    tester,
  ) async {
    if (defaultTargetPlatform != TargetPlatform.android) return;

    final capabilities = await const PhoneAuthNative()
        .getSecurityCapabilities();
    expect(capabilities.biometrics.availability, isNotNull);
  });
}
