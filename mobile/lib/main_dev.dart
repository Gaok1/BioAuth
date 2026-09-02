import 'app/config.dart';
import 'core/mock/fake_phone_authenticator.dart';
import 'core/mock/mock_seed.dart';
import 'main.dart';

Future<void> main() async {
  final config = AppConfig.development(buildMockSeed());
  // A release build of the dev flavour is a real app with a dev application id,
  // so it gets the real stack. Only a debug build gets the fake.
  await runPhoneAuth(
    config,
    authenticator: config.mockEnabled ? const FakePhoneAuthenticator() : null,
  );
}
