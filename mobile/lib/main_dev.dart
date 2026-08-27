import 'app/config.dart';
import 'core/auth/phone_authenticator.dart';
import 'core/mock/fake_phone_authenticator.dart';
import 'core/mock/mock_seed.dart';
import 'main.dart';

void main() {
  final config = AppConfig.development(buildMockSeed());
  runPhoneAuth(
    config,
    authenticator: config.mockEnabled
        ? const FakePhoneAuthenticator()
        : const UnavailablePhoneAuthenticator(),
  );
}
