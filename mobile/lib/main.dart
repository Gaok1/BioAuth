import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'app/app.dart';
import 'app/app_controller.dart';
import 'app/config.dart';
import 'core/auth/phone_authenticator.dart';

void main() => runPhoneAuth(const AppConfig.production());

void runPhoneAuth(
  AppConfig config, {
  PhoneAuthenticator authenticator = const UnavailablePhoneAuthenticator(),
}) {
  runApp(
    ProviderScope(
      overrides: [
        appConfigProvider.overrideWithValue(config),
        phoneAuthenticatorProvider.overrideWithValue(authenticator),
      ],
      child: const PhoneAuthApp(),
    ),
  );
}
