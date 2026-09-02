import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'app/app.dart';
import 'app/app_controller.dart';
import 'app/config.dart';
import 'app/providers.dart';
import 'core/auth/phone_authenticator.dart';
import 'l10n/language_preference.dart';

Future<void> main() => runPhoneAuth(const AppConfig.production());

/// Boots the app.
///
/// [authenticator] defaults to the real one: the request on screen and the
/// biometric prompt behind it are the same exchange, driven by
/// [interactiveAuthorizerProvider]. Tests and the mock flavour pass their own.
Future<void> runPhoneAuth(
  AppConfig config, {
  PhoneAuthenticator? authenticator,
}) async {
  WidgetsFlutterBinding.ensureInitialized();
  // Read before the first frame so the app never paints in the phone's
  // language and then switches to the chosen one in front of the user.
  final language = await loadLanguageChoice();
  runApp(
    ProviderScope(
      overrides: [
        appConfigProvider.overrideWithValue(config),
        bootLanguageProvider.overrideWithValue(language),
        if (authenticator != null)
          phoneAuthenticatorProvider.overrideWithValue(authenticator)
        else
          phoneAuthenticatorProvider.overrideWith(
            (ref) => ref.watch(interactiveAuthorizerProvider),
          ),
      ],
      child: const PhoneAuthApp(),
    ),
  );
}
