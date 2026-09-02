import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/app/app.dart';
import 'package:phone_auth/app/app_controller.dart';
import 'package:phone_auth/app/config.dart';
import 'package:phone_auth/core/mock/fake_phone_authenticator.dart';
import 'package:phone_auth/core/mock/mock_seed.dart';
import 'package:phone_auth/l10n/language_preference.dart';

void main() {
  testWidgets('shows contextual request and approves through mock biometric', (
    tester,
  ) async {
    final now = DateTime.now().toUtc();
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          appConfigProvider.overrideWithValue(
            AppConfig.development(buildMockSeed(now)),
          ),
          phoneAuthenticatorProvider.overrideWithValue(
            const FakePhoneAuthenticator(),
          ),
        ],
        child: const PhoneAuthApp(),
      ),
    );

    expect(find.text('Desktop-Casa'), findsWidgets);
    expect(find.text('SSH • prod-server'), findsOneWidget);
    await tester.tap(find.text('SSH • prod-server'));
    await tester.pumpAndSettle();

    expect(find.text('Origin'), findsOneWidget);
    expect(find.text('User'), findsOneWidget);
    expect(find.text('alice'), findsOneWidget);
    await tester.tap(find.widgetWithText(FilledButton, 'Approve'));
    await tester.pumpAndSettle();

    expect(find.text('Requests'), findsNothing);
  });

  testWidgets('production starts with onboarding and no mock data', (
    tester,
  ) async {
    await tester.pumpWidget(const ProviderScope(child: PhoneAuthApp()));

    expect(find.text('Approve logins with your phone'), findsOneWidget);
    expect(find.text('Passkeys have no backup'), findsOneWidget);
    expect(find.text('Desktop-Casa'), findsNothing);
  });

  testWidgets("with nothing picked, the app speaks the phone's language", (
    tester,
  ) async {
    await tester.pumpWidget(const ProviderScope(child: PhoneAuthApp()));

    final context = tester.element(find.byType(Navigator).first);
    expect(Localizations.localeOf(context), const Locale('en'));
    expect(find.text('Approve logins with your phone'), findsOneWidget);
  });

  /// The strings nobody writes and everybody reads: the overflow button on
  /// every vault item, the toolbar over every text field, the back button.
  /// They come from Flutter, and a picked language that moved only this app's
  /// own words would leave half a screen in each.
  testWidgets("a picked language moves Flutter's own strings too", (
    tester,
  ) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          bootLanguageProvider.overrideWithValue(const Locale('pt', 'BR')),
        ],
        child: const PhoneAuthApp(),
      ),
    );

    final context = tester.element(find.byType(Navigator).first);
    expect(Localizations.localeOf(context), const Locale('pt', 'BR'));
    expect(find.text('Aprove acessos pelo telefone'), findsOneWidget);

    final material = MaterialLocalizations.of(context);
    expect(material.pasteButtonLabel, isNot('Paste'));
    expect(material.backButtonTooltip, isNot('Back'));
    expect(material.popupMenuLabel, isNot('Show menu'));
  });
}
