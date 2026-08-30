import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/app/app.dart';
import 'package:phone_auth/app/app_controller.dart';
import 'package:phone_auth/app/config.dart';
import 'package:phone_auth/core/mock/fake_phone_authenticator.dart';
import 'package:phone_auth/core/mock/mock_seed.dart';

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

    expect(find.text('Origem'), findsOneWidget);
    expect(find.text('Usuário'), findsOneWidget);
    expect(find.text('alice'), findsOneWidget);
    await tester.tap(find.widgetWithText(FilledButton, 'Autorizar'));
    await tester.pumpAndSettle();

    expect(find.text('Solicitações'), findsNothing);
  });

  testWidgets('production starts with onboarding and no mock data', (
    tester,
  ) async {
    await tester.pumpWidget(const ProviderScope(child: PhoneAuthApp()));

    expect(find.text('Seu telefone, sua aprovação'), findsOneWidget);
    expect(find.text('Passkeys ainda não têm backup'), findsOneWidget);
    expect(find.text('Desktop-Casa'), findsNothing);
  });

  testWidgets('Flutter speaks the language the rest of the app does', (
    tester,
  ) async {
    await tester.pumpWidget(const ProviderScope(child: PhoneAuthApp()));

    final context = tester.element(find.byType(Navigator).first);
    expect(Localizations.localeOf(context), const Locale('pt', 'BR'));

    // The strings nobody writes and everybody reads: the overflow button on
    // every vault item, the toolbar over every text field, the back button.
    // With no delegates a `MaterialApp` runs on `DefaultMaterialLocalizations`
    // and these were English in an app that is Portuguese everywhere else.
    final material = MaterialLocalizations.of(context);
    expect(material.pasteButtonLabel, isNot('Paste'));
    expect(material.backButtonTooltip, isNot('Back'));
    expect(material.popupMenuLabel, isNot('Show menu'));
  });
}
