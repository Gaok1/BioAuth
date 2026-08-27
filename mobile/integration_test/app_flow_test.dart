import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:phone_auth/app/app.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('onboarding reaches the offline device list', (tester) async {
    await tester.pumpWidget(const ProviderScope(child: PhoneAuthApp()));
    await tester.tap(find.widgetWithText(FilledButton, 'Começar'));
    await tester.pumpAndSettle();

    expect(find.text('Nenhum dispositivo pareado.'), findsOneWidget);
    expect(find.text('Dispositivos'), findsWidgets);
  });
}
