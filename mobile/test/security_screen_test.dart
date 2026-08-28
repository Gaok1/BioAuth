import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/app/providers.dart';
import 'package:phone_auth/features/security/security_screen.dart';
import 'package:phone_auth_native/phone_auth_native.dart';

void main() {
  testWidgets('shows native key, biometric, and background capabilities', (
    tester,
  ) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          securityCapabilitiesProvider.overrideWith(
            (ref) async => const SecurityCapabilities(
              keyExists: true,
              hardwareBacked: true,
              strongBoxBacked: true,
              biometrics: BiometricCapabilities(
                availability: BiometricAvailability.available,
                strongBiometrics: true,
              ),
            ),
          ),
          backgroundSessionsReadyProvider.overrideWith((ref) async => true),
        ],
        child: const MaterialApp(home: SecurityScreen()),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.textContaining('StrongBox'), findsOneWidget);
    expect(find.text('BIOMETRIC_STRONG disponível'), findsOneWidget);
    expect(find.text('Serviço persistente ativo'), findsOneWidget);
  });
}
