import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/domain/connection_phase.dart';
import 'package:phone_auth/domain/desktop_device.dart';
import 'package:phone_auth/shared/device_card.dart';

void main() {
  testWidgets('explains bilateral revocation before removing the device', (
    tester,
  ) async {
    var revoked = false;
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: DeviceCard(
            device: DesktopDevice(
              id: 'desktop-1',
              name: 'Desktop Casa',
              phase: ConnectionPhase.connected,
              lastSeen: DateTime.now().toUtc(),
            ),
            onRevoke: () => revoked = true,
          ),
        ),
      ),
    );

    await tester.tap(find.byTooltip('Device options'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Revoke device'));
    await tester.pumpAndSettle();

    expect(find.text('Revoke this computer?'), findsOneWidget);
    expect(find.textContaining('public key'), findsOneWidget);
    expect(find.textContaining('unpair there too'), findsOneWidget);
    expect(revoked, isFalse);

    await tester.tap(find.widgetWithText(FilledButton, 'Revoke'));
    await tester.pumpAndSettle();
    expect(revoked, isTrue);
  });
}
