import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/app/app_controller.dart';
import 'package:phone_auth/app/config.dart';
import 'package:phone_auth/app/router.dart';
import 'package:phone_auth/core/mock/mock_seed.dart';

void main() {
  // A request is listed on the Devices screen and nowhere else: no notification
  // is posted for one, so someone reading the Cofre tab when the desktop asked
  // had no sign at all that it had, and the desktop timed out. From either seat
  // that is the pairing being broken.
  testWidgets('a waiting request is visible from another tab', (tester) async {
    final now = DateTime.now().toUtc();
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          appConfigProvider.overrideWithValue(
            AppConfig.development(buildMockSeed(now)),
          ),
        ],
        child: const MaterialApp(home: HomeShell()),
      ),
    );
    await tester.pump();

    expect(
      find.widgetWithText(Badge, '1'),
      findsOneWidget,
      reason: 'the seed leaves one request waiting, and the tab says so',
    );

    // Answering it is what takes the badge down -- not switching tabs, and not
    // the sheet scrolling out of view.
    final ref = ProviderScope.containerOf(
      tester.element(find.byType(HomeShell)),
    );
    ref.read(appControllerProvider.notifier).deny('mock-request-1', at: now);
    await tester.pump();

    expect(
      find.byType(Badge),
      findsNothing,
      reason: 'nothing is waiting, so nothing is announced',
    );
  });
}
