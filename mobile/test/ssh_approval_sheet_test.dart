/// The SSH approval sheet.
///
/// The thing being approved here lasts longer than anything else this app
/// approves: a copied password is spent when it is pasted, and an SSH
/// signature opens a session that runs until the terminal closes. So what the
/// sheet says, and what it says when it does not know, is the feature.
library;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/ssh/ssh_service.dart';
import 'package:phone_auth/features/ssh/ssh_approval_sheet.dart';

void main() {
  Future<bool?> pump(
    WidgetTester tester, {
    String destination = 'SHA256:abc123',
    String user = 'deploy',
    Brightness brightness = Brightness.light,
  }) async {
    bool? answer;
    await tester.pumpWidget(
      MaterialApp(
        theme: ThemeData(brightness: brightness),
        home: Builder(
          builder: (context) => TextButton(
            onPressed: () async {
              answer = await showSshApprovalSheet(
                context,
                SshApprovalRequest(
                  id: 'request-1',
                  verifierName: 'Meu computador de trabalho',
                  user: user,
                  destination: destination,
                ),
              );
            },
            child: const Text('abrir'),
          ),
        ),
      ),
    );
    await tester.tap(find.text('abrir'));
    await tester.pumpAndSettle();
    return answer;
  }

  testWidgets('everything needed to decide is on the sheet as text', (
    tester,
  ) async {
    await pump(tester);

    for (final expected in [
      'Meu computador de trabalho', // which computer claims to be asking
      'deploy', // which account it logs in as
      'SHA256:abc123', // which server, as a fingerprint ssh also prints
    ]) {
      expect(
        find.textContaining(expected),
        findsWidgets,
        reason: '`$expected` is not on the sheet',
      );
    }

    // And the consequence, which is what makes this different from every other
    // approval in the app.
    expect(find.textContaining('enquanto o terminal'), findsOneWidget);
  });

  /// An `ssh` older than 8.9 sends no `session-bind`, so the phone genuinely
  /// does not know the host. A blank where a server belongs reads as "no
  /// server involved" rather than as "nobody told me".
  testWidgets('an unnamed destination is said out loud, not left blank', (
    tester,
  ) async {
    await pump(tester, destination: '');

    expect(find.textContaining('não disse para qual servidor'), findsOneWidget);
    expect(find.textContaining('não informado'), findsOneWidget);
  });

  /// The two answers, and a helper that actually waits for the sheet to
  /// resolve rather than reading a local the closure has not written yet.
  Future<bool> answerWith(WidgetTester tester, String button) async {
    late bool approved;
    await tester.pumpWidget(
      MaterialApp(
        home: Builder(
          builder: (context) => TextButton(
            onPressed: () async {
              approved = await showSshApprovalSheet(
                context,
                const SshApprovalRequest(
                  id: 'r',
                  verifierName: 'PC',
                  user: 'alice',
                  destination: 'SHA256:x',
                ),
              );
            },
            child: const Text('abrir'),
          ),
        ),
      ),
    );
    await tester.tap(find.text('abrir'));
    await tester.pumpAndSettle();
    await tester.tap(find.text(button));
    await tester.pumpAndSettle();
    return approved;
  }

  testWidgets('approving returns true', (tester) async {
    expect(await answerWith(tester, 'Aprovar login'), isTrue);
  });

  testWidgets('refusing returns false', (tester) async {
    expect(await answerWith(tester, 'Recusar'), isFalse);
  });

  /// Dismissing is not approving. A sheet whose only escape is the approve
  /// button is a sheet people approve to get rid of.
  testWidgets('dismissing the sheet is a refusal', (tester) async {
    late bool approved;
    await tester.pumpWidget(
      MaterialApp(
        home: Builder(
          builder: (context) => TextButton(
            onPressed: () async {
              approved = await showSshApprovalSheet(
                context,
                const SshApprovalRequest(
                  id: 'r',
                  verifierName: 'PC',
                  user: 'alice',
                  destination: 'SHA256:x',
                ),
              );
            },
            child: const Text('abrir'),
          ),
        ),
      ),
    );
    await tester.tap(find.text('abrir'));
    await tester.pumpAndSettle();

    // What a back gesture or a tap outside does.
    Navigator.of(tester.element(find.byType(FilledButton))).pop();
    await tester.pumpAndSettle();

    expect(approved, isFalse);
  });

  /// The same three guidelines the vault sheet is held to, in both themes. A
  /// palette that passes in light and fails in dark fails for whoever has dark
  /// mode on.
  for (final brightness in Brightness.values) {
    testWidgets('the sheet meets the accessibility guidelines in $brightness', (
      tester,
    ) async {
      await pump(tester, brightness: brightness);
      final handle = tester.ensureSemantics();

      await expectLater(tester, meetsGuideline(textContrastGuideline));
      await expectLater(tester, meetsGuideline(androidTapTargetGuideline));
      await expectLater(tester, meetsGuideline(labeledTapTargetGuideline));

      handle.dispose();
    });

    /// The warning state has its own colours, so it needs its own check —
    /// error containers are exactly where contrast tends to fall over.
    testWidgets('the unnamed-destination warning is legible in $brightness', (
      tester,
    ) async {
      await pump(tester, destination: '', brightness: brightness);
      final handle = tester.ensureSemantics();

      await expectLater(tester, meetsGuideline(textContrastGuideline));

      handle.dispose();
    });
  }
}
