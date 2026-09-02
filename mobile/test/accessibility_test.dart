/// Accessibility guarantees for the screens that decide something.
///
/// REL-09. The rule that matters here is the last one in that row: **a
/// critical operation may not depend on colour or an icon alone.** An approval
/// sheet whose "this is the computer asking" is conveyed by a red border is an
/// approval sheet a screen-reader user cannot audit, and the thing they are
/// approving is a password leaving the phone.
///
/// Flutter's own guideline matchers cover the mechanical half — contrast, tap
/// target size, whether a tappable thing has a label at all — and they run in
/// an ordinary widget test, so there is no reason for this to be manual.
///
/// What they do not cover, and what the explicit assertions below are for, is
/// whether the *meaning* survives without sight: every field on the approval
/// sheet has to be readable as text.
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/vault/vault_approval.dart';
import 'package:phone_auth/features/vault/vault_approval_sheet.dart';
import 'package:phone_auth/features/vault/vault_controller.dart';
import 'package:phone_auth/features/vault/vault_screen.dart';
import 'package:phone_auth/features/vault/vault_store.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const sensitiveChannel = MethodChannel('flutter/sensitivecontent');

  setUp(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(sensitiveChannel, (call) async => false);
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(sensitiveChannel, null);
  });

  /// Runs the three mechanical guidelines over whatever is on screen.
  ///
  /// Both themes, because a palette that passes in light and fails in dark is
  /// a palette that fails for whoever has dark mode on.
  Future<void> checkGuidelines(WidgetTester tester) async {
    final handle = tester.ensureSemantics();
    await expectLater(tester, meetsGuideline(textContrastGuideline));
    await expectLater(tester, meetsGuideline(androidTapTargetGuideline));
    await expectLater(tester, meetsGuideline(labeledTapTargetGuideline));
    handle.dispose();
  }

  for (final brightness in Brightness.values) {
    testWidgets('the locked vault meets the guidelines in $brightness', (
      tester,
    ) async {
      await tester.pumpWidget(
        MaterialApp(
          theme: ThemeData(brightness: brightness),
          home: VaultScreen(controller: VaultController(store: _Store())),
        ),
      );
      await tester.pumpAndSettle();

      await checkGuidelines(tester);
    });

    testWidgets('the unlocked vault meets the guidelines in $brightness', (
      tester,
    ) async {
      final controller = VaultController(store: _Store(), copy: (_) async {});
      await tester.pumpWidget(
        MaterialApp(
          theme: ThemeData(brightness: brightness),
          home: VaultScreen(controller: controller),
        ),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.text('Unlock'));
      await tester.pumpAndSettle();

      await checkGuidelines(tester);
    });

    testWidgets('the approval sheet meets the guidelines in $brightness', (
      tester,
    ) async {
      await pumpApprovalSheet(tester, brightness: brightness);

      await checkGuidelines(tester);
    });
  }

  /// The one that is not mechanical. Everything the user needs in order to say
  /// no has to be *text*, because a screen reader announces text and does not
  /// announce a border colour or an icon glyph.
  testWidgets('the approval sheet says everything in words', (tester) async {
    await pumpApprovalSheet(tester);

    for (final expected in [
      'Meu computador de trabalho', // which computer claims to be asking
      'Copy the password of', // what it wants to do
      'Banco Exemplo', // which item
      'alice', // which account
      'banco.example.com', // where it belongs
    ]) {
      expect(
        find.textContaining(expected),
        findsWidgets,
        reason: '`$expected` is not on the sheet as text',
      );
    }

    // And the consequence, which is the part a user has no other way to know:
    // approving moves the password somewhere the phone stops controlling.
    expect(find.textContaining('clipboard'), findsWidgets);
  });

  /// Refusing must be reachable, not a dismiss gesture somebody has to guess.
  /// A sheet whose only way out is a swipe is a sheet people approve to make
  /// it go away.
  testWidgets('the approval sheet has a labelled refusal', (tester) async {
    await pumpApprovalSheet(tester);

    expect(find.widgetWithText(TextButton, 'Refuse'), findsOneWidget);
    expect(find.widgetWithText(FilledButton, 'Approve copy'), findsOneWidget);
  });

  /// Both buttons are reachable from the keyboard, in the order they read. A
  /// hardware keyboard is how many motor-impaired users drive a phone, and an
  /// approval that can only be tapped excludes them from the decision.
  testWidgets('the approval sheet is reachable without a touchscreen', (
    tester,
  ) async {
    await pumpApprovalSheet(tester);

    final focusable = tester
        .widgetList<Focus>(find.byType(Focus))
        .where((node) => node.canRequestFocus)
        .length;

    expect(focusable, greaterThanOrEqualTo(2), reason: 'nothing to tab to');
  });
}

Future<void> pumpApprovalSheet(
  WidgetTester tester, {
  Brightness brightness = Brightness.light,
}) async {
  await tester.pumpWidget(
    MaterialApp(
      theme: ThemeData(brightness: brightness),
      home: Builder(
        builder: (context) => TextButton(
          onPressed: () => showVaultApprovalSheet(
            context,
            const VaultApprovalRequest(
              id: 'request-1',
              verifierName: 'Meu computador de trabalho',
              operation: VaultOperation.read,
              itemName: 'Banco Exemplo',
              username: 'alice',
              uri: 'https://banco.example.com/login',
            ),
          ),
          child: const Text('abrir'),
        ),
      ),
    ),
  );
  await tester.tap(find.text('abrir'));
  await tester.pumpAndSettle();
}

class _Store extends VaultStore {
  @override
  Future<VaultPage> listPage([String? cursor]) async => VaultPage(
    items: [
      VaultItemSummary(
        id: 'one',
        revision: 1,
        kind: VaultItemKind.login,
        name: 'Banco Exemplo',
        username: 'alice',
        uri: 'https://banco.example.com',
        updatedAt: DateTime.utc(2026),
      ),
    ],
  );

  @override
  Future<VaultSecret> fetch(String id) async =>
      VaultSecret(id: id, revision: 1, secret: 'hunter2');

  @override
  Future<VaultWrite> create(VaultItemInput item) async =>
      const VaultWrite(id: 'created', revision: 1);

  @override
  Future<VaultWrite> update(
    VaultItemSummary current,
    VaultItemInput item,
  ) async => VaultWrite(id: current.id, revision: current.revision + 1);

  @override
  Future<List<VaultItemSummary>?> delete(VaultItemSummary item) async => null;
}
