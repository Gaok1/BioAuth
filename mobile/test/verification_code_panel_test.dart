/// The confirmation panel.
///
/// Two questions get answered here and they are not the same question. The six
/// digits say *which* computer is on the other end of the handshake. The
/// purpose says what that computer will be able to ask for afterwards — and
/// since the desktop is the side that chose it, the phone is the only place
/// the user can find out before agreeing.
library;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/protocol/enrolment.dart';
import 'package:phone_auth/l10n/app_strings_en.dart';
import 'package:phone_auth/shared/verification_code_panel.dart';

void main() {
  Future<void> pump(
    WidgetTester tester, {
    CredentialPurpose purpose = CredentialPurpose.authorization,
    Brightness brightness = Brightness.light,
  }) => tester.pumpWidget(
    MaterialApp(
      theme: ThemeData(brightness: brightness),
      home: Scaffold(
        body: VerificationCodePanel(
          code: '123456',
          verifierId: 'desktop-1',
          purpose: purpose,
          onConfirm: () async {},
          onReject: () async {},
        ),
      ),
    ),
  );

  testWidgets('the code is grouped for reading aloud', (tester) async {
    await pump(tester);

    expect(find.text('123 456'), findsOneWidget);
    expect(find.textContaining('desktop-1'), findsOneWidget);
  });

  /// Every purpose says something, because a panel that falls silent on one of
  /// them is silent exactly where the user has no other source.
  testWidgets('every purpose is described in words', (tester) async {
    for (final purpose in CredentialPurpose.values) {
      await pump(tester, purpose: purpose);

      expect(
        find.textContaining(
          const EnglishStrings().credentialPurposeNote(purpose),
        ),
        findsOneWidget,
        reason: '$purpose says nothing about itself',
      );
    }
  });

  /// The one that matters most: an SSH pairing looks identical to a `sudo`
  /// pairing once it is in the list, so the difference has to be said here.
  testWidgets('an SSH pairing says it signs server logins', (tester) async {
    await pump(tester, purpose: CredentialPurpose.ssh);

    expect(find.textContaining('SSH logins'), findsOneWidget);
    // And that approving the pairing is not approving the logins themselves.
    expect(find.textContaining('fingerprint'), findsOneWidget);
  });

  for (final brightness in Brightness.values) {
    testWidgets('the panel is accessible in $brightness', (tester) async {
      await pump(
        tester,
        purpose: CredentialPurpose.ssh,
        brightness: brightness,
      );
      final handle = tester.ensureSemantics();

      await expectLater(tester, meetsGuideline(textContrastGuideline));
      await expectLater(tester, meetsGuideline(androidTapTargetGuideline));
      await expectLater(tester, meetsGuideline(labeledTapTargetGuideline));

      handle.dispose();
    });
  }
}
