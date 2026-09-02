import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/features/passkeys/passkeys_screen.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('phone_auth_native');
  var deleted = false;
  var listCalls = 0;

  setUp(() {
    deleted = false;
    listCalls = 0;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          if (call.method == 'listPasskeys') {
            listCalls++;
            return deleted
                ? <Object?>[]
                : [
                    {
                      'kind': 'credential',
                      'identifier': 'AQ',
                      'rpId': 'example.com',
                      'userName': 'alice',
                      'userDisplayName': 'Alice',
                      'createdAtMillis': 1787875200000,
                      'status': 'available',
                    },
                  ];
          }
          if (call.method == 'deletePasskey') {
            deleted = true;
            return true;
          }
          throw MissingPluginException();
        });
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  testWidgets('lists and deletes both passkey metadata and native key', (
    tester,
  ) async {
    await tester.pumpWidget(const MaterialApp(home: PasskeysScreen()));
    await tester.pumpAndSettle();

    expect(find.text('example.com'), findsOneWidget);
    expect(find.textContaining('Alice'), findsOneWidget);
    await tester.tap(find.byTooltip('Delete passkey'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Continue'));
    await tester.pumpAndSettle();
    await tester.pump();

    expect(deleted, isTrue);
    expect(listCalls, 2);
    expect(find.text('No passkeys on this phone.'), findsOneWidget);
  });
}
