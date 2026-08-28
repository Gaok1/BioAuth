import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/features/vault/vault_store.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('bioauth/vault_store');

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  test(
    'native store follows bounded pagination without accepting a cycle',
    () async {
      var cyclic = false;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
            expect(call.method, 'list');
            final cursor = (call.arguments as Map)['cursor'];
            if (cursor == null) {
              return {
                'items': [_summary('one')],
                'nextCursor': '1',
              };
            }
            return {
              'items': [_summary('two')],
              'nextCursor': cyclic ? '1' : null,
            };
          });

      expect(
        (await const NativeVaultStore().listAll()).map((item) => item.id),
        ['one', 'two'],
      );
      cyclic = true;
      await expectLater(
        const NativeVaultStore().listAll(),
        throwsFormatException,
      );
    },
  );
}

Map<String, Object> _summary(String id) => {
  'id': id,
  'revision': 1,
  'kind': 0,
  'name': 'Example',
  'username': 'alice',
  'uri': 'https://example.com',
  'updatedAtMs': 1787875200000,
};
