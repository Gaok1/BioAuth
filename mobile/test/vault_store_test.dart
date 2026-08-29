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

  /// The bound on this loop is the number of items a vault may hold, and the
  /// vault holds thirty-two times as many as it hands out per page. Bounding
  /// it by the page size instead meant a vault past about a thousand items
  /// threw on every unlock — the screen said only that the operation had
  /// failed, so a restored vault of any real size simply stopped opening.
  test('a vault as large as it is allowed to be still lists', () async {
    const pageSize = 32;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          final cursor = (call.arguments as Map)['cursor'] as String?;
          final offset = int.parse(cursor ?? '0');
          final next = offset + pageSize;
          return {
            'items': [
              for (var index = offset; index < next; index++)
                _summary('item-$index'),
            ],
            'nextCursor': next < maxVaultItems ? '$next' : null,
          };
        });

    final items = await const NativeVaultStore().listAll();

    expect(items, hasLength(maxVaultItems));
    expect(items.last.id, 'item-${maxVaultItems - 1}');
  });

  /// And no further: past the ceiling the store is describing a vault it
  /// cannot have written, and reading it into memory is the failure the
  /// ceiling exists to prevent.
  test('a store that claims more items than a vault can hold is refused', () {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          final offset = int.parse(
            ((call.arguments as Map)['cursor'] as String?) ?? '0',
          );
          return {
            'items': [_summary('item-$offset')],
            'nextCursor': '${offset + 1}',
          };
        });

    expect(const NativeVaultStore().listAll(), throwsFormatException);
  });
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
