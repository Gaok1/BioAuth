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

      expect((await const _PagedStore().listAll()).map((item) => item.id), [
        'one',
        'two',
      ]);
      cyclic = true;
      await expectLater(const _PagedStore().listAll(), throwsFormatException);
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

    final items = await const _PagedStore().listAll();

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

    expect(const _PagedStore().listAll(), throwsFormatException);
  });

  /// The whole reason [NativeVaultStore] does not use the walk above.
  ///
  /// The Keystore key is auth-per-use, so every trip through the channel is a
  /// biometric prompt. Walking pages asked for one per thirty-two items, and
  /// cancelling any of them left the vault shut reporting a cancelled
  /// authentication -- so a vault of a hundred items looked like a vault that
  /// would not open.
  test('the native store asks for the whole vault once', () async {
    final asked = <String>[];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          asked.add(call.method);
          return {
            'items': [
              for (var index = 0; index < 70; index++) _summary('item-$index'),
            ],
          };
        });

    final items = await const NativeVaultStore().listAll();

    expect(asked, ['listAll']);
    expect(items, hasLength(70));
    expect(items.first.id, 'item-0');
  });

  test('a native listing larger than a vault may be is refused', () {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          return {
            'items': [
              for (var index = 0; index <= maxVaultItems; index++)
                _summary('item-$index'),
            ],
          };
        });

    expect(const NativeVaultStore().listAll(), throwsFormatException);
  });
}

/// The inherited walk, over the real channel.
///
/// [NativeVaultStore] overrides `listAll` to ask once. The walk is still what
/// any store that implements only [VaultStore.listPage] gets, and its bounds
/// are what the tests above are about.
class _PagedStore extends VaultStore {
  const _PagedStore();

  @override
  Future<VaultPage> listPage([String? cursor]) =>
      const NativeVaultStore().listPage(cursor);

  @override
  Future<VaultSecret> fetch(String id) => throw UnimplementedError();

  @override
  Future<VaultWrite> create(VaultItemInput item) => throw UnimplementedError();

  @override
  Future<VaultWrite> update(VaultItemSummary current, VaultItemInput item) =>
      throw UnimplementedError();

  @override
  Future<List<VaultItemSummary>?> delete(VaultItemSummary item) =>
      throw UnimplementedError();
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
