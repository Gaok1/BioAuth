import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/features/vault/vault_controller.dart';
import 'package:phone_auth/features/vault/vault_store.dart';

void main() {
  test('search, reveal, copy, CRUD and lock keep plaintext bounded', () async {
    final store = _MemoryVaultStore();
    String? copied;
    final controller = VaultController(
      store: store,
      copy: (value) async => copied = value,
    );

    await controller.unlock();
    expect(controller.items.map((item) => item.name), ['Example']);

    controller.search('alice');
    expect(controller.items, hasLength(1));
    controller.search('missing');
    expect(controller.items, isEmpty);
    controller.search('');

    final item = controller.items.single;
    await controller.reveal(item);
    expect(controller.secretFor(item.id), 'hunter2');
    await controller.copy(item);
    expect(copied, 'hunter2');
    expect(store.fetches, 2, reason: 'reveal and copy each require biometrics');

    await controller.update(
      item,
      const VaultItemInput(
        kind: VaultItemKind.login,
        name: 'Updated',
        secret: 'new-secret',
      ),
    );
    expect(controller.items.single.revision, 2);
    await controller.create(
      const VaultItemInput(
        kind: VaultItemKind.note,
        name: 'Note',
        secret: 'body',
      ),
    );
    expect(controller.items, hasLength(2));
    await controller.delete(controller.items.last);
    expect(controller.items, hasLength(1));

    controller.lock();
    expect(controller.locked, isTrue);
    expect(controller.items, isEmpty);
    expect(controller.secretFor(item.id), isNull);
  });
}

class _MemoryVaultStore implements VaultStore {
  final _values = <String, ({VaultItemSummary summary, String secret})>{
    'one': (
      summary: VaultItemSummary(
        id: 'one',
        revision: 1,
        kind: VaultItemKind.login,
        name: 'Example',
        username: 'alice',
        uri: 'https://example.com',
        updatedAt: DateTime.utc(2026),
      ),
      secret: 'hunter2',
    ),
  };
  int fetches = 0;

  @override
  Future<List<VaultItemSummary>> listAll() async =>
      _values.values.map((value) => value.summary).toList();

  @override
  Future<VaultSecret> fetch(String id) async {
    fetches++;
    final value = _values[id]!;
    return VaultSecret(
      id: id,
      revision: value.summary.revision,
      secret: value.secret,
    );
  }

  @override
  Future<void> create(VaultItemInput item) async {
    final id = 'item-${_values.length}';
    _values[id] = (summary: _summary(id, 1, item), secret: item.secret);
  }

  @override
  Future<void> update(VaultItemSummary current, VaultItemInput item) async {
    _values[current.id] = (
      summary: _summary(current.id, current.revision + 1, item),
      secret: item.secret,
    );
  }

  @override
  Future<void> delete(VaultItemSummary item) async => _values.remove(item.id);

  VaultItemSummary _summary(String id, int revision, VaultItemInput item) =>
      VaultItemSummary(
        id: id,
        revision: revision,
        kind: item.kind,
        name: item.name,
        username: item.username,
        uri: item.uri,
        updatedAt: DateTime.utc(2026),
      );
}
