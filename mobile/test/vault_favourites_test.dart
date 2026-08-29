/// Favourites: which items float to the top.
///
/// Kept out of the vault deliberately — see `vault_favourites.dart`. What is
/// pinned here is that the ordering never loses an item, never blocks the
/// unlock, and never becomes a growing record of everything ever starred.
library;

import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/features/vault/vault_controller.dart';
import 'package:phone_auth/features/vault/vault_favourites.dart';
import 'package:phone_auth/features/vault/vault_store.dart';

void main() {
  VaultItemSummary item(String id) => VaultItemSummary(
    id: id,
    revision: 1,
    kind: VaultItemKind.login,
    name: id,
    username: 'alice',
    uri: 'https://$id.example.com',
    updatedAt: DateTime.utc(2026),
  );

  test('starred items come first and nothing is dropped', () {
    final favourites = _Fake({'b', 'd'});
    final items = ['a', 'b', 'c', 'd'].map(item).toList();

    final ordered = favourites.order(items);

    expect(ordered.map((i) => i.id), ['b', 'd', 'a', 'c']);
    expect(ordered.length, items.length, reason: 'ordering lost an item');
  });

  /// A stable partition, not a sort: the store already returns items
  /// newest-first, and re-sorting the rest would silently discard that.
  test('the order the store gave survives inside each group', () {
    final favourites = _Fake({'c'});
    final items = ['z', 'c', 'a', 'm'].map(item).toList();

    expect(favourites.order(items).map((i) => i.id), ['c', 'z', 'a', 'm']);
  });

  test('with nothing starred the list is untouched', () {
    final items = ['a', 'b'].map(item).toList();

    expect(identical(_Fake(const {}).order(items), items), isTrue);
  });

  /// Filtering happens first, so a search shows its matches with the starred
  /// ones on top — not every favourite regardless of the query.
  test('a search shows its matches, starred first', () async {
    final controller = VaultController(
      store: _Store(['banco', 'bar', 'email']),
      favourites: _Fake({'bar'}),
      copy: (_) async {},
    );
    addTearDown(controller.dispose);
    await controller.unlock();

    controller.search('ba');

    expect(controller.items.map((i) => i.id), ['bar', 'banco']);
  });

  /// Stars for items that are gone would accumulate forever, turning the
  /// stored list into a slowly growing record of everything ever starred.
  test('stars for items that no longer exist are forgotten', () async {
    final favourites = _Fake({'kept', 'gone'});

    await favourites.prune(['kept']);

    expect(favourites.contains('kept'), isTrue);
    expect(favourites.contains('gone'), isFalse);
  });

  /// Ordering is a convenience and unlocking is the feature. A preference
  /// store that never answers must not hold the vault shut.
  test('a preference store that hangs does not block the unlock', () async {
    final controller = VaultController(
      store: _Store(['a']),
      favourites: _Hanging(),
      copy: (_) async {},
    );
    addTearDown(controller.dispose);

    await controller.unlock().timeout(const Duration(seconds: 2));

    expect(controller.locked, isFalse);
    expect(controller.items, hasLength(1));
  });
}

/// A `VaultFavourites` that keeps its set in memory, with no platform behind
/// it — the persistence is the plugin's job and not what these assert.
class _Fake extends VaultFavourites {
  _Fake(this._ids);

  Set<String> _ids;

  @override
  Future<void> load() async {}

  @override
  bool contains(String id) => _ids.contains(id);

  @override
  bool get isEmpty => _ids.isEmpty;

  @override
  Future<void> toggle(String id) async {
    final next = _ids.toSet();
    if (!next.remove(id)) next.add(id);
    _ids = next;
  }

  @override
  Future<void> prune(Iterable<String> livingIds) async {
    final living = livingIds.toSet();
    _ids = _ids.where(living.contains).toSet();
  }

  @override
  List<VaultItemSummary> order(List<VaultItemSummary> items) {
    if (_ids.isEmpty) return items;
    return [
      ...items.where((item) => _ids.contains(item.id)),
      ...items.where((item) => !_ids.contains(item.id)),
    ];
  }
}

/// Never finishes loading, which is what an unavailable plugin looks like.
class _Hanging extends _Fake {
  _Hanging() : super(const {});

  @override
  Future<void> load() => Completer<void>().future;
}

class _Store extends VaultStore {
  _Store(this.ids);

  final List<String> ids;

  @override
  Future<VaultPage> listPage([String? cursor]) async => VaultPage(
    items: [
      for (final id in ids)
        VaultItemSummary(
          id: id,
          revision: 1,
          kind: VaultItemKind.login,
          name: id,
          username: 'alice',
          uri: 'https://$id.example.com',
          updatedAt: DateTime.utc(2026),
        ),
    ],
  );

  @override
  Future<VaultSecret> fetch(String id) async =>
      VaultSecret(id: id, revision: 1, secret: 'hunter2');

  @override
  Future<VaultWrite> create(VaultItemInput item) async =>
      const VaultWrite(id: 'new', revision: 1);

  @override
  Future<VaultWrite> update(
    VaultItemSummary current,
    VaultItemInput item,
  ) async => VaultWrite(id: current.id, revision: current.revision + 1);

  @override
  Future<void> delete(VaultItemSummary item) async {}
}
