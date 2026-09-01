import 'dart:async';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/features/vault/vault_controller.dart';
import 'package:phone_auth/features/vault/vault_store.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  // The screen owns the controller and disposes it on the way out, and two of
  // these notify after an `await`. Notifying a disposed `ChangeNotifier`
  // throws, and the build people are handed to test is `flutter build apk
  // --debug`, where that assert is live -- so this is a crash, not a warning.
  group('work that outlives the screen that started it', () {
    setUp(() => SharedPreferences.setMockInitialValues({}));

    test(
      'starring an item and leaving does not notify a dead controller',
      () async {
        final controller = VaultController(
          store: _MemoryVaultStore(),
          copy: (_) async {},
        );
        await controller.unlock();
        final id = controller.items.single.id;

        // One gesture: tap the star, leave. `toggleFavourite` is deliberately
        // not routed through `_run`, so nothing marks the controller busy and
        // nothing waits for the preference write before the screen goes.
        final starring = controller.toggleFavourite(id);
        controller.dispose();

        await expectLater(starring, completes);
      },
    );

    test(
      'an operation still in flight does not notify a dead controller',
      () async {
        final store = _BlockingVaultStore();
        final controller = VaultController(store: store, copy: (_) async {});

        // The vault raises a biometric prompt for every operation, so "in
        // flight" is as long as a person takes -- and the back gesture that
        // dismisses the prompt is one press away from the one that pops the
        // screen.
        final unlocking = controller.unlock();
        controller.dispose();
        store.answer();

        await expectLater(unlocking, completes);
      },
    );
  });

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

  test('locking forgets the search, not just the items', () async {
    final store = _MemoryVaultStore();
    final controller = VaultController(store: store, copy: (_) async {});

    await controller.unlock();
    controller.search('nada corresponde a isto');
    expect(controller.items, isEmpty);

    // What the app does every time it leaves the foreground.
    controller.lock();
    await controller.unlock();

    // The search field lives in the unlocked view and is rebuilt empty, so a
    // query that survived the lock filtered the vault against a box showing
    // nothing -- which reads as a vault that lost its items.
    expect(controller.items.map((item) => item.name), ['Example']);
  });

  test(
    'a write shows the vault it left behind, without reading it again',
    () async {
      final store = _AnsweringStore();
      final controller = VaultController(store: store, copy: (_) async {});

      await controller.unlock();
      expect(store.reads, 1);

      await controller.create(
        const VaultItemInput(
          kind: VaultItemKind.login,
          name: 'Novo',
          secret: 'segredo',
        ),
      );
      expect(controller.items.map((item) => item.name), ['Example', 'Novo']);
      // A write already decrypts the vault and seals it again, and on a phone
      // each of those is its own biometric prompt. Reading the list afterwards
      // made adding one item cost three fingerprints for a list the write had
      // in hand.
      expect(store.reads, 1);

      await controller.delete(
        controller.items.firstWhere((item) => item.name == 'Novo'),
      );
      expect(controller.items.map((item) => item.name), ['Example']);
      expect(store.reads, 1);
    },
  );

  test('a lock during an unlock wins over the unlock', () async {
    // The Keystore prompt is the whole delay: `listAll` is what raises it, and
    // the app can leave the foreground while it is up. `lock` forgot what the
    // vault held at the moment it ran, and the read still in flight wrote its
    // own result afterwards -- so the vault ended up open, with every item in
    // memory, on an app that had already gone to the background.
    final store = _SlowStore();
    final controller = VaultController(store: store, copy: (_) async {});
    final unlocking = controller.unlock();
    await pumpEventQueue();
    expect(store.pending.isCompleted, isFalse, reason: 'the prompt is up');

    controller.lock();
    store.pending.complete();
    await unlocking;

    expect(
      controller.locked,
      isTrue,
      reason:
          'leaving the foreground forgets, and finishing later is not '
          'permission to remember',
    );
    expect(controller.items, isEmpty);
  });

  test('a lock during a reveal drops the secret it was fetching', () async {
    final store = _SlowStore();
    final controller = VaultController(store: store, copy: (_) async {});
    store.pending.complete();
    await controller.unlock();
    final item = controller.items.single;

    store.pending = Completer<void>();
    final revealing = controller.reveal(item);
    await pumpEventQueue();
    controller.lock();
    store.pending.complete();
    await revealing;

    expect(
      controller.secretFor(item.id),
      isNull,
      reason: 'the plaintext arrived after the vault was told to forget',
    );
  });

  /// A copy is the most-used action on this screen and it said nothing at all.
  ///
  /// A failure has been shown in red all along, so success and failure were
  /// told apart by one of them being invisible. Android's own copy preview used
  /// to cover it, and `EXTRA_IS_SENSITIVE` is what suppresses that preview --
  /// which makes the silence this app's doing rather than the platform's.
  group('a copy says whether it happened', () {
    setUp(() => SharedPreferences.setMockInitialValues({}));

    test('a successful copy leaves a notice naming the item', () async {
      final controller = VaultController(
        store: _MemoryVaultStore(),
        copy: (_) async {},
      );
      addTearDown(controller.dispose);
      await controller.unlock();
      expect(controller.notice, isNull);

      await controller.copy(controller.items.single);

      expect(controller.notice, contains('Example'));
      expect(controller.error, isNull);
    });

    test('a refused copy leaves the error and no notice', () async {
      final controller = VaultController(
        store: _MemoryVaultStore(),
        copy: (_) async => throw PlatformException(code: 'not_found'),
      );
      addTearDown(controller.dispose);
      await controller.unlock();

      await controller.copy(controller.items.single);

      expect(
        controller.notice,
        isNull,
        reason: 'nothing reached the clipboard, so nothing may say it did',
      );
      expect(controller.error, isNotNull);
    });

    test('the next action clears what the last one said', () async {
      final controller = VaultController(
        store: _MemoryVaultStore(),
        copy: (_) async {},
      );
      addTearDown(controller.dispose);
      await controller.unlock();
      await controller.copy(controller.items.single);
      expect(controller.notice, isNotNull);

      controller.lock();

      expect(controller.notice, isNull);
    });
  });
}

/// A store whose reads wait, the way the Keystore prompt makes them wait.
class _SlowStore extends _MemoryVaultStore {
  Completer<void> pending = Completer<void>();

  @override
  Future<VaultPage> listPage([String? cursor]) async {
    await pending.future;
    return super.listPage(cursor);
  }

  @override
  Future<VaultSecret> fetch(String id) async {
    await pending.future;
    return super.fetch(id);
  }
}

class _MemoryVaultStore extends VaultStore {
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
  Future<VaultPage> listPage([String? cursor]) async =>
      VaultPage(items: _values.values.map((value) => value.summary).toList());

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
  Future<VaultWrite> create(VaultItemInput item) async {
    final id = 'item-${_values.length}';
    _values[id] = (summary: _summary(id, 1, item), secret: item.secret);
    return VaultWrite(id: id, revision: 1);
  }

  @override
  Future<VaultWrite> update(
    VaultItemSummary current,
    VaultItemInput item,
  ) async {
    _values[current.id] = (
      summary: _summary(current.id, current.revision + 1, item),
      secret: item.secret,
    );
    return VaultWrite(id: current.id, revision: current.revision + 1);
  }

  @override
  Future<List<VaultItemSummary>?> delete(VaultItemSummary item) async {
    _values.remove(item.id);
    return null;
  }

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

/// A store that answers a write with the vault the write left behind, the way
/// the phone's own store does.
///
/// Counts reads rather than writes, because a read of this vault is a
/// fingerprint: the Keystore key is auth-per-use.
class _AnsweringStore extends _MemoryVaultStore {
  int reads = 0;

  @override
  Future<List<VaultItemSummary>> listAll() async {
    reads++;
    return super.listAll();
  }

  @override
  Future<VaultWrite> create(VaultItemInput item) async {
    final written = await super.create(item);
    return VaultWrite(
      id: written.id,
      revision: written.revision,
      items: await super.listAll(),
    );
  }

  @override
  Future<VaultWrite> update(
    VaultItemSummary current,
    VaultItemInput item,
  ) async {
    final written = await super.update(current, item);
    return VaultWrite(
      id: written.id,
      revision: written.revision,
      items: await super.listAll(),
    );
  }

  @override
  Future<List<VaultItemSummary>?> delete(VaultItemSummary item) async {
    await super.delete(item);
    return super.listAll();
  }
}

/// A vault that does not answer until it is told to, standing in for the wait
/// on the Keystore prompt.
class _BlockingVaultStore extends VaultStore {
  final _held = Completer<VaultPage>();

  void answer() => _held.complete(const VaultPage(items: []));

  @override
  Future<VaultPage> listPage([String? cursor]) => _held.future;

  // Nothing below is reached: unlocking is the only thing these tests start.
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
