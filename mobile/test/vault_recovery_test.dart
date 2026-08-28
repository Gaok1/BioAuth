/// What happens when the vault cannot be opened at all.
///
/// VLT-13. Three failures are permanent from this app's side — a key a new
/// biometric enrolment invalidated, a file that fails its authentication tag,
/// and a store written by a newer build — and they used to arrive as the same
/// sentence as a cancelled fingerprint. A user who cannot tell those apart
/// retries forever on two of them and deletes their vault on the third.
library;

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/features/vault/vault_controller.dart';
import 'package:phone_auth/features/vault/vault_store.dart';

void main() {
  Future<VaultController> failing(String code) async {
    final controller = VaultController(store: _FailingStore(code));
    await controller.unlock();
    return controller;
  }

  test('a transient failure stays retryable', () async {
    final controller = await failing('authentication_cancelled');

    expect(controller.error, 'Autenticação cancelada.');
    expect(controller.unrecoverable, isFalse);
    expect(controller.canDiscard, isFalse);
  });

  /// The one most likely to reach a real user: enrolling a new fingerprint
  /// invalidates the key, and the vault is gone for everyone including them.
  test(
    'an invalidated key says the content is gone, and offers a way out',
    () async {
      final controller = await failing('key_invalidated');

      expect(controller.error, contains('biometria'));
      expect(controller.error, contains('backup'));
      expect(controller.unrecoverable, isTrue);
      expect(controller.canDiscard, isTrue);
    },
  );

  test('a corrupt store says so rather than blaming the fingerprint', () async {
    final controller = await failing('store_corrupt');

    expect(controller.error, contains('integridade'));
    expect(controller.canDiscard, isTrue);
  });

  /// A store from a newer build is unreadable *here* and perfectly readable
  /// after an update. Offering to discard it would be a button that destroys
  /// data a version bump recovers.
  test('a store from a newer build is never offered for discarding', () async {
    final controller = await failing('store_version_unsupported');

    expect(controller.unrecoverable, isTrue);
    expect(controller.canDiscard, isFalse);
    expect(controller.error, contains('mais nova'));
    expect(controller.error, contains('não apague'));
  });

  test(
    'a concurrent operation is reported as one, not as a vault failure',
    () async {
      final controller = await failing('operation_in_progress');

      expect(controller.error, contains('andamento'));
      expect(controller.unrecoverable, isFalse);
    },
  );

  /// The flag has to clear, or one unrecoverable failure would leave the
  /// discard button on screen for the rest of the session.
  test('a later success clears the unrecoverable state', () async {
    final store = _FailingStore('key_invalidated');
    final controller = VaultController(store: store);
    await controller.unlock();
    expect(controller.canDiscard, isTrue);

    store.code = null;
    await controller.unlock();

    expect(controller.unrecoverable, isFalse);
    expect(controller.canDiscard, isFalse);
    expect(controller.error, isNull);
    expect(controller.locked, isFalse);
  });

  test('discarding empties the vault and locks it again', () async {
    final store = _FailingStore('key_invalidated');
    final controller = VaultController(store: store);
    await controller.unlock();

    store.code = null;
    await controller.discard();

    expect(store.discarded, isTrue);
    expect(controller.locked, isTrue);
    expect(controller.items, isEmpty);
  });

  /// A store that has no way to discard must say so rather than report
  /// success. A no-op here would leave the user believing they had started
  /// over on a vault that is still sitting there.
  test('a store that cannot discard refuses instead of pretending', () async {
    final controller = VaultController(store: _UndiscardableStore());

    await controller.discard();

    expect(controller.error, isNotNull);
  });
}

class _FailingStore extends VaultStore {
  _FailingStore(this.code);

  String? code;
  bool discarded = false;

  Never _fail() => throw PlatformException(code: code!);

  @override
  Future<VaultPage> listPage([String? cursor]) async {
    if (code != null) _fail();
    return const VaultPage(items: []);
  }

  @override
  Future<void> discard() async {
    if (code != null) _fail();
    discarded = true;
  }

  @override
  Future<VaultSecret> fetch(String id) async => _fail();

  @override
  Future<VaultWrite> create(VaultItemInput item) async => _fail();

  @override
  Future<VaultWrite> update(
    VaultItemSummary current,
    VaultItemInput item,
  ) async => _fail();

  @override
  Future<void> delete(VaultItemSummary item) async => _fail();
}

/// Inherits the base refusal, which is the behaviour under test.
class _UndiscardableStore extends VaultStore {
  @override
  Future<VaultPage> listPage([String? cursor]) async =>
      const VaultPage(items: []);

  @override
  Future<VaultSecret> fetch(String id) => throw UnimplementedError();

  @override
  Future<VaultWrite> create(VaultItemInput item) => throw UnimplementedError();

  @override
  Future<VaultWrite> update(VaultItemSummary current, VaultItemInput item) =>
      throw UnimplementedError();

  @override
  Future<void> delete(VaultItemSummary item) => throw UnimplementedError();
}
