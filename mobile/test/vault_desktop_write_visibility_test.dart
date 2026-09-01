/// What the phone shows after a computer writes to the vault behind it.
///
/// The vault screen reads the store exactly once, when it unlocks. Every write
/// it makes itself replaces that list as it finishes, so the gap only opens for
/// writes it did not make — which is precisely `vault.create`, the point of
/// being able to generate a password on the PC and keep it on the phone. The
/// item was stored, the sheet was approved, and the list behind the sheet still
/// did not have it. From the user's seat that is the feature not working.
///
/// The signal deliberately stops at "this list is behind". Listing decrypts the
/// vault and the key is auth-per-use, so reloading on its own would raise a
/// fingerprint prompt nobody asked for, a second after the one spent approving
/// the write.
library;

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/protocol/application_frame.dart';
import 'package:phone_auth/core/protocol/vault_payloads.dart' as wire;
import 'package:phone_auth/core/vault/vault_approval.dart';
import 'package:phone_auth/core/vault/vault_mutations.dart';
import 'package:phone_auth/core/vault/vault_service.dart';
import 'package:phone_auth/features/vault/vault_controller.dart';
import 'package:phone_auth/features/vault/vault_store.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUp(() => SharedPreferences.setMockInitialValues({}));

  final binding = Uint8List(32);
  final now = DateTime.utc(2026, 8, 31, 12);

  Uint8List createFrame() => ApplicationFrame(
    protocolVersion: 1,
    kind: ApplicationFrameKind.request,
    requestId: 'request-create',
    sessionBinding: binding,
    operation: wire.vaultCreateOperation,
    issuedAt: now,
    expiresAt: now.add(const Duration(seconds: 60)),
    payload: wire.VaultCreateRequest(
      verifierName: 'Workstation',
      kind: wire.VaultItemKind.login,
      name: 'Roteador',
      secret: 'senha-nova',
    ).encode(),
  ).encode();

  test('a write from the desktop reaches the open list', () async {
    final store = _MemoryStore();
    final mutations = VaultMutations();
    final controller = VaultController(
      store: store,
      copy: (_) async {},
      mutations: mutations,
    );
    addTearDown(controller.dispose);
    await controller.unlock();

    expect(controller.stale, isFalse);
    expect(controller.items, hasLength(1));
    final readsAfterUnlock = store.reads;

    final answer = ApplicationFrame.decode(
      await VaultService(
        repository: store,
        approval: const _Allow(),
        mutations: mutations,
      ).handle(
        createFrame(),
        sessionBinding: binding,
        authorized: true,
        now: now,
      ),
    );
    expect(answer.kind, ApplicationFrameKind.response);

    // Said, not done: the item is in the store, the list still is not, and no
    // biometric was spent saying so.
    expect(controller.stale, isTrue);
    expect(controller.items, hasLength(1));
    expect(store.reads, readsAfterUnlock);

    await controller.refresh();
    expect(controller.stale, isFalse);
    expect(
      controller.items.map((item) => item.name),
      containsAll(<String>['Example', 'Roteador']),
    );
  });

  test('a locked vault has no list to fall behind', () async {
    final store = _MemoryStore();
    final mutations = VaultMutations();
    final controller = VaultController(
      store: store,
      copy: (_) async {},
      mutations: mutations,
    );
    addTearDown(controller.dispose);

    mutations.recordWrite();

    // A banner over "O cofre está bloqueado" would be asking the user to
    // refresh a list they cannot see, and unlocking reads the store anyway.
    expect(controller.stale, isFalse);
    await controller.unlock();
    expect(controller.stale, isFalse);
  });

  test('locking again drops the warning with the list it described', () async {
    final store = _MemoryStore();
    final mutations = VaultMutations();
    final controller = VaultController(
      store: store,
      copy: (_) async {},
      mutations: mutations,
    );
    addTearDown(controller.dispose);

    await controller.unlock();
    mutations.recordWrite();
    expect(controller.stale, isTrue);

    controller.lock();
    expect(controller.stale, isFalse);
  });

  test('a write announced after the screen is gone notifies nobody', () async {
    final mutations = VaultMutations();
    final controller = VaultController(
      store: _MemoryStore(),
      copy: (_) async {},
      mutations: mutations,
    );
    await controller.unlock();
    controller.dispose();

    // The signal outlives the screen -- it is shared by the whole app -- and
    // notifying a disposed `ChangeNotifier` throws in a debug build, which is
    // the build the phone runs.
    expect(mutations.recordWrite, returnsNormally);
  });
}

class _Allow implements VaultApproval {
  const _Allow();

  @override
  Future<bool> confirm(VaultApprovalRequest request) async => true;
}

/// Counts reads, because a read of the real vault is a fingerprint.
class _MemoryStore extends VaultStore {
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
  int reads = 0;

  @override
  Future<VaultPage> listPage([String? cursor]) async {
    reads++;
    return VaultPage(
      items: _values.values.map((value) => value.summary).toList(),
    );
  }

  @override
  Future<VaultSecret> fetch(String id) async {
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
    _values[id] = (
      summary: VaultItemSummary(
        id: id,
        revision: 1,
        kind: item.kind,
        name: item.name,
        username: item.username,
        uri: item.uri,
        updatedAt: DateTime.utc(2026),
      ),
      secret: item.secret,
    );
    return VaultWrite(id: id, revision: 1);
  }

  @override
  Future<VaultWrite> update(VaultItemSummary current, VaultItemInput item) =>
      throw UnimplementedError();

  @override
  Future<List<VaultItemSummary>?> delete(VaultItemSummary item) =>
      throw UnimplementedError();
}
