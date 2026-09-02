/// The drill the backup exists for: a vault leaves one phone and lands on
/// another that has never seen it.
///
/// The format itself is covered in `vault_export_test.dart`. What is exercised
/// here is the controller path — export, code, restore — and the promise that
/// a restore adds instead of replacing.
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/features/vault/vault_controller.dart';
import 'package:phone_auth/features/vault/vault_store.dart';
import 'package:phone_auth/core/vault/vault_export.dart';

void main() {
  VaultItemInput input(String name, String secret) => VaultItemInput(
    kind: VaultItemKind.login,
    name: name,
    username: 'alice',
    uri: 'https://$name.example.com',
    secret: secret,
  );

  test('a vault moves to a phone that has never seen it', () async {
    final oldPhone = _MemoryStore()
      ..seed(input('banco', 'hunter2'))
      ..seed(input('email', 'correct horse'));
    final backup = await VaultController(store: oldPhone).exportBackup();
    expect(backup, isNotNull, reason: 'the export must have produced a file');
    expect(backup!.itemCount, 2);

    final newPhone = _MemoryStore();
    final controller = VaultController(store: newPhone);
    final outcome = await controller.restoreBackup(backup.bytes, backup.code);

    expect(controller.failure, isNull);
    expect(outcome!.added, 2);
    expect(outcome.skipped, 0);
    expect(await newPhone.fetchByName('banco'), 'hunter2');
    expect(await newPhone.fetchByName('email'), 'correct horse');
  });

  /// One wrong file must not cost the user everything stored since the backup
  /// was made, so a restore adds and never replaces.
  test('restoring into a vault in use keeps what is already there', () async {
    final source = _MemoryStore()..seed(input('banco', 'hunter2'));
    final backup = await VaultController(store: source).exportBackup();

    final target = _MemoryStore()..seed(input('trabalho', 'nao apague'));
    final outcome = await VaultController(
      store: target,
    ).restoreBackup(backup!.bytes, backup.code);

    expect(outcome!.added, 1);
    expect(await target.fetchByName('trabalho'), 'nao apague');
    expect(await target.fetchByName('banco'), 'hunter2');
  });

  test('restoring the same file twice adds nothing the second time', () async {
    final source = _MemoryStore()..seed(input('banco', 'hunter2'));
    final backup = await VaultController(store: source).exportBackup();
    final target = _MemoryStore();

    final first = await VaultController(
      store: target,
    ).restoreBackup(backup!.bytes, backup.code);
    final second = await VaultController(
      store: target,
    ).restoreBackup(backup.bytes, backup.code);

    expect(first!.added, 1);
    expect(second!.added, 0);
    expect(second.skipped, 1);
    expect((await target.listAll()).length, 1);
  });

  test('a wrong code changes nothing and says which half failed', () async {
    final source = _MemoryStore()..seed(input('banco', 'hunter2'));
    final backup = await VaultController(store: source).exportBackup();
    final target = _MemoryStore();
    final controller = VaultController(store: target);

    final outcome = await controller.restoreBackup(
      backup!.bytes,
      'BAV1-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA',
    );

    expect(outcome, isNull);
    // Not the generic vault message: the user has to know it was the code and
    // not the file, or they go looking for the wrong problem.
    expect(
      (controller.failure! as VaultBackupFailure).problem,
      BackupProblem.wrongCodeOrEdited,
    );
    expect(await target.listAll(), isEmpty);
  });

  test(
    'a code that is not a code is refused before anything is written',
    () async {
      final target = _MemoryStore();
      final controller = VaultController(store: target);

      final outcome = await controller.restoreBackup(
        await VaultController(
          store: _MemoryStore()..seed(input('banco', 's')),
        ).exportBackup().then((backup) => backup!.bytes),
        'nao sou um codigo',
      );

      expect(outcome, isNull);
      expect(await target.listAll(), isEmpty);
    },
  );

  /// Two exports of the same vault must not produce the same bytes: a fresh
  /// salt and nonce each time is what keeps two backups from revealing that
  /// nothing changed between them.
  test('two exports of one vault differ', () async {
    final store = _MemoryStore()..seed(input('banco', 'hunter2'));
    final controller = VaultController(store: store);

    final first = await controller.exportBackup();
    final second = await controller.exportBackup();

    expect(first!.bytes, isNot(equals(second!.bytes)));
    expect(first.code, isNot(equals(second.code)));
  });
}

class _MemoryStore extends VaultStore {
  final List<VaultItemSummary> _summaries = [];
  final Map<String, String> _secrets = {};
  var _nextId = 1;

  void seed(VaultItemInput item) {
    final id = 'seed-${_nextId++}';
    _summaries.add(
      VaultItemSummary(
        id: id,
        revision: 1,
        kind: item.kind,
        name: item.name,
        username: item.username,
        uri: item.uri,
        updatedAt: DateTime.utc(2026),
      ),
    );
    _secrets[id] = item.secret;
  }

  Future<String?> fetchByName(String name) async {
    final match = _summaries.where((item) => item.name == name).firstOrNull;
    return match == null ? null : _secrets[match.id];
  }

  @override
  Future<VaultPage> listPage([String? cursor]) async =>
      VaultPage(items: List.of(_summaries));

  @override
  Future<VaultSecret> fetch(String id) async =>
      VaultSecret(id: id, revision: 1, secret: _secrets[id]!);

  @override
  Future<VaultWrite> create(VaultItemInput item) async {
    seed(item);
    return VaultWrite(id: _summaries.last.id, revision: 1);
  }

  @override
  Future<VaultWrite> update(VaultItemSummary current, VaultItemInput item) =>
      throw UnimplementedError();

  @override
  Future<List<VaultItemSummary>?> delete(VaultItemSummary item) =>
      throw UnimplementedError();
}
