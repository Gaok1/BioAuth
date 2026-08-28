/// The drill that keeps a backup worth making.
///
/// REL-10. A backup format is a promise to a version of the app that does not
/// exist yet. The round-trip tests in `vault_export_test.dart` prove today's
/// code can read what today's code wrote, which is exactly the property that
/// stays true while the format changes underneath it.
///
/// This opens bytes that were sealed once and checked in. When it fails, every
/// backup any user has ever taken stopped opening — and it fails here, in a
/// pull request, rather than on the phone of somebody who just lost theirs.
///
/// **Never regenerate the fixture to make this pass.** A change that cannot
/// read `vault-export-v1.bakv` needs a version 2 and a reader for version 1,
/// not a new fixture. `tool/make_vault_fixture.dart` exists for adding a
/// version, not for repairing one.
library;

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/vault/vault_export.dart';
import 'package:phone_auth/features/vault/vault_store.dart';

/// The code printed when the fixture was made. Public in a test file because
/// the fixture protects nothing: it holds two invented items.
const _code =
    'BAV1-AADQ-4FI4-EMVD-COB7-IZGV-IW3C-NFYH-O7UF-RSJZ-VINI-V63L-3RGL-2LMQ';

void main() {
  final fixture = File('test/fixtures/vault-export-v1.bakv').readAsBytesSync();

  test('a version 1 backup still opens', () async {
    final items = await openVaultExport(fixture, VaultExportKey.parse(_code));

    expect(items, hasLength(2));
    expect(items.first.kind, VaultItemKind.login);
    expect(items.first.name, 'Banco');
    expect(items.first.username, 'alice');
    expect(items.first.uri, 'https://banco.example.com/login');
    expect(items.first.secret, 'hunter2');

    expect(items.last.kind, VaultItemKind.note);
    expect(items.last.name, 'Cofre físico');
    // Non-ASCII on purpose: a codec change that broke UTF-8 would still pass a
    // fixture made only of letters.
    expect(items.last.secret, 'a combinação é 31-14-15 — não perca');
  });

  test('its header reads without the code, as a restore screen needs', () {
    final header = inspectVaultExport(fixture);

    expect(header.schema, 1);
    expect(header.itemCount, 2);
    expect(header.createdAt, DateTime.utc(2026, 8, 28, 12));
  });

  /// The whole point of a fixture is that it was not produced by the code
  /// under test. If sealing the same inputs today reproduced these bytes, the
  /// test would be circular the moment someone regenerated it.
  test('the fixture is bytes, not a re-run of the encoder', () async {
    final now = await sealVaultExport(
      items: const [
        VaultExportItem(
          kind: VaultItemKind.login,
          name: 'Banco',
          username: 'alice',
          uri: 'https://banco.example.com/login',
          secret: 'hunter2',
        ),
      ],
      key: VaultExportKey.parse(_code),
      createdAt: DateTime.utc(2026, 8, 28, 12),
    );

    expect(now, isNot(equals(fixture)));
  });

  /// A restored backup has to land in a vault, not just decode. This is the
  /// half of the drill that would catch a store whose bounds drifted away from
  /// what the format allows.
  test('what comes out of the fixture is accepted by the store', () async {
    final items = await openVaultExport(fixture, VaultExportKey.parse(_code));
    final store = _MemoryStore();

    final outcome = await store.restore([
      for (final item in items) item.toInput(),
    ]);

    expect(outcome.added, 2);
    expect((await store.listAll()).map((item) => item.name), [
      'Banco',
      'Cofre físico',
    ]);
  });
}

class _MemoryStore extends VaultStore {
  final List<VaultItemSummary> _items = [];
  final Map<String, String> _secrets = {};

  @override
  Future<VaultPage> listPage([String? cursor]) async =>
      VaultPage(items: List.of(_items));

  @override
  Future<VaultSecret> fetch(String id) async =>
      VaultSecret(id: id, revision: 1, secret: _secrets[id]!);

  @override
  Future<VaultWrite> create(VaultItemInput item) async {
    final id = 'item-${_items.length + 1}';
    _items.add(
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
    return VaultWrite(id: id, revision: 1);
  }

  @override
  Future<VaultWrite> update(VaultItemSummary current, VaultItemInput item) =>
      throw UnimplementedError();

  @override
  Future<void> delete(VaultItemSummary item) => throw UnimplementedError();
}
