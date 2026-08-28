/// Writes the versioned backup fixture that `vault_restore_drill_test.dart`
/// opens.
///
/// Run only when adding a *new* schema version. Regenerating an existing
/// fixture defeats it: the file is checked in precisely so that today's code
/// is tested against bytes today's code did not produce.
///
/// Shaped as a test because the store it imports reaches
/// `package:flutter/services.dart`, which needs a binding that plain
/// `dart run` does not provide.
///
///   flutter test tool/make_vault_fixture.dart
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/vault/vault_export.dart';
import 'package:phone_auth/features/vault/vault_store.dart';

/// Fixed so the fixture is reproducible and reviewable. A real export draws
/// all three from the CSPRNG; nothing here is a key anybody uses.
final _key = VaultExportKey(
  Uint8List.fromList(List<int>.generate(32, (index) => index * 7 % 256)),
);
final _salt = Uint8List.fromList(List<int>.generate(16, (index) => index));
final _nonce = Uint8List.fromList(
  List<int>.generate(12, (index) => 200 - index),
);

void main() {
  test('writes the versioned backup fixture', () async {
    final file = await sealVaultExport(
      items: const [
        VaultExportItem(
          kind: VaultItemKind.login,
          name: 'Banco',
          username: 'alice',
          uri: 'https://banco.example.com/login',
          secret: 'hunter2',
        ),
        VaultExportItem(
          kind: VaultItemKind.note,
          name: 'Cofre físico',
          username: '',
          uri: '',
          // Non-ASCII on purpose: a codec change that broke UTF-8 would still
          // pass a fixture made only of letters.
          secret: 'a combinação é 31-14-15 — não perca',
        ),
      ],
      key: _key,
      createdAt: DateTime.utc(2026, 8, 28, 12),
      salt: _salt,
      nonce: _nonce,
    );

    const path = 'test/fixtures/vault-export-v1.bakv';
    // Refusing rather than overwriting is the point. A fixture regenerated to
    // make the drill pass is a drill that tests the encoder against itself,
    // and it would look green while every existing backup had stopped opening.
    if (File(path).existsSync()) {
      fail(
        '$path already exists. A change that cannot read it needs a version 2 '
        'and a reader for version 1, not a new fixture. Delete it by hand only '
        'if you are certain no release ever wrote this version.',
      );
    }
    await File(path).writeAsBytes(file);
    stdout.writeln('wrote $path (${file.length} bytes)');
    stdout.writeln('code: ${_key.format()}');
  });
}
