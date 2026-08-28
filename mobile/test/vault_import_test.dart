import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/vault/vault_import.dart';
import 'package:phone_auth/features/vault/vault_store.dart';

Uint8List bytes(String text) => Uint8List.fromList(utf8.encode(text));

void main() {
  group('Bitwarden JSON', () {
    String export(List<Map<String, Object?>> items) =>
        jsonEncode({'encrypted': false, 'items': items});

    test('reads logins and notes', () async {
      final preview = await parseVaultImport(
        bytes(
          export([
            {
              'type': 1,
              'name': 'Banco',
              'login': {
                'username': 'alice',
                'password': 'hunter2',
                'uris': [
                  {'uri': 'https://banco.example.com'},
                ],
              },
            },
            {'type': 2, 'name': 'Cofre físico', 'notes': '31-14-15'},
          ]),
        ),
      );

      expect(preview.rejections, isEmpty);
      expect(preview.items, hasLength(2));
      expect(preview.items.first.kind, VaultItemKind.login);
      expect(preview.items.first.username, 'alice');
      expect(preview.items.first.uri, 'https://banco.example.com');
      expect(preview.items.first.secret, 'hunter2');
      expect(preview.items.last.kind, VaultItemKind.note);
      expect(preview.items.last.secret, '31-14-15');
    });

    /// There is nothing here that could ask for the Bitwarden password, so an
    /// encrypted export has to say what to do rather than fail as bad JSON.
    test('an encrypted export says what to do about it', () async {
      expect(
        () => parseVaultImport(
          bytes(jsonEncode({'encrypted': true, 'items': []})),
        ),
        throwsA(
          isA<VaultImportException>().having(
            (error) => error.message,
            'message',
            contains('sem criptografia'),
          ),
        ),
      );
    });

    /// Cards and identities have no home in this schema. Flattening them into
    /// notes would lose their structure silently, so they are reported.
    test(
      'types this vault has no shape for are reported, not flattened',
      () async {
        final preview = await parseVaultImport(
          bytes(
            export([
              {'type': 3, 'name': 'Meu cartão'},
              {
                'type': 1,
                'name': 'Banco',
                'login': {'password': 'hunter2'},
              },
            ]),
          ),
        );

        expect(preview.items, hasLength(1));
        expect(preview.rejections, hasLength(1));
        expect(preview.rejections.single.name, 'Meu cartão');
        expect(preview.rejections.single.reason, contains('tipo 3'));
      },
    );

    test('a row without a password is reported with its line number', () async {
      final preview = await parseVaultImport(
        bytes(
          export([
            {
              'type': 1,
              'name': 'Vazio',
              'login': {'username': 'alice'},
            },
          ]),
        ),
      );

      expect(preview.items, isEmpty);
      expect(preview.rejections.single.row, 1);
      expect(preview.rejections.single.reason, contains('sem senha'));
    });

    test('malformed JSON is refused', () {
      expect(
        () => parseVaultImport(bytes('{"items": [')),
        throwsA(isA<VaultImportException>()),
      );
    });
  });

  group('CSV', () {
    test("reads Bitwarden's own column names", () async {
      final preview = await parseVaultImport(
        bytes(
          'folder,favorite,type,name,notes,fields,login_uri,login_username,login_password\n'
          ',,login,Banco,,,https://banco.example.com,alice,hunter2\n',
        ),
      );

      expect(preview.rejections, isEmpty);
      expect(preview.items.single.name, 'Banco');
      expect(preview.items.single.username, 'alice');
      expect(preview.items.single.secret, 'hunter2');
    });

    test('reads the plain column names other managers use', () async {
      final preview = await parseVaultImport(
        bytes(
          'title,username,password,url\nBanco,alice,hunter2,https://b.example\n',
        ),
      );

      expect(preview.items.single.name, 'Banco');
      expect(preview.items.single.uri, 'https://b.example');
    });

    /// Quoting is where hand-rolled CSV parsers go wrong, and a password with
    /// a comma in it is not unusual.
    test('a quoted field with a comma survives', () async {
      final preview = await parseVaultImport(
        bytes('name,password\nBanco,"hunter2,with,commas"\n'),
      );

      expect(preview.items.single.secret, 'hunter2,with,commas');
    });

    test('a row with a note and no password becomes a note', () async {
      final preview = await parseVaultImport(
        bytes('name,password,notes\nLembrete,,o portão é 4417\n'),
      );

      expect(preview.items.single.kind, VaultItemKind.note);
      expect(preview.items.single.secret, 'o portão é 4417');
    });

    /// A trailing newline is normal and must not show up as a rejection, or
    /// the real rejections get buried.
    test('a trailing blank line is not a rejection', () async {
      final preview = await parseVaultImport(
        bytes('name,password\nBanco,hunter2\n\n'),
      );

      expect(preview.items, hasLength(1));
      expect(preview.rejections, isEmpty);
    });

    /// Exporters in locales that use the comma as a decimal separator emit
    /// semicolon-delimited CSV. Reading one of those with commas gives rows
    /// that look plausible and are wrong.
    test('a semicolon-delimited file is read as one', () async {
      final preview = await parseVaultImport(
        bytes('name;username;password\nBanco;alice;hunter2\n'),
      );

      expect(preview.items.single.username, 'alice');
      expect(preview.items.single.secret, 'hunter2');
    });

    /// The delimiter comes from the header line alone. Counting over the whole
    /// file would let one password full of semicolons outvote it.
    test(
      'a password full of semicolons does not change the delimiter',
      () async {
        final preview = await parseVaultImport(
          bytes('name,password\nBanco,";;;;;;;;;;"\n'),
        );

        expect(preview.items.single.secret, ';;;;;;;;;;');
      },
    );

    test('a file with no name column is refused up front', () {
      expect(
        () => parseVaultImport(bytes('username,password\nalice,hunter2\n')),
        throwsA(
          isA<VaultImportException>().having(
            (error) => error.message,
            'message',
            contains('coluna de nome'),
          ),
        ),
      );
    });

    test('rejections carry the row number a spreadsheet shows', () async {
      final preview = await parseVaultImport(
        bytes('name,password\nBanco,hunter2\n,semnome\nOutro,\n'),
      );

      expect(preview.items, hasLength(1));
      expect(preview.rejections.map((r) => r.row), [3, 4]);
    });

    /// A field longer than the store accepts must be a line number on a
    /// preview, not a failure part-way through writing the vault.
    test('a field over the store limit is refused before any write', () async {
      final preview = await parseVaultImport(
        bytes('name,password\n${'n' * 300},hunter2\n'),
      );

      expect(preview.items, isEmpty);
      expect(preview.rejections.single.reason, contains('nome longo'));
    });
  });

  test('a file that is not text is refused with a reason', () {
    expect(
      () => parseVaultImport(Uint8List.fromList([0xff, 0xfe, 0x00, 0x01])),
      throwsA(
        isA<VaultImportException>().having(
          (error) => error.message,
          'message',
          contains('UTF-8'),
        ),
      ),
    );
  });

  /// The format is chosen from the bytes, not the extension: an extension is a
  /// hint somebody's file manager wrote down.
  test('JSON in a file named like a CSV still imports', () async {
    final preview = await parseVaultImport(
      bytes(
        jsonEncode({
          'items': [
            {
              'type': 1,
              'name': 'Banco',
              'login': {'password': 'hunter2'},
            },
          ],
        }),
      ),
    );

    expect(preview.items.single.name, 'Banco');
  });
}
