import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/vault/vault_export.dart';
import 'package:phone_auth/features/vault/vault_store.dart';

void main() {
  final createdAt = DateTime.utc(2026, 8, 28, 12);

  List<VaultExportItem> sample() => const [
    VaultExportItem(
      kind: VaultItemKind.login,
      name: 'Banco',
      username: 'alice',
      uri: 'https://banco.example.com',
      secret: 'hunter2',
    ),
    VaultExportItem(
      kind: VaultItemKind.note,
      name: 'Cofre físico',
      username: '',
      uri: '',
      secret: 'a combinação é 31-14-15',
    ),
  ];

  test('a sealed vault comes back through its own code', () async {
    final key = VaultExportKey.random();
    final file = await sealVaultExport(
      items: sample(),
      key: key,
      createdAt: createdAt,
    );

    final reopened = await openVaultExport(
      file,
      VaultExportKey.parse(key.format()),
    );

    expect(reopened, hasLength(2));
    expect(reopened.first.name, 'Banco');
    expect(reopened.first.secret, 'hunter2');
    expect(reopened.last.kind, VaultItemKind.note);
    expect(reopened.last.secret, 'a combinação é 31-14-15');
  });

  /// The whole point of the file is that it is useless on its own. If any of
  /// this shows up in the bytes, the export is a plaintext dump with a
  /// ceremony around it.
  test('nothing readable survives into the file', () async {
    final file = await sealVaultExport(
      items: sample(),
      key: VaultExportKey.random(),
      createdAt: createdAt,
    );
    final bytes = String.fromCharCodes(file);

    for (final secret in ['hunter2', 'Banco', 'alice', 'banco.example.com']) {
      expect(
        bytes.contains(secret),
        isFalse,
        reason: '`$secret` is legible in the exported file',
      );
    }
  });

  test(
    'a restore screen can describe the file before asking for a code',
    () async {
      final file = await sealVaultExport(
        items: sample(),
        key: VaultExportKey.random(),
        createdAt: createdAt,
      );

      final header = inspectVaultExport(file);

      expect(header.itemCount, 2);
      expect(header.createdAt, createdAt);
      expect(header.schema, vaultExportSchema);
    },
  );

  test('a wrong code is refused', () async {
    final file = await sealVaultExport(
      items: sample(),
      key: VaultExportKey.random(),
      createdAt: createdAt,
    );

    expect(
      () => openVaultExport(file, VaultExportKey.random()),
      throwsA(isA<VaultExportException>()),
    );
  });

  /// The count sits outside the ciphertext so the restore screen can show it.
  /// It is covered by the AEAD's associated data, so a file that lies about
  /// what it holds must fail to open rather than open and surprise the user.
  test('editing the header stops the file from opening', () async {
    final key = VaultExportKey.random();
    final file = await sealVaultExport(
      items: sample(),
      key: key,
      createdAt: createdAt,
    );

    // Rebuild with the item count changed, keeping the same ciphertext.
    final tampered = Uint8List.fromList(file);
    final claimed = tampered.lastIndexOf(2);
    expect(claimed, greaterThan(0), reason: 'the count is in the header');
    tampered[claimed] = 3;

    expect(
      () => openVaultExport(tampered, key),
      throwsA(isA<VaultExportException>()),
    );
  });

  test('flipping one byte of the ciphertext is caught', () async {
    final key = VaultExportKey.random();
    final file = await sealVaultExport(
      items: sample(),
      key: key,
      createdAt: createdAt,
    );

    final tampered = Uint8List.fromList(file);
    tampered[tampered.length - 20] ^= 0x01;

    expect(
      () => openVaultExport(tampered, key),
      throwsA(isA<VaultExportException>()),
    );
  });

  group('the code', () {
    test('survives the way a person retypes it', () {
      final key = VaultExportKey.random();
      final formatted = key.format();

      final retyped = VaultExportKey.parse(
        '  ${formatted.toLowerCase().replaceAll('-', ' ')}  ',
      );

      expect(retyped.bytes, key.bytes);
    });

    test('is grouped and prefixed so it is recognisable on sight', () {
      final code = VaultExportKey.random().format();

      expect(code.startsWith('BAV1-'), isTrue);
      for (final group in code.split('-').skip(1)) {
        expect(group.length, lessThanOrEqualTo(4));
      }
    });

    /// The alphabet has no `0`, `1`, `8` or `9`. A digit typed where a letter
    /// belongs has to be rejected, not decoded into a different key that then
    /// fails somewhere less legible.
    test('rejects the digits that look like letters', () {
      for (final digit in ['0', '1', '8', '9']) {
        expect(
          () => VaultExportKey.parse('BAV1-ABCD-EFG$digit'),
          throwsA(isA<VaultExportException>()),
          reason: digit,
        );
      }
    });

    test('rejects a code of the wrong length', () {
      expect(
        () => VaultExportKey.parse('BAV1-ABCD'),
        throwsA(isA<VaultExportException>()),
      );
    });

    test('rejects a code that is not a vault backup', () {
      // `BAL1` is the locker's. Two codes that look alike must not be
      // interchangeable, or a user hands over the wrong one and learns the
      // difference from a decryption failure.
      expect(
        () => VaultExportKey.parse('BAL1-ABCD-EFGH'),
        throwsA(isA<VaultExportException>()),
      );
    });
  });

  test('a file that is not an export is refused, not parsed', () {
    expect(
      () => inspectVaultExport(Uint8List.fromList([1, 2, 3, 4])),
      throwsA(isA<VaultExportException>()),
    );
  });

  test('an empty vault still exports and restores', () async {
    final key = VaultExportKey.random();
    final file = await sealVaultExport(
      items: const [],
      key: key,
      createdAt: createdAt,
    );

    expect(inspectVaultExport(file).itemCount, 0);
    expect(await openVaultExport(file, key), isEmpty);
  });
}
