/// The encrypted export that lets a vault survive the phone holding it.
///
/// Everything else in this project is deliberately bound to one device: the
/// Keystore keys cannot leave, and losing the phone loses what they protect.
/// That is the right default and the wrong only option, so this is the way
/// out — one file, encrypted under a code the user keeps somewhere else, that
/// a new phone can read.
///
/// The construction is the locker's, deliberately. A 32-byte key drawn from
/// the system CSPRNG is rendered as a code and never stored; HKDF-SHA256
/// spreads it into the key that actually encrypts; ChaCha20-Poly1305 seals the
/// items with the header as associated data. There is no passphrase and so no
/// password KDF: a code the user cannot choose cannot be guessed, and offering
/// a passphrase would let someone pick one worth less than the vault it holds.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../protocol/cbor.dart';
import '../../features/vault/vault_store.dart';

/// Marks the file's version, so a future scheme is distinguishable on sight
/// rather than by failing to decrypt.
const int vaultExportSchema = 1;

const String _codePrefix = 'BAV1';

/// RFC 4648 base32 without `0`, `1`, `8` or `9`, so a digit typed in place of
/// a letter is rejected instead of quietly decoding to something else. The
/// same alphabet the locker's recovery code uses.
const String _alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

const int _codeGroup = 4;
const int _keyLength = 32;
const int _saltLength = 16;
const int _nonceLength = 12;

const String _kdfInfo = 'bioauth-vault-export-v1';

/// A vault big enough to be this file is a vault that was not exported, and
/// refusing is better than an out-of-memory on a phone. The store's own
/// ceiling, so anything that fits in a vault fits in a backup of it.
const int maxExportItems = maxVaultItems;

class VaultExportException implements Exception {
  const VaultExportException(this.message);
  final String message;

  @override
  String toString() => message;
}

/// One item as it travels inside an export. Carries the secret, which is why
/// nothing constructs this outside the sealed payload.
class VaultExportItem {
  const VaultExportItem({
    required this.kind,
    required this.name,
    required this.username,
    required this.uri,
    required this.secret,
  });

  final VaultItemKind kind;
  final String name;
  final String username;
  final String uri;
  final String secret;

  VaultItemInput toInput() => VaultItemInput(
    kind: kind,
    name: name,
    username: username,
    uri: uri,
    secret: secret,
  );
}

/// What a file says about itself before anyone has the key.
///
/// The count and the timestamp are outside the ciphertext on purpose: a
/// restore screen has to be able to say *what it is about to do* before the
/// user types a code. They are covered by the AEAD's associated data, so a
/// file claiming to hold three items and holding three hundred fails to open
/// rather than surprising the user.
class VaultExportHeader {
  const VaultExportHeader({
    required this.schema,
    required this.createdAt,
    required this.itemCount,
  });

  final int schema;
  final DateTime createdAt;
  final int itemCount;
}

/// The key behind an export code.
class VaultExportKey {
  VaultExportKey(this.bytes)
    : assert(bytes.length == _keyLength, 'export keys are 32 bytes');

  final Uint8List bytes;

  /// Draws a fresh key from the system CSPRNG.
  ///
  /// `Random.secure()` and not `Random()`: the ordinary one is seeded from the
  /// clock, and an export key a stopwatch can narrow down is not a key.
  factory VaultExportKey.random() {
    final random = Random.secure();
    return VaultExportKey(
      Uint8List.fromList(
        List<int>.generate(_keyLength, (_) => random.nextInt(256)),
      ),
    );
  }

  /// `BAV1-` followed by base32, uppercase, in groups of four.
  String format() {
    final buffer = StringBuffer(_codePrefix);
    var accumulator = 0;
    var bits = 0;
    var written = 0;

    void push(int index) {
      if (written % _codeGroup == 0) buffer.write('-');
      buffer.write(_alphabet[index]);
      written++;
    }

    for (final byte in bytes) {
      accumulator = (accumulator << 8) | byte;
      bits += 8;
      while (bits >= 5) {
        bits -= 5;
        push((accumulator >> bits) & 31);
      }
    }
    if (bits > 0) push((accumulator << (5 - bits)) & 31);
    return buffer.toString();
  }

  /// Reads a code back. Case, dashes, underscores and whitespace are ignored,
  /// because this is a string a person copies by hand.
  ///
  /// There is no checksum: a wrong code fails on the AEAD tag, which is the
  /// check that matters and the only one that cannot be fooled.
  factory VaultExportKey.parse(String code) {
    final cleaned = code.replaceAll(RegExp(r'[\s\-_]'), '').toUpperCase();
    if (!cleaned.startsWith(_codePrefix)) {
      throw const VaultExportException(
        'Este código não é de um backup de cofre',
      );
    }

    final body = cleaned.substring(_codePrefix.length);
    final out = <int>[];
    var accumulator = 0;
    var bits = 0;
    for (final character in body.split('')) {
      final index = _alphabet.indexOf(character);
      if (index < 0) {
        throw const VaultExportException('O código tem um caractere inválido');
      }
      accumulator = (accumulator << 5) | index;
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        out.add((accumulator >> bits) & 0xff);
      }
    }
    if (out.length != _keyLength) {
      throw const VaultExportException('O código está incompleto');
    }
    return VaultExportKey(Uint8List.fromList(out));
  }
}

/// Seals a vault into one file.
///
/// The caller supplies the key so that the code can be shown to the user and
/// the same key reused if they export twice in a row; nothing here stores it.
Future<Uint8List> sealVaultExport({
  required List<VaultExportItem> items,
  required VaultExportKey key,
  required DateTime createdAt,
  Uint8List? salt,
  Uint8List? nonce,
}) async {
  if (items.length > maxExportItems) {
    throw const VaultExportException('Cofre grande demais para exportar');
  }
  final random = Random.secure();
  final actualSalt =
      salt ??
      Uint8List.fromList(
        List<int>.generate(_saltLength, (_) => random.nextInt(256)),
      );
  final actualNonce =
      nonce ??
      Uint8List.fromList(
        List<int>.generate(_nonceLength, (_) => random.nextInt(256)),
      );

  final header = _encodeHeader(
    salt: actualSalt,
    nonce: actualNonce,
    createdAt: createdAt,
    itemCount: items.length,
  );
  final sealed = await Chacha20.poly1305Aead().encrypt(
    _encodeItems(items),
    secretKey: await _derive(key, actualSalt),
    nonce: actualNonce,
    aad: header,
  );

  final writer = CborWriter()
    ..array(2)
    ..bytes(header)
    ..bytes([...sealed.cipherText, ...sealed.mac.bytes]);
  return writer.takeBytes();
}

/// Reads what a file says about itself, without the key.
VaultExportHeader inspectVaultExport(Uint8List file) {
  final (header, _) = _split(file);
  return _decodeHeader(header);
}

/// Opens a file with the code the user typed.
///
/// A wrong code, a truncated file and a file somebody edited all fail here,
/// with the same message: the tag does not distinguish between them and
/// neither should the screen.
Future<List<VaultExportItem>> openVaultExport(
  Uint8List file,
  VaultExportKey key,
) async {
  final (header, sealed) = _split(file);
  final described = _decodeHeader(header);
  if (sealed.length < 16) {
    throw const VaultExportException('O arquivo de backup está truncado');
  }

  final reader = CborReader(header);
  reader.array();
  reader.uint();
  final salt = reader.bytes();
  final nonce = reader.bytes();

  final Uint8List plaintext;
  try {
    plaintext = Uint8List.fromList(
      await Chacha20.poly1305Aead().decrypt(
        SecretBox(
          sealed.sublist(0, sealed.length - 16),
          nonce: nonce,
          mac: Mac(sealed.sublist(sealed.length - 16)),
        ),
        secretKey: await _derive(key, salt),
        // The same header the seal covered. Leaving it out here is the bug
        // that makes every file fail to open, and every tampering test pass
        // for the wrong reason.
        aad: header,
      ),
    );
  } on Object {
    throw const VaultExportException(
      'O código não abre este arquivo, ou o arquivo foi alterado',
    );
  }

  final items = _decodeItems(plaintext);
  // The count outside the ciphertext is covered by the AEAD, so this can only
  // disagree if the encoder was wrong. Checking anyway costs nothing and keeps
  // the restore screen's promise honest.
  if (items.length != described.itemCount) {
    throw const VaultExportException('O backup se contradiz sobre o conteúdo');
  }
  return items;
}

Future<SecretKey> _derive(VaultExportKey key, Uint8List salt) async {
  final derived = await Hkdf(hmac: Hmac.sha256(), outputLength: _keyLength)
      .deriveKey(
        secretKey: SecretKey(key.bytes),
        nonce: salt,
        info: utf8.encode(_kdfInfo),
      );
  return derived;
}

Uint8List _encodeHeader({
  required Uint8List salt,
  required Uint8List nonce,
  required DateTime createdAt,
  required int itemCount,
}) {
  final writer = CborWriter()
    ..array(5)
    ..uint(vaultExportSchema)
    ..bytes(salt)
    ..bytes(nonce)
    ..int64(createdAt.toUtc().millisecondsSinceEpoch)
    ..uint(itemCount);
  return writer.takeBytes();
}

VaultExportHeader _decodeHeader(Uint8List header) {
  try {
    final reader = CborReader(header);
    if (reader.array() != 5) {
      throw const VaultExportException('Cabeçalho de backup inválido');
    }
    final schema = reader.uint();
    if (schema != vaultExportSchema) {
      throw VaultExportException(
        'Este backup é da versão $schema; este aplicativo lê a '
        '$vaultExportSchema',
      );
    }
    reader.bytes();
    reader.bytes();
    final createdAtMs = reader.int64();
    final itemCount = reader.uint();
    reader.finish();
    if (itemCount > maxExportItems) {
      throw const VaultExportException('Backup grande demais para restaurar');
    }
    return VaultExportHeader(
      schema: schema,
      createdAt: DateTime.fromMillisecondsSinceEpoch(createdAtMs, isUtc: true),
      itemCount: itemCount,
    );
  } on CborException {
    throw const VaultExportException('Cabeçalho de backup inválido');
  }
}

(Uint8List, Uint8List) _split(Uint8List file) {
  try {
    final reader = CborReader(file);
    if (reader.array() != 2) {
      throw const VaultExportException('Isto não é um backup de cofre');
    }
    final header = reader.bytes();
    final sealed = reader.bytes();
    reader.finish();
    return (header, sealed);
  } on CborException {
    throw const VaultExportException('Isto não é um backup de cofre');
  }
}

Uint8List _encodeItems(List<VaultExportItem> items) {
  final writer = CborWriter()..array(items.length);
  for (final item in items) {
    writer
      ..array(5)
      ..uint(item.kind.index)
      ..text(item.name)
      ..text(item.username)
      ..text(item.uri)
      ..text(item.secret);
  }
  return writer.takeBytes();
}

List<VaultExportItem> _decodeItems(Uint8List payload) {
  try {
    final reader = CborReader(payload);
    final count = reader.array();
    if (count > maxExportItems) {
      throw const VaultExportException('Backup grande demais para restaurar');
    }
    final items = <VaultExportItem>[];
    for (var index = 0; index < count; index++) {
      if (reader.array() != 5) {
        throw const VaultExportException('Item inválido no backup');
      }
      final kind = reader.uint();
      if (kind >= VaultItemKind.values.length) {
        throw const VaultExportException('Tipo de item desconhecido no backup');
      }
      items.add(
        VaultExportItem(
          kind: VaultItemKind.values[kind],
          name: reader.text(),
          username: reader.text(),
          uri: reader.text(),
          secret: reader.text(),
        ),
      );
    }
    reader.finish();
    return items;
  } on CborException {
    throw const VaultExportException('O conteúdo do backup está corrompido');
  }
}
