/// Reading a vault out of somebody else's export.
///
/// Two formats: Bitwarden's JSON export and a CSV with a header row, which
/// covers Bitwarden's own CSV and most of what other managers emit. Anything
/// else needs a real fixture before it gets a parser — a format guessed at
/// from documentation is a format that silently drops half of somebody's
/// passwords.
///
/// Nothing here writes to the vault. Parsing produces a [VaultImportPreview]:
/// what would be added, and what was refused and why. The user sees both
/// before anything is stored, because an importer that reports "412 imported"
/// and nothing else is an importer whose mistakes are invisible.
///
/// **The file is plaintext.** It has to be — that is what an export from
/// another manager is. It reaches this process as bytes and is never written
/// anywhere by us; the caller is responsible for the copy the file picker may
/// have made. Dart strings are immutable and garbage-collected, so the parsed
/// contents cannot be wiped on demand, and [VaultImportPreview] is built to be
/// short-lived rather than pretending otherwise.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:csv/csv.dart';

import '../../features/vault/vault_store.dart';

/// The store refuses anything longer, so refusing here gives the user a row
/// number instead of a failure part-way through a write.
const int _maxName = 255;
const int _maxUsername = 255;
const int _maxUri = 1024;
const int _maxSecret = 4096;

/// Above this a file is not an export, and parsing it would spend the phone's
/// memory finding that out.
const int maxImportRows = 4096;

class VaultImportException implements Exception {
  const VaultImportException(this.message);
  final String message;

  @override
  String toString() => message;
}

/// One row that will not be imported, and why.
///
/// The row number is one-based and counts the header, so it matches what a
/// spreadsheet shows the user.
class VaultImportRejection {
  const VaultImportRejection({
    required this.row,
    required this.reason,
    this.name = '',
  });

  final int row;
  final String reason;

  /// The item's name when there was one. Never its secret — this list is
  /// rendered on screen and may be screenshotted or read aloud.
  final String name;
}

class VaultImportPreview {
  const VaultImportPreview({required this.items, required this.rejections});

  final List<VaultItemInput> items;
  final List<VaultImportRejection> rejections;

  bool get isEmpty => items.isEmpty;
}

/// Picks the parser from the bytes rather than from the file name.
///
/// An extension is a hint the user's file manager wrote down, and a `.csv`
/// holding JSON should import rather than fail on a technicality.
Future<VaultImportPreview> parseVaultImport(Uint8List bytes) async {
  final String text;
  try {
    text = utf8.decode(bytes, allowMalformed: false);
  } on FormatException {
    throw const VaultImportException(
      'O arquivo não é texto UTF-8. Exporte de novo em UTF-8.',
    );
  }

  final trimmed = text.trimLeft();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    return _parseBitwardenJson(trimmed);
  }
  return _parseCsv(text);
}

// --- Bitwarden JSON ---------------------------------------------------------

VaultImportPreview _parseBitwardenJson(String text) {
  final Object? decoded;
  try {
    decoded = jsonDecode(text);
  } on FormatException {
    throw const VaultImportException('O JSON deste arquivo está malformado.');
  }
  if (decoded is! Map<String, Object?>) {
    throw const VaultImportException(
      'Este JSON não parece uma exportação do Bitwarden.',
    );
  }

  // An encrypted export is not something to fail on obscurely: the user has to
  // be told to export again unencrypted, because there is nothing here that
  // could ask them for the Bitwarden password.
  if (decoded['encrypted'] == true) {
    throw const VaultImportException(
      'Esta exportação do Bitwarden está criptografada. Exporte de novo sem '
      'criptografia — este aplicativo não tem como pedir a senha do Bitwarden.',
    );
  }

  final rawItems = decoded['items'];
  if (rawItems is! List) {
    throw const VaultImportException('Este JSON não tem uma lista `items`.');
  }
  if (rawItems.length > maxImportRows) {
    throw const VaultImportException(
      'O arquivo tem mais de $maxImportRows itens.',
    );
  }

  final items = <VaultItemInput>[];
  final rejections = <VaultImportRejection>[];

  for (var index = 0; index < rawItems.length; index++) {
    final row = index + 1;
    final raw = rawItems[index];
    if (raw is! Map<String, Object?>) {
      rejections.add(VaultImportRejection(row: row, reason: 'não é um item'));
      continue;
    }

    // Trimmed here for the same reason the CSV path trims: a stray space
    // around a name is an artefact of whatever produced the file, and the name
    // is what a restore compares to decide whether two rows are one account.
    // The two importers used to disagree about that, so the same login brought
    // in from a JSON export and from a CSV export was two entries.
    final name = _string(raw['name']).trim();
    // Bitwarden's type 1 is a login and 2 a secure note. Cards, identities and
    // SSH keys have no home in this schema (VLT-15), so they are reported
    // rather than flattened into notes that lose their structure.
    final type = raw['type'];
    final login = raw['login'];
    final (kind, username, uri, secret) = switch (type) {
      1 when login is Map<String, Object?> => (
        VaultItemKind.login,
        _string(login['username']).trim(),
        _firstUri(login['uris']).trim(),
        // Not the password. That one is stored exactly as it was exported,
        // on both paths, because a space at either end of it is part of it.
        _string(login['password']),
      ),
      2 => (VaultItemKind.note, '', '', _string(raw['notes'])),
      _ => (VaultItemKind.login, '', '', ''),
    };

    if (type != 1 && type != 2) {
      rejections.add(
        VaultImportRejection(
          row: row,
          name: name,
          reason: 'tipo ${type ?? '?'} não é login nem nota',
        ),
      );
      continue;
    }

    final rejection = _validate(
      row: row,
      name: name,
      username: username,
      uri: uri,
      secret: secret,
    );
    if (rejection != null) {
      rejections.add(rejection);
      continue;
    }
    items.add(
      VaultItemInput(
        kind: kind,
        name: name,
        username: username,
        uri: uri,
        secret: secret,
      ),
    );
  }

  return VaultImportPreview(items: items, rejections: rejections);
}

String _firstUri(Object? uris) {
  if (uris is! List || uris.isEmpty) return '';
  final first = uris.first;
  if (first is Map<String, Object?>) return _string(first['uri']);
  return _string(first);
}

// --- CSV --------------------------------------------------------------------

/// Column names this understands, lowercased. Bitwarden's CSV headers are the
/// `login_*` ones; the bare names cover most other exporters.
const Map<String, String> _columnAliases = {
  'name': 'name',
  'title': 'name',
  'item': 'name',
  'account': 'name',
  'username': 'username',
  'login_username': 'username',
  'user': 'username',
  'email': 'username',
  'password': 'secret',
  'login_password': 'secret',
  'pass': 'secret',
  'url': 'uri',
  'uri': 'uri',
  'login_uri': 'uri',
  'website': 'uri',
  'site': 'uri',
  'notes': 'notes',
  'note': 'notes',
  'type': 'type',
};

/// The delimiter, decided from the header line alone.
///
/// Only the first line, because that is the row whose shape we know: it holds
/// column names, so whichever separator appears most there is the separator.
/// Counting over the whole file would let one password containing semicolons
/// outvote the header.
String _delimiterOf(String text) {
  final header = text.split('\n').first;
  var best = ',';
  var bestCount = 0;
  for (final candidate in [',', ';', '\t']) {
    final count = candidate.allMatches(header).length;
    if (count > bestCount) {
      best = candidate;
      bestCount = count;
    }
  }
  return best;
}

VaultImportPreview _parseCsv(String text) {
  final List<List<dynamic>> rows;
  try {
    rows = CsvDecoder(
      // Auto-detection would let a file whose first line happens to hold more
      // semicolons than commas be read with the wrong delimiter, and the rows
      // that came out would look plausible.
      fieldDelimiter: _delimiterOf(text),
      skipEmptyLines: true,
      // A password of "0123" is a string, not the number 123. Dynamic typing
      // here would silently rewrite secrets.
      dynamicTyping: false,
    ).convert(text.replaceAll('\r\n', '\n'));
  } on Object {
    throw const VaultImportException('Não foi possível ler este CSV.');
  }
  if (rows.isEmpty) {
    throw const VaultImportException('O arquivo está vazio.');
  }
  if (rows.length - 1 > maxImportRows) {
    throw const VaultImportException(
      'O arquivo tem mais de $maxImportRows linhas.',
    );
  }

  final header = <String, int>{};
  for (var column = 0; column < rows.first.length; column++) {
    final label = rows.first[column].toString().trim().toLowerCase();
    final field = _columnAliases[label];
    // First column wins. A file with two `password` columns is ambiguous, and
    // guessing which one is the real password is not a guess worth making.
    if (field != null) header.putIfAbsent(field, () => column);
  }
  if (!header.containsKey('name')) {
    throw const VaultImportException(
      'O CSV precisa de uma coluna de nome (name, title ou account).',
    );
  }
  if (!header.containsKey('secret') && !header.containsKey('notes')) {
    throw const VaultImportException(
      'O CSV precisa de uma coluna de senha ou de nota.',
    );
  }

  final items = <VaultItemInput>[];
  final rejections = <VaultImportRejection>[];

  for (var index = 1; index < rows.length; index++) {
    final row = index + 1;
    final cells = rows[index];
    // Trimmed, for matching a name and for deciding whether a cell holds
    // anything at all.
    String at(String field) {
      final column = header[field];
      if (column == null || column >= cells.length) return '';
      return cells[column].toString().trim();
    }

    // Untrimmed, for the one value that is not ours to tidy. A password may
    // legitimately begin or end with a space, and a manager that exports one
    // is not making a mistake. Trimming it here returned a password that no
    // longer works -- silently, and at the exact moment the user has just
    // migrated away from the product that still held the original. The same
    // care is already taken one function up, where `dynamicTyping` is off so
    // that "0123" does not become the number 123; this is the other half of
    // it. Bitwarden's JSON path never trimmed the secret, so this is also the
    // two importers finally agreeing about the same password.
    String verbatim(String field) {
      final column = header[field];
      if (column == null || column >= cells.length) return '';
      return cells[column].toString();
    }

    final name = at('name');
    // A row with only a name and a note is a note; anything with a password is
    // a login. Trusting a `type` column would mean trusting another product's
    // vocabulary for what these two words mean.
    final password = at('secret');
    final notes = at('notes');
    final isNote = password.isEmpty && notes.isNotEmpty;

    // Wholly blank lines are what a trailing newline produces; reporting them
    // as rejections would bury the real ones.
    if (name.isEmpty && password.isEmpty && notes.isEmpty) continue;

    // Whether there *is* a secret stays a question about the trimmed cell -- a
    // cell holding three spaces is an empty one, and is rejected as such, the
    // same as before. Only once it counts as present is the cell stored as it
    // was written.
    final present = isNote ? notes.isNotEmpty : password.isNotEmpty;
    final secret = !present
        ? ''
        : isNote
        ? verbatim('notes')
        : verbatim('secret');

    final rejection = _validate(
      row: row,
      name: name,
      username: isNote ? '' : at('username'),
      uri: isNote ? '' : at('uri'),
      secret: secret,
    );
    if (rejection != null) {
      rejections.add(rejection);
      continue;
    }

    items.add(
      VaultItemInput(
        kind: isNote ? VaultItemKind.note : VaultItemKind.login,
        name: name,
        username: isNote ? '' : at('username'),
        uri: isNote ? '' : at('uri'),
        secret: secret,
      ),
    );
  }

  return VaultImportPreview(items: items, rejections: rejections);
}

// --- shared -----------------------------------------------------------------

String _string(Object? value) => value is String ? value : '';

/// The store's own bounds, checked here so a bad row is a line number on a
/// preview rather than a failure part-way through writing the vault.
VaultImportRejection? _validate({
  required int row,
  required String name,
  required String username,
  required String uri,
  required String secret,
}) {
  final problem = switch (true) {
    _ when name.isEmpty => 'sem nome',
    // Asked of the trimmed value while the item keeps the untrimmed one.
    // Whitespace is not content: a CSV cell holding three spaces and a JSON
    // string holding three spaces are the same empty item, and only the CSV
    // path used to say so. The other stored it as a password, so the user
    // ended up with a vault entry that reveals nothing and logs in nowhere.
    _ when secret.trim().isEmpty => 'sem senha nem conteúdo',
    _ when name.length > _maxName => 'nome longo demais',
    _ when username.length > _maxUsername => 'usuário longo demais',
    _ when uri.length > _maxUri => 'endereço longo demais',
    _ when secret.length > _maxSecret => 'conteúdo longo demais',
    _ => null,
  };
  return problem == null
      ? null
      : VaultImportRejection(row: row, name: name, reason: problem);
}
