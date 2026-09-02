import 'package:flutter/services.dart';

const _channel = MethodChannel('bioauth/vault_store');

/// The most items one vault holds.
///
/// Enforced by the native store on a restore, because the vault is one blob
/// decrypted into memory on every operation: a vault that will not fit is not
/// a slow vault, it is a vault that stops opening.
const int maxVaultItems = 4096;

/// How long each field of an item may be, in UTF-16 code units.
///
/// Not local preferences. The native store checks the same four numbers, the
/// protocol crate on the desktop checks them again before it will encode a
/// request, and Dart's `String.length` counts the same units both of those do.
/// They live here because this file is the one the app already treats as the
/// authority on what a vault holds, and because they were written out as bare
/// literals in two Dart files: the import preview exists precisely to turn a
/// row the store would refuse into a line number, and it can only do that
/// while its idea of "too long" is the store's.
const int maxVaultNameLength = 255;
const int maxVaultUsernameLength = 255;
const int maxVaultUriLength = 1024;
const int maxVaultSecretLength = 4096;

enum VaultItemKind {
  login,
  note,

  /// A TOTP seed. The stored secret is the base32 key; the digits are derived
  /// on demand and never stored, because a stored code outlives its window.
  totp,
}

class VaultItemSummary {
  const VaultItemSummary({
    required this.id,
    required this.revision,
    required this.kind,
    required this.name,
    required this.username,
    required this.uri,
    required this.updatedAt,
  });

  final String id;
  final int revision;
  final VaultItemKind kind;
  final String name;
  final String username;
  final String uri;
  final DateTime updatedAt;

  static VaultItemSummary fromMap(Map<Object?, Object?> map) {
    final kind = _integer(map, 'kind');
    if (kind < 0 || kind >= VaultItemKind.values.length) {
      throw const FormatException('invalid vault item kind');
    }
    return VaultItemSummary(
      id: _text(map, 'id'),
      revision: _positive(map, 'revision'),
      kind: VaultItemKind.values[kind],
      name: _text(map, 'name'),
      username: _text(map, 'username'),
      uri: _text(map, 'uri'),
      updatedAt: DateTime.fromMillisecondsSinceEpoch(
        _integer(map, 'updatedAtMs'),
        isUtc: true,
      ),
    );
  }
}

class VaultItemInput {
  const VaultItemInput({
    required this.kind,
    required this.name,
    required this.secret,
    this.username = '',
    this.uri = '',
  });

  final VaultItemKind kind;
  final String name;
  final String username;
  final String uri;
  final String secret;

  Map<String, Object?> toMap([String? id]) => {
    'id': ?id,
    'kind': kind.index,
    'name': name,
    'username': username,
    'uri': uri,
    'secret': secret,
  };
}

class VaultSecret {
  const VaultSecret({
    required this.id,
    required this.revision,
    required this.secret,
  });

  final String id;
  final int revision;
  final String secret;
}

class VaultWrite {
  const VaultWrite({required this.id, required this.revision, this.items});

  final String id;
  final int revision;

  /// The whole vault as the write left it, when the store had it for free.
  ///
  /// A write already decrypts the vault and seals it again, and on a phone
  /// each of those is its own biometric prompt because the key is
  /// auth-per-use. Reading the list back afterwards is a third prompt for a
  /// list the write had computed, so the store that did the writing says.
  /// Null means it could not, and the caller reads the vault again.
  final List<VaultItemSummary>? items;
}

class VaultPage {
  const VaultPage({required this.items, this.nextCursor});

  final List<VaultItemSummary> items;
  final String? nextCursor;
}

abstract class VaultStore {
  const VaultStore();

  Future<VaultPage> listPage([String? cursor]);

  /// Reads every page, refusing a store that will not finish handing them out.
  ///
  /// The bound is on items, because the number of items is what the vault has
  /// a limit on. It used to be `seen.length > 32` — thirty-two *cursors*,
  /// which is the page size wearing a page count's clothes. A page holds
  /// thirty-two items, so a vault past about a thousand of them threw here on
  /// every unlock, and the screen reported the generic failure: a vault
  /// restored from a large export was a vault that had stopped opening. The
  /// limit that matters is [maxVaultItems], the same ceiling the native
  /// store enforces on a restore.
  Future<List<VaultItemSummary>> listAll() async {
    final result = <VaultItemSummary>[];
    String? cursor;
    final seen = <String>{};
    do {
      final page = await listPage(cursor);
      result.addAll(page.items);
      cursor = page.nextCursor;
      // A repeated cursor is a cycle, and an empty page that still asks to be
      // followed is a store making no progress — either one loops forever.
      if (cursor != null &&
          (!seen.add(cursor) ||
              page.items.isEmpty ||
              result.length > maxVaultItems)) {
        throw const FormatException('invalid vault pagination');
      }
    } while (cursor != null);
    return result;
  }

  Future<VaultSecret> fetch(String id);
  Future<VaultWrite> create(VaultItemInput item);
  Future<VaultWrite> update(VaultItemSummary current, VaultItemInput item);

  /// Removes an item, answering with the vault it left behind when it can.
  ///
  /// See [VaultWrite.items]: null means the caller has to read the list back,
  /// which costs an unlock.
  Future<List<VaultItemSummary>?> delete(VaultItemSummary item);

  /// Every item, secrets included, for one encrypted backup.
  ///
  /// The only call in the app that yields more than one secret at a time. The
  /// caller must seal what comes back before doing anything else with it.
  ///
  /// The fallback below is correct but costs one unlock per item, because it
  /// goes through [fetch]. [NativeVaultStore] overrides it: the whole vault is
  /// a single blob there, so one decryption yields everything, and a backup
  /// that asked for a fingerprint fifty times is a backup nobody finishes.
  Future<List<VaultItemInput>> exportAll() async {
    final items = <VaultItemInput>[];
    for (final summary in await listAll()) {
      final secret = await fetch(summary.id);
      items.add(
        VaultItemInput(
          kind: summary.kind,
          name: summary.name,
          username: summary.username,
          uri: summary.uri,
          secret: secret.secret,
        ),
      );
    }
    return items;
  }

  /// Throws the vault away: the stored items and the key that protects them.
  ///
  /// The way out of a vault nothing can open — a key a new biometric
  /// enrolment invalidated, a file that fails its authentication tag. Both are
  /// permanent, so without this the app has a tab that only ever shows an
  /// error.
  ///
  /// Destroys data, and needs no unlock, because an unlock is exactly what is
  /// unavailable. The confirmation belongs to the caller.
  ///
  /// Refuses by default rather than doing nothing. A store that cannot discard
  /// must say so: a no-op would report success and leave the user believing
  /// they had started over on a vault that is still there.
  Future<void> discard() async {
    throw UnsupportedError('this vault cannot be discarded');
  }

  /// Adds items from a backup to whatever this vault already holds.
  ///
  /// Never replaces. A restore that emptied the vault first would turn one
  /// wrong file — the wrong backup, the right backup from a year ago — into
  /// losing everything stored since it was made. An item the vault already
  /// holds is counted rather than duplicated, so restoring the same file twice
  /// is harmless.
  Future<VaultRestoreOutcome> restore(List<VaultItemInput> items) async {
    final existing = {
      for (final item in await listAll())
        _identity(item.kind, item.name, item.username, item.uri),
    };
    var added = 0;
    var skipped = 0;
    for (final item in items) {
      if (!existing.add(
        _identity(item.kind, item.name, item.username, item.uri),
      )) {
        skipped++;
        continue;
      }
      await create(item);
      added++;
    }
    return VaultRestoreOutcome(added: added, skipped: skipped);
  }

  /// What makes two entries the same entry, for a restore.
  ///
  /// The secret is not part of it: two rows for the same login on the same
  /// site with different passwords are one account whose password changed, and
  /// keeping both leaves the user guessing which one is current.
  ///
  /// Joined on NUL rather than a space, because a space appears inside names.
  /// `("a b", "c")` and `("a", "b c")` are different entries and would share a
  /// space-joined key, so a restore would drop one of them as a duplicate.
  static String _identity(
    VaultItemKind kind,
    String name,
    String username,
    String uri,
  ) => '${kind.index}\u0000$name\u0000$username\u0000$uri';
}

/// What a restore did, for the screen that reports it.
class VaultRestoreOutcome {
  const VaultRestoreOutcome({
    required this.added,
    required this.skipped,
    this.items,
  });

  final int added;

  /// The vault after the restore, when the store had it for free. See
  /// [VaultWrite.items].
  final List<VaultItemSummary>? items;

  /// Items the vault already held. Counted rather than duplicated, so
  /// restoring the same file twice is harmless.
  final int skipped;
}

class NativeVaultStore extends VaultStore {
  const NativeVaultStore();

  @override
  Future<VaultPage> listPage([String? cursor]) async {
    final raw = await _channel.invokeMapMethod<Object?, Object?>('list', {
      'cursor': ?cursor,
    });
    if (raw == null || raw['items'] is! List) {
      throw const FormatException('invalid vault response');
    }
    final items = <VaultItemSummary>[];
    for (final value in raw['items']! as List) {
      if (value is! Map) {
        throw const FormatException('invalid vault item');
      }
      items.add(VaultItemSummary.fromMap(value.cast<Object?, Object?>()));
    }
    final next = raw['nextCursor'];
    if (next != null && (next is! String || next.isEmpty)) {
      throw const FormatException('invalid vault cursor');
    }
    return VaultPage(items: items, nextCursor: next as String?);
  }

  /// Every item in one unlock, rather than one unlock per page.
  ///
  /// The inherited walk is correct and costs a biometric prompt per page,
  /// because the Keystore key is auth-per-use and every trip through the
  /// channel decrypts the blob again. Opening a vault of a hundred items asked
  /// for four fingerprints in a row, and cancelling any of them left the vault
  /// shut saying the authentication was cancelled -- which is a vault that,
  /// from the outside, does not open. [exportAll] is overridden for the same
  /// reason and this one runs on every unlock.
  @override
  Future<List<VaultItemSummary>> listAll() async {
    final raw = await _channel.invokeMapMethod<Object?, Object?>(
      'listAll',
      <String, Object?>{},
    );
    final items = _summaries(raw);
    if (items == null) {
      throw const FormatException('invalid vault response');
    }
    return items;
  }

  @override
  Future<VaultSecret> fetch(String id) async {
    final raw = await _channel.invokeMapMethod<Object?, Object?>('fetch', {
      'id': id,
    });
    if (raw == null) throw const FormatException('invalid vault response');
    return VaultSecret(
      id: _text(raw, 'id'),
      revision: _positive(raw, 'revision'),
      secret: _text(raw, 'secret'),
    );
  }

  @override
  Future<VaultWrite> create(VaultItemInput item) async {
    _validate(item);
    return _write(
      await _channel.invokeMapMethod<Object?, Object?>('create', {
        'item': item.toMap(),
      }),
    );
  }

  @override
  Future<VaultWrite> update(
    VaultItemSummary current,
    VaultItemInput item,
  ) async {
    _validate(item);
    return _write(
      await _channel.invokeMapMethod<Object?, Object?>('update', {
        'item': item.toMap(current.id),
        'expectedRevision': current.revision,
      }),
    );
  }

  @override
  Future<List<VaultItemSummary>?> delete(VaultItemSummary item) async =>
      _summaries(
        await _channel.invokeMapMethod<Object?, Object?>('delete', {
          'id': item.id,
          'expectedRevision': item.revision,
        }),
      );

  @override
  Future<void> discard() =>
      _channel.invokeMethod<Object?>('discard', <String, Object?>{});

  @override
  Future<List<VaultItemInput>> exportAll() async {
    final raw = await _channel.invokeMapMethod<Object?, Object?>('export', {});
    if (raw == null || raw['items'] is! List) {
      throw const FormatException('invalid vault response');
    }
    return [
      for (final value in raw['items']! as List)
        if (value is Map)
          VaultItemInput(
            kind: VaultItemKind.values[_kind(value)],
            name: _text(value, 'name'),
            username: _optionalText(value, 'username'),
            uri: _optionalText(value, 'uri'),
            secret: _text(value, 'secret'),
          )
        else
          throw const FormatException('invalid vault item'),
    ];
  }

  @override
  Future<VaultRestoreOutcome> restore(List<VaultItemInput> items) async {
    for (final item in items) {
      _validate(item);
    }
    final raw = await _channel.invokeMapMethod<Object?, Object?>('restore', {
      'items': [for (final item in items) item.toMap()],
    });
    if (raw == null) throw const FormatException('invalid vault response');
    return VaultRestoreOutcome(
      added: _count(raw, 'added'),
      skipped: _count(raw, 'skipped'),
      items: _summaries(raw),
    );
  }

  static void _validate(VaultItemInput item) {
    if (item.name.isEmpty || item.name.length > maxVaultNameLength) {
      throw ArgumentError.value(
        item.name,
        'name',
        'use de 1 a $maxVaultNameLength caracteres',
      );
    }
    if (item.username.length > maxVaultUsernameLength ||
        item.uri.length > maxVaultUriLength) {
      throw ArgumentError('username or address too large');
    }
    if (item.secret.isEmpty || item.secret.length > maxVaultSecretLength) {
      throw ArgumentError.value(
        item.secret.length,
        'secret.length',
        'use de 1 a $maxVaultSecretLength caracteres',
      );
    }
  }

  static VaultWrite _write(Map<Object?, Object?>? raw) {
    if (raw == null) throw const FormatException('invalid vault response');
    return VaultWrite(
      id: _text(raw, 'id'),
      revision: _positive(raw, 'revision'),
      items: _summaries(raw),
    );
  }

  /// The listing an answer carries, or null when it carries none.
  ///
  /// Every write answers with one, so the caller never has to unlock the vault
  /// again just to see what it now holds. Absent is not an error here -- only
  /// [listAll], where the listing is the whole answer, insists on it.
  static List<VaultItemSummary>? _summaries(Map<Object?, Object?>? raw) {
    final items = raw?['items'];
    if (items is! List) return null;
    // The same ceiling the native store enforces on a restore. A store that
    // hands back more than a vault can hold is not a vault this build wrote.
    if (items.length > maxVaultItems) {
      throw const FormatException('Cofre maior do que o formato permite');
    }
    return [
      for (final value in items)
        if (value is Map)
          VaultItemSummary.fromMap(value.cast<Object?, Object?>())
        else
          throw const FormatException('invalid vault item'),
    ];
  }
}

String _text(Map<Object?, Object?> map, String key) {
  final value = map[key];
  if (value is! String) throw FormatException('invalid field: $key');
  return value;
}

int _integer(Map<Object?, Object?> map, String key) {
  final value = map[key];
  if (value is! int) throw FormatException('invalid field: $key');
  return value;
}

int _positive(Map<Object?, Object?> map, String key) {
  final value = _integer(map, key);
  if (value < 1) throw FormatException('invalid field: $key');
  return value;
}

/// A tally, which unlike a revision is allowed to be zero.
int _count(Map<Object?, Object?> map, String key) {
  final value = _integer(map, key);
  if (value < 0) throw FormatException('invalid field: $key');
  return value;
}

int _kind(Map<Object?, Object?> map) {
  final value = _integer(map, 'kind');
  if (value < 0 || value >= VaultItemKind.values.length) {
    throw const FormatException('invalid vault item kind');
  }
  return value;
}

/// An empty username or URI arrives as an absent key rather than as `''`.
String _optionalText(Map<Object?, Object?> map, String key) {
  final value = map[key];
  if (value == null) return '';
  if (value is! String) throw FormatException('invalid field: $key');
  return value;
}
