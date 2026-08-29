import 'package:flutter/services.dart';

const _channel = MethodChannel('bioauth/vault_store');

/// The most items one vault holds.
///
/// Enforced by the native store on a restore, because the vault is one blob
/// decrypted into memory on every operation: a vault that will not fit is not
/// a slow vault, it is a vault that stops opening.
const int maxVaultItems = 4096;

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
      throw const FormatException('Tipo de item do cofre inválido');
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
  const VaultWrite({required this.id, required this.revision});

  final String id;
  final int revision;
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
        throw const FormatException('Paginação inválida do cofre');
      }
    } while (cursor != null);
    return result;
  }

  /// One item's metadata, or null when nothing carries that id.
  ///
  /// Costs one unlock and releases no secret, which is the point: the approval
  /// sheet has to name the item *before* the user is asked to release it, and
  /// going through [fetch] to learn the name would hand over the secret in
  /// order to draw the screen that asks whether to hand over the secret.
  ///
  /// One unlock, not none. The metadata lives inside the encrypted blob, so
  /// reading a name needs the key, and the key is auth-per-use -- which means
  /// a request from a desktop raises a prompt before the sheet that explains
  /// it. That is the cost of keeping metadata sealed; what it must not also be
  /// is a prompt *per page*, which is why [listAll] is one call.
  Future<VaultItemSummary?> summary(String id) async {
    for (final item in await listAll()) {
      if (item.id == id) return item;
    }
    return null;
  }

  Future<VaultSecret> fetch(String id);
  Future<VaultWrite> create(VaultItemInput item);
  Future<VaultWrite> update(VaultItemSummary current, VaultItemInput item);
  Future<void> delete(VaultItemSummary item);

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
    throw UnsupportedError('Este cofre não pode ser descartado');
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
  const VaultRestoreOutcome({required this.added, required this.skipped});

  final int added;

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
      throw const FormatException('Resposta inválida do cofre');
    }
    final items = <VaultItemSummary>[];
    for (final value in raw['items']! as List) {
      if (value is! Map) {
        throw const FormatException('Item inválido no cofre');
      }
      items.add(VaultItemSummary.fromMap(value.cast<Object?, Object?>()));
    }
    final next = raw['nextCursor'];
    if (next != null && (next is! String || next.isEmpty)) {
      throw const FormatException('Cursor inválido do cofre');
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
    if (raw == null || raw['items'] is! List) {
      throw const FormatException('Resposta inválida do cofre');
    }
    final items = raw['items']! as List;
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
          throw const FormatException('Item inválido no cofre'),
    ];
  }

  @override
  Future<VaultSecret> fetch(String id) async {
    final raw = await _channel.invokeMapMethod<Object?, Object?>('fetch', {
      'id': id,
    });
    if (raw == null) throw const FormatException('Resposta inválida do cofre');
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
  Future<void> delete(VaultItemSummary item) => _channel.invokeMethod<Object?>(
    'delete',
    {'id': item.id, 'expectedRevision': item.revision},
  );

  @override
  Future<void> discard() =>
      _channel.invokeMethod<Object?>('discard', <String, Object?>{});

  @override
  Future<List<VaultItemInput>> exportAll() async {
    final raw = await _channel.invokeMapMethod<Object?, Object?>('export', {});
    if (raw == null || raw['items'] is! List) {
      throw const FormatException('Resposta inválida do cofre');
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
          throw const FormatException('Item inválido no cofre'),
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
    if (raw == null) throw const FormatException('Resposta inválida do cofre');
    return VaultRestoreOutcome(
      added: _count(raw, 'added'),
      skipped: _count(raw, 'skipped'),
    );
  }

  static void _validate(VaultItemInput item) {
    if (item.name.isEmpty || item.name.length > 255) {
      throw ArgumentError.value(item.name, 'name', 'use de 1 a 255 caracteres');
    }
    if (item.username.length > 255 || item.uri.length > 1024) {
      throw ArgumentError('Usuário ou endereço grande demais');
    }
    if (item.secret.isEmpty || item.secret.length > 4096) {
      throw ArgumentError.value(
        item.secret.length,
        'secret.length',
        'use de 1 a 4096 caracteres',
      );
    }
  }

  static VaultWrite _write(Map<Object?, Object?>? raw) {
    if (raw == null) throw const FormatException('Resposta inválida do cofre');
    return VaultWrite(
      id: _text(raw, 'id'),
      revision: _positive(raw, 'revision'),
    );
  }
}

String _text(Map<Object?, Object?> map, String key) {
  final value = map[key];
  if (value is! String) throw FormatException('Campo inválido: $key');
  return value;
}

int _integer(Map<Object?, Object?> map, String key) {
  final value = map[key];
  if (value is! int) throw FormatException('Campo inválido: $key');
  return value;
}

int _positive(Map<Object?, Object?> map, String key) {
  final value = _integer(map, key);
  if (value < 1) throw FormatException('Campo inválido: $key');
  return value;
}

/// A tally, which unlike a revision is allowed to be zero.
int _count(Map<Object?, Object?> map, String key) {
  final value = _integer(map, key);
  if (value < 0) throw FormatException('Campo inválido: $key');
  return value;
}

int _kind(Map<Object?, Object?> map) {
  final value = _integer(map, 'kind');
  if (value < 0 || value >= VaultItemKind.values.length) {
    throw const FormatException('Tipo de item do cofre inválido');
  }
  return value;
}

/// An empty username or URI arrives as an absent key rather than as `''`.
String _optionalText(Map<Object?, Object?> map, String key) {
  final value = map[key];
  if (value == null) return '';
  if (value is! String) throw FormatException('Campo inválido: $key');
  return value;
}
