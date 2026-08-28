import 'package:flutter/services.dart';

const _channel = MethodChannel('bioauth/vault_store');

enum VaultItemKind { login, note }

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

abstract interface class VaultStore {
  Future<List<VaultItemSummary>> listAll();
  Future<VaultSecret> fetch(String id);
  Future<void> create(VaultItemInput item);
  Future<void> update(VaultItemSummary current, VaultItemInput item);
  Future<void> delete(VaultItemSummary item);
}

class NativeVaultStore implements VaultStore {
  const NativeVaultStore();

  @override
  Future<List<VaultItemSummary>> listAll() async {
    final result = <VaultItemSummary>[];
    String? cursor;
    final seen = <String>{};
    do {
      final raw = await _channel.invokeMapMethod<Object?, Object?>('list', {
        'cursor': ?cursor,
      });
      if (raw == null || raw['items'] is! List) {
        throw const FormatException('Resposta inválida do cofre');
      }
      for (final value in raw['items']! as List) {
        if (value is! Map) {
          throw const FormatException('Item inválido no cofre');
        }
        result.add(VaultItemSummary.fromMap(value.cast<Object?, Object?>()));
      }
      final next = raw['nextCursor'];
      if (next != null && next is! String) {
        throw const FormatException('Cursor inválido do cofre');
      }
      cursor = next as String?;
      if (cursor != null && (!seen.add(cursor) || seen.length > 32)) {
        throw const FormatException('Paginação inválida do cofre');
      }
    } while (cursor != null);
    return result;
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
  Future<void> create(VaultItemInput item) async {
    _validate(item);
    await _channel.invokeMethod<Object?>('create', {'item': item.toMap()});
  }

  @override
  Future<void> update(VaultItemSummary current, VaultItemInput item) async {
    _validate(item);
    await _channel.invokeMethod<Object?>('update', {
      'item': item.toMap(current.id),
      'expectedRevision': current.revision,
    });
  }

  @override
  Future<void> delete(VaultItemSummary item) => _channel.invokeMethod<Object?>(
    'delete',
    {'id': item.id, 'expectedRevision': item.revision},
  );

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
