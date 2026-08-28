import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'vault_store.dart';

typedef VaultClipboard = Future<void> Function(String value);

class VaultController extends ChangeNotifier {
  VaultController({VaultStore? store, VaultClipboard? copy})
    : _store = store ?? const NativeVaultStore(),
      _copy =
          copy ?? ((value) => Clipboard.setData(ClipboardData(text: value)));

  final VaultStore _store;
  final VaultClipboard _copy;
  List<VaultItemSummary> _items = const [];
  String _query = '';
  String? _revealedId;
  String? _revealedSecret;

  bool locked = true;
  bool busy = false;
  String? error;

  List<VaultItemSummary> get items {
    final query = _query.trim().toLowerCase();
    if (query.isEmpty) return _items;
    return _items
        .where(
          (item) =>
              item.name.toLowerCase().contains(query) ||
              item.username.toLowerCase().contains(query) ||
              item.uri.toLowerCase().contains(query),
        )
        .toList(growable: false);
  }

  String? secretFor(String id) => id == _revealedId ? _revealedSecret : null;

  void search(String query) {
    _query = query;
    notifyListeners();
  }

  Future<void> unlock() => _run(() async {
    _items = await _store.listAll();
    locked = false;
  });

  void lock() {
    locked = true;
    _items = const [];
    _revealedId = null;
    _revealedSecret = null;
    error = null;
    notifyListeners();
  }

  Future<void> reveal(VaultItemSummary item) => _run(() async {
    final fetched = await _store.fetch(item.id);
    if (fetched.revision != item.revision) {
      throw StateError('Item alterado; atualize o cofre');
    }
    _revealedId = item.id;
    _revealedSecret = fetched.secret;
  });

  void hide() {
    _revealedId = null;
    _revealedSecret = null;
    notifyListeners();
  }

  Future<void> copy(VaultItemSummary item) => _run(() async {
    final fetched = await _store.fetch(item.id);
    if (fetched.revision != item.revision) {
      throw StateError('Item alterado; atualize o cofre');
    }
    await _copy(fetched.secret);
  });

  Future<void> create(VaultItemInput input) =>
      _mutate(() => _store.create(input));

  Future<void> update(VaultItemSummary item, VaultItemInput input) =>
      _mutate(() => _store.update(item, input));

  Future<void> delete(VaultItemSummary item) =>
      _mutate(() => _store.delete(item));

  Future<void> _mutate(Future<Object?> Function() action) => _run(() async {
    await action();
    _items = await _store.listAll();
    _revealedId = null;
    _revealedSecret = null;
  });

  Future<void> _run(Future<void> Function() action) async {
    if (busy) return;
    busy = true;
    error = null;
    notifyListeners();
    try {
      await action();
    } on PlatformException catch (failure) {
      error = switch (failure.code) {
        'authentication_cancelled' => 'Autenticação cancelada.',
        'biometric_unavailable' =>
          'Cadastre uma biometria forte para usar o cofre.',
        'revision_conflict' =>
          'Este item mudou. Atualize o cofre e tente novamente.',
        _ => 'Não foi possível concluir a operação do cofre.',
      };
    } on Object {
      error = 'Não foi possível concluir a operação do cofre.';
    } finally {
      busy = false;
      notifyListeners();
    }
  }
}
