import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '../../core/vault/vault_export.dart';
import 'vault_store.dart';

typedef VaultClipboard = Future<void> Function(String value);

/// A sealed backup, together with the one string that opens it.
///
/// The two travel together exactly once, from the controller to the screen
/// that shows the code. Anything that persisted this pair would be storing the
/// vault in the clear with extra steps.
class VaultBackup {
  const VaultBackup({
    required this.bytes,
    required this.code,
    required this.itemCount,
  });

  final Uint8List bytes;
  final String code;
  final int itemCount;
}

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

  /// Seals the whole vault into one file and returns it with its code.
  ///
  /// The code is generated here and handed straight back to the screen that
  /// has to show it once. Nothing stores it: a backup code kept next to the
  /// backup protects nothing, which is the same reason the locker's recovery
  /// code is written to a file the user is told to move.
  Future<VaultBackup?> exportBackup() async {
    VaultBackup? backup;
    await _run(() async {
      final items = await _store.exportAll();
      final key = VaultExportKey.random();
      backup = VaultBackup(
        bytes: await sealVaultExport(
          items: [
            for (final item in items)
              VaultExportItem(
                kind: item.kind,
                name: item.name,
                username: item.username,
                uri: item.uri,
                secret: item.secret,
              ),
          ],
          key: key,
          createdAt: DateTime.now().toUtc(),
        ),
        code: key.format(),
        itemCount: items.length,
      );
    });
    return backup;
  }

  /// Reads a backup with the code the user typed and adds what it holds.
  ///
  /// Additive, never replacing: see [VaultStore.restore]. Returns null when
  /// the file or the code was refused, with [error] describing which.
  Future<VaultRestoreOutcome?> restoreBackup(
    Uint8List file,
    String code,
  ) async {
    VaultRestoreOutcome? outcome;
    await _run(() async {
      final items = await openVaultExport(file, VaultExportKey.parse(code));
      outcome = await _store.restore([
        for (final item in items) item.toInput(),
      ]);
      _items = await _store.listAll();
    });
    return outcome;
  }

  /// Writes an already-previewed import into the vault.
  ///
  /// Takes the items rather than the file: parsing and reporting happen on the
  /// screen, and the user has seen what would be added and what was refused
  /// before this is called. Goes through the same additive [VaultStore.restore]
  /// a backup does, so an import cannot delete anything either.
  Future<VaultRestoreOutcome?> importItems(List<VaultItemInput> items) async {
    VaultRestoreOutcome? outcome;
    await _run(() async {
      outcome = await _store.restore(items);
      _items = await _store.listAll();
    });
    return outcome;
  }

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
    } on VaultExportException catch (failure) {
      // A backup already says exactly what is wrong with it — bad code, wrong
      // file, edited file — and flattening those into the generic message
      // would leave the user retyping a code that was never the problem.
      error = failure.message;
    } on Object {
      error = 'Não foi possível concluir a operação do cofre.';
    } finally {
      busy = false;
      notifyListeners();
    }
  }
}
