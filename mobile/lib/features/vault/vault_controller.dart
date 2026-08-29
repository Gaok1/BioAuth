import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '../../core/vault/sensitive_clipboard.dart';
import '../../core/vault/totp.dart';
import '../../core/vault/vault_export.dart';
import 'vault_favourites.dart';
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
  VaultController({
    VaultStore? store,
    VaultClipboard? copy,
    VaultFavourites? favourites,
  }) : _store = store ?? const NativeVaultStore(),
       _favourites = favourites ?? VaultFavourites(),
       _copy = copy ?? copySensitive;

  final VaultStore _store;
  final VaultFavourites _favourites;
  final VaultClipboard _copy;
  List<VaultItemSummary> _items = const [];
  String _query = '';
  String? _revealedId;
  String? _revealedSecret;
  TotpCode? _revealedCode;
  Timer? _totpTicker;
  TotpSecret? _totpSecret;

  bool locked = true;
  bool busy = false;
  String? error;

  /// Whether the last failure was one no retry can fix.
  ///
  /// An invalidated key, a corrupt file and a store from a newer build are all
  /// permanent from this app's side, and the screen has to offer something
  /// other than the button that just failed.
  bool unrecoverable = false;

  bool _discardable = false;

  /// Set by [dispose]. The favourites load is deliberately not awaited, so it
  /// can outlive the screen that started it, and notifying a disposed
  /// `ChangeNotifier` throws.
  bool _disposed = false;

  /// Whether the vault can be thrown away and started over.
  ///
  /// Narrower than [unrecoverable]: only failures that no future version of
  /// this app could read either. A vault written by a newer build is
  /// unreadable here and fine after an update, so it is never offered.
  ///
  /// Never true after a transient failure. A data-loss button that appears
  /// next to "authentication cancelled" is a data-loss button somebody taps.
  bool get canDiscard => _discardable;

  List<VaultItemSummary> get items {
    final query = _query.trim().toLowerCase();
    final matching = query.isEmpty
        ? _items
        : _items
              .where(
                (item) =>
                    item.name.toLowerCase().contains(query) ||
                    item.username.toLowerCase().contains(query) ||
                    item.uri.toLowerCase().contains(query),
              )
              .toList(growable: false);
    // Ordering happens after filtering, so a search shows its matches with the
    // starred ones first rather than showing every favourite regardless.
    return _favourites.order(matching);
  }

  bool isFavourite(String id) => _favourites.contains(id);

  /// Stars or unstars an item.
  ///
  /// Not routed through [_run]: it touches no key and asks the phone for
  /// nothing, so making it wait behind a busy vault operation would be a
  /// spinner on a star.
  Future<void> toggleFavourite(String id) async {
    await _favourites.toggle(id);
    notifyListeners();
  }

  String? secretFor(String id) => id == _revealedId ? _revealedSecret : null;

  /// The live code for a revealed TOTP item, or null.
  ///
  /// Separate from [secretFor] because they are different things: the stored
  /// secret of a TOTP item is the seed, and showing that where the user
  /// expects six digits would put the seed on screen — the one value that must
  /// never be read aloud or screenshotted.
  TotpCode? totpFor(String id) => id == _revealedId ? _revealedCode : null;

  void search(String query) {
    _query = query;
    notifyListeners();
  }

  Future<void> unlock() => _run(() async {
    _items = await _store.listAll();
    locked = false;
    // Deliberately not awaited. The vault opens at the vault's speed; if the
    // preference store is slow or absent, the list appears unordered and
    // reorders a moment later, rather than the unlock waiting on a star.
    unawaited(_loadFavourites());
  });

  Future<void> _loadFavourites() async {
    await _favourites.load();
    // Stars for items that are gone would otherwise accumulate forever, and
    // the stored list would slowly become a record of everything ever starred.
    if (_disposed) return;
    await _favourites.prune(_items.map((item) => item.id));
    if (_disposed || locked) return;
    notifyListeners();
  }

  void lock() {
    locked = true;
    _items = const [];
    _revealedId = null;
    _revealedSecret = null;
    _clearTotp();
    error = null;
    notifyListeners();
  }

  Future<void> reveal(VaultItemSummary item) => _run(() async {
    final fetched = await _store.fetch(item.id);
    if (fetched.revision != item.revision) {
      throw StateError('Item alterado; atualize o cofre');
    }
    _revealedId = item.id;
    if (item.kind == VaultItemKind.totp) {
      // The seed itself never reaches the screen. What is shown is the code
      // derived from it, and it keeps deriving while the item is open so the
      // digits on screen are the digits the site will accept.
      _totpSecret = TotpSecret.parse(fetched.secret);
      _revealedSecret = null;
      await _tickTotp();
      _totpTicker?.cancel();
      _totpTicker = Timer.periodic(
        const Duration(seconds: 1),
        (_) => _tickTotp(),
      );
    } else {
      _revealedSecret = fetched.secret;
    }
  });

  Future<void> _tickTotp() async {
    final secret = _totpSecret;
    if (secret == null) return;
    final code = await generateTotp(secret);
    // The generate is asynchronous, so the screen can be gone by the time it
    // returns — the ticker fires every second and disposal does not wait.
    if (_disposed || _totpSecret != secret) return;
    _revealedCode = code;
    notifyListeners();
  }

  void hide() {
    _revealedId = null;
    _revealedSecret = null;
    _clearTotp();
    notifyListeners();
  }

  void _clearTotp() {
    _totpTicker?.cancel();
    _totpTicker = null;
    _totpSecret = null;
    _revealedCode = null;
  }

  @override
  void dispose() {
    _disposed = true;
    _totpTicker?.cancel();
    super.dispose();
  }

  Future<void> copy(VaultItemSummary item) => _run(() async {
    final fetched = await _store.fetch(item.id);
    if (fetched.revision != item.revision) {
      throw StateError('Item alterado; atualize o cofre');
    }
    // A TOTP item copies its six digits, never its seed. Putting the seed on
    // the clipboard would paste something no login field accepts and leave the
    // second factor itself sitting there.
    if (item.kind == VaultItemKind.totp) {
      final code = await generateTotp(TotpSecret.parse(fetched.secret));
      await _copy(code.digits);
      return;
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

  /// Throws the vault away — the file and the key — and starts over empty.
  ///
  /// Only reachable when [canDiscard] says the vault is unopenable by anyone,
  /// which is the only situation where destroying it is better than leaving
  /// it. Needs no unlock, because an unlock is exactly what is unavailable.
  ///
  /// The screen is where the confirmation lives, so this is the one operation
  /// whose safety is not enforced here.
  Future<void> discard() => _run(() async {
    await _store.discard();
    _items = const [];
    _revealedId = null;
    _revealedSecret = null;
    locked = true;
  });

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
    _clearTotp();
  });

  Future<void> _run(Future<void> Function() action) async {
    if (busy) return;
    busy = true;
    error = null;
    unrecoverable = false;
    _discardable = false;
    notifyListeners();
    try {
      await action();
    } on PlatformException catch (failure) {
      // Three of these no retry can fix, and saying so is the whole message. A
      // user whose key a new fingerprint invalidated has lost the vault for
      // good; "could not complete the operation" leaves them retrying forever.
      unrecoverable = const {
        'key_invalidated',
        'store_corrupt',
        'store_version_unsupported',
      }.contains(failure.code);

      // A store written by a newer build is unreadable *here* and perfectly
      // readable after an update. It must never be offered for discarding:
      // that button would destroy data a version bump recovers.
      _discardable = const {
        'key_invalidated',
        'store_corrupt',
      }.contains(failure.code);

      error = switch (failure.code) {
        'authentication_cancelled' => 'Autenticação cancelada.',
        'biometric_unavailable' =>
          'Cadastre uma biometria forte para usar o cofre.',
        'revision_conflict' =>
          'Este item mudou. Atualize o cofre e tente novamente.',
        'operation_in_progress' =>
          'Outra operação do cofre está em andamento. Tente de novo em '
              'instantes.',
        'vault_full' => 'O cofre está cheio.',
        'key_invalidated' =>
          'A chave deste cofre foi invalidada por um novo cadastro de '
              'biometria. O conteúdo não pode mais ser aberto — nem por você, '
              'nem por ninguém. Restaure a partir de um backup.',
        'store_corrupt' =>
          'O arquivo do cofre não passou na verificação de integridade. '
              'Ele não pode ser aberto. Restaure a partir de um backup.',
        'store_version_unsupported' =>
          'Este cofre foi gravado por uma versão mais nova do aplicativo. '
              'Atualize antes de abri-lo — não apague nada.',
        _ => 'Não foi possível concluir a operação do cofre.',
      };
    } on TotpException catch (failure) {
      // A seed that will not parse is a stored item that is wrong, and saying
      // so beats the generic message: the user can fix it by editing the item.
      error = failure.message;
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
