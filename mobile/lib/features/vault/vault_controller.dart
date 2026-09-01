import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '../../core/vault/sensitive_clipboard.dart';
import '../../core/vault/totp.dart';
import '../../core/vault/vault_export.dart';
import 'vault_favourites.dart';
import 'vault_store.dart';
import '../../core/vault/vault_mutations.dart';

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
    VaultMutations? mutations,
  }) : _store = store ?? const NativeVaultStore(),
       _favourites = favourites ?? VaultFavourites(),
       _mutations = mutations ?? VaultMutations.shared,
       _copy = copy ?? copySensitive {
    _mutations.addListener(_storeChanged);
  }

  final VaultStore _store;
  final VaultFavourites _favourites;
  final VaultClipboard _copy;
  final VaultMutations _mutations;
  List<VaultItemSummary> _items = const [];

  /// Every replacement of the list goes through here.
  ///
  /// [stale] means "these items are older than the store", so it has to die
  /// with the items it described. Clearing it at each assignment site instead
  /// was one edit away from a banner that never went away.
  set _list(List<VaultItemSummary> items) {
    _items = items;
    stale = false;
  }

  String _query = '';
  String? _revealedId;
  String? _revealedSecret;
  TotpCode? _revealedCode;
  Timer? _totpTicker;
  TotpSecret? _totpSecret;

  bool locked = true;
  bool busy = false;
  String? error;

  /// What the last action did, when it worked.
  ///
  /// A copy was completely silent. The biometric prompt closes, the list looks
  /// identical, and nothing anywhere says the clipboard changed -- while a
  /// failure has been shown in red all along, so the two outcomes were told
  /// apart by one of them being invisible.
  ///
  /// The platform used to cover this: Android raises a preview of whatever was
  /// copied. `EXTRA_IS_SENSITIVE` is what suppresses that preview, and setting
  /// it is right -- it is also the app removing the only confirmation there was
  /// and putting nothing back. It matters most for a TOTP item, where what
  /// lands on the clipboard is six digits and what is stored is the seed, and
  /// the user has no way to tell which one they are about to paste.
  String? notice;

  /// Whether a write landed in the store after this list was read.
  ///
  /// Only the desktop can do that: the screen's own writes replace [_items] as
  /// they finish. Left unsaid, a password created from the PC simply was not
  /// on the phone, and three separate failures already tell the user to
  /// "atualize o cofre" — an instruction the screen had no way to follow.
  bool stale = false;

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

  /// Bumped every time the vault is locked.
  ///
  /// An operation still waiting on the Keystore when the app leaves the
  /// foreground finishes afterwards and writes its result into a vault that
  /// has just been told to forget everything. [lock] cleared what was held at
  /// the moment it ran, and nothing stopped the work already in flight from
  /// putting it back -- so backgrounding mid-unlock forgot the vault and then
  /// unlocked it again, and backgrounding mid-reveal left the plaintext in
  /// memory behind a screen that said it was locked.
  int _generation = 0;

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

  /// Whether the vault holds nothing, as opposed to the search matching
  /// nothing.
  ///
  /// [items] is filtered, so the screen could not tell those apart and said
  /// the same sentence for both. "No items found", to somebody who has just
  /// unlocked a vault for the first time, reads as a vault that failed to
  /// load rather than as one waiting to be filled.
  bool get isEmpty => _items.isEmpty;

  bool isFavourite(String id) => _favourites.contains(id);

  /// Stars or unstars an item.
  ///
  /// Not routed through [_run]: it touches no key and asks the phone for
  /// nothing, so making it wait behind a busy vault operation would be a
  /// spinner on a star.
  Future<void> toggleFavourite(String id) async {
    await _favourites.toggle(id);
    // The preference write is disk I/O and nothing waits for it: not being
    // routed through [_run] means no busy flag either, so starring an item and
    // leaving the screen is one ordinary gesture. Same rule as
    // [_loadFavourites], which is where it is spelled out.
    if (_disposed) return;
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
    _list = await _store.listAll();
    locked = false;
    // Deliberately not awaited. The vault opens at the vault's speed; if the
    // preference store is slow or absent, the list appears unordered and
    // reorders a moment later, rather than the unlock waiting on a star.
    unawaited(_loadFavourites());
  });

  Future<void> _loadFavourites() async {
    // This one is launched with `unawaited` from inside an action, so the
    // generation check in `_run`'s `finally` does not cover it. It carries its
    // own.
    final generation = _generation;
    await _favourites.load();
    // Stars for items that are gone would otherwise accumulate forever, and
    // the stored list would slowly become a record of everything ever starred.
    if (_disposed) return;
    // Asked before the prune and not only before the notify below, because
    // the prune is the destructive half. A lock empties the list it prunes
    // against, and pruning against an empty list is not a no-op: every id is
    // absent from it, so every star is dropped and the empty set is written to
    // disk. The whole vault's favourites, gone, for leaving the foreground
    // while the preference store was still answering -- which is a platform
    // channel round trip on first use, and the app is one notification away
    // from backgrounding at any moment.
    if (_generation != generation) return;
    await _favourites.prune(_items.map((item) => item.id));
    if (_disposed || locked) return;
    notifyListeners();
  }

  void lock() {
    _generation++;
    locked = true;
    _forget();
    error = null;
    notice = null;
    notifyListeners();
  }

  /// Drops everything the unlocked vault held.
  ///
  /// The search text with it. The field holding that text lives in the
  /// unlocked view and is destroyed along with it, so a query that outlived
  /// the lock came back filtering the list against a box the user could see
  /// was empty -- and one that matched nothing came back as a vault that had
  /// apparently lost every item it had. Locking happens on its own, every time
  /// the app leaves the foreground, so this was not a state anybody had to go
  /// looking for.
  void _forget() {
    _list = const [];
    _query = '';
    _revealedId = null;
    _revealedSecret = null;
    _clearTotp();
  }

  Future<void> reveal(VaultItemSummary item) => _run(() async {
    final fetched = await _store.fetch(item.id);
    if (fetched.revision != item.revision) {
      throw StateError('Item alterado; atualize o cofre');
    }
    // Whatever was open before is closed here, ticker included. There is one
    // revealed code for the whole vault and it is read by whichever item is
    // currently revealed, so a ticker left running from a TOTP item kept
    // writing into the row that had replaced it: revealing a password after
    // an authenticator showed the password's row counting down somebody
    // else's six digits, and the seed went on being derived from until the
    // vault was locked.
    _clearTotp();
    _revealedSecret = null;
    _revealedId = item.id;
    if (item.kind == VaultItemKind.totp) {
      // The seed itself never reaches the screen. What is shown is the code
      // derived from it, and it keeps deriving while the item is open so the
      // digits on screen are the digits the site will accept.
      _totpSecret = readTotpSecret(fetched.secret);
      await _tickTotp();
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
    _mutations.removeListener(_storeChanged);
    _totpTicker?.cancel();
    super.dispose();
  }

  /// A write served to a desktop landed in the store this screen is showing.
  ///
  /// Deliberately does not reload. Listing decrypts the vault and the key is
  /// auth-per-use, so reloading here would raise a fingerprint prompt out of
  /// nowhere. The list says it is behind and [refresh] spends the biometric
  /// when the user asks for it.
  void _storeChanged() {
    if (_disposed || locked || stale) return;
    stale = true;
    notifyListeners();
  }

  /// Reads the vault again, at the cost of one biometric prompt.
  ///
  /// The way out of every "atualize o cofre" the screen can show: a revision
  /// conflict on copy or on reveal, an edit refused because the item moved,
  /// and a list that a desktop wrote behind.
  Future<void> refresh() => _run(() async {
    _list = await _store.listAll();
    // Whatever was on screen was read from the list that just went away.
    _revealedId = null;
    _revealedSecret = null;
    _clearTotp();
  });

  Future<void> copy(VaultItemSummary item) => _run(() async {
    final fetched = await _store.fetch(item.id);
    if (fetched.revision != item.revision) {
      throw StateError('Item alterado; atualize o cofre');
    }
    // A TOTP item copies its six digits, never its seed. Putting the seed on
    // the clipboard would paste something no login field accepts and leave the
    // second factor itself sitting there.
    if (item.kind == VaultItemKind.totp) {
      final code = await generateTotp(readTotpSecret(fetched.secret));
      await _copy(code.digits);
      // Said out loud, because this is the one item whose stored value and
      // copied value are different things.
      notice = 'Código de ${item.name} copiado — não a semente.';
      return;
    }
    await _copy(fetched.secret);
    notice = 'Senha de ${item.name} copiada.';
  });

  Future<void> create(VaultItemInput input) =>
      _mutate(() async => (await _store.create(input)).items);

  Future<void> update(VaultItemSummary item, VaultItemInput input) =>
      _mutate(() async => (await _store.update(item, input)).items);

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
      final restored = await _store.restore([
        for (final item in items) item.toInput(),
      ]);
      outcome = restored;
      _list = restored.items ?? await _store.listAll();
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
    // The same forgetting a lock does, because a discarded vault holds even
    // less than a locked one. It used to do most of it by hand and leave the
    // TOTP ticker running, so a seed went on being derived from after the
    // vault it came out of had been destroyed.
    _forget();
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
      final restored = await _store.restore(items);
      outcome = restored;
      _list = restored.items ?? await _store.listAll();
    });
    return outcome;
  }

  /// Runs a write and shows the vault it left behind.
  ///
  /// The list comes from the write itself when the store can say, because a
  /// write has already decrypted the vault and sealed it again — two
  /// biometric prompts, since the key is auth-per-use — and asking for the
  /// list afterwards made adding one item cost three fingerprints. A store
  /// that cannot say returns null and the vault is read again.
  Future<void> _mutate(Future<List<VaultItemSummary>?> Function() action) =>
      _run(() async {
        _list = await action() ?? await _store.listAll();
        _revealedId = null;
        _revealedSecret = null;
        _clearTotp();
      });

  Future<void> _run(Future<void> Function() action) async {
    if (busy) return;
    final generation = _generation;
    busy = true;
    error = null;
    // The last action's word on itself does not survive the next one starting.
    notice = null;
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
        // The vault needs a Keystore key bound to a strong biometric, which
        // the store refuses to create before Android 11. The plugin's minSdk
        // is 24, so this is a device the app installs on perfectly happily and
        // then cannot open a vault on -- and it is not a failure that a retry
        // reaches. Left out of this set it took the generic message and kept
        // the "Desbloquear" button live, so the answer to tapping it was to
        // tap it again.
        'unsupported_android',
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
        // Not the same as cancelling, and the store already tells them apart:
        // this is the prompt ending on its own -- a lockout after too many
        // attempts, a timeout, a sensor that failed to read. Retrying is the
        // right thing to do and the generic message did not say so.
        'authentication_failed' =>
          'Não foi possível confirmar sua biometria. Tente de novo em '
              'instantes.',
        // `UserNotAuthenticatedException`: the key is auth-per-use and the
        // authentication behind it has expired. Also a retry.
        'authentication_required' =>
          'Confirme sua biometria para abrir o cofre.',
        'biometric_unavailable' =>
          'Cadastre uma biometria forte para usar o cofre.',
        // The prompt could not be raised at all -- the app was on its way out
        // of the foreground when the tap landed. Nothing is wrong with the
        // vault and the next tap works, which the generic message did not say.
        'activity_unavailable' =>
          'O cofre não conseguiu abrir a confirmação. Volte para o aplicativo '
              'e tente de novo.',
        // Permanent on this phone, and not a reason to destroy anything --
        // there is nothing stored yet, because the key was never created.
        'unsupported_android' =>
          'O cofre precisa do Android 11 ou mais novo. Este aparelho não '
              'consegue guardar a chave com a proteção que o cofre exige.',
        'revision_conflict' =>
          'Este item mudou. Atualize o cofre e tente novamente.',
        'operation_in_progress' =>
          'Outra operação do cofre está em andamento. Tente de novo em '
              'instantes.',
        // Every message around this one names the next thing to do, and this
        // one named a state. A vault at its ceiling is the one failure here
        // the user can clear themselves in ten seconds, and "o cofre está
        // cheio" left them looking for a setting that does not exist.
        'vault_full' =>
          'O cofre já guarda o máximo de $maxVaultItems itens. Apague algum '
              'antes de guardar outro.',
        // The vault operation worked. The item was fetched, the biometric was
        // spent and the plaintext was decrypted -- and then the clipboard
        // refused it. Blaming the vault sends the user to look at the wrong
        // thing, and a retry buys another fingerprint for the same failure.
        'clipboard_unavailable' =>
          'Este aparelho não tem área de transferência, então nada foi '
              'copiado. Use "Revelar" para ler o valor na tela.',
        'clipboard_failed' =>
          'A área de transferência recusou o valor; nada foi copiado.',
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
      // A lock that landed while this was in flight wins, whatever the
      // operation went on to write. Checked here rather than inside each
      // action because it is the same rule for all of them: the vault forgets
      // when the app leaves the foreground, and that has to hold against work
      // that had already started.
      if (_generation != generation) {
        _forget();
        locked = true;
      }
      // Everything above still runs after disposal -- forgetting the plaintext
      // an operation was carrying is exactly what should happen when the
      // screen goes. Only the notify is skipped, and only because it throws:
      // every vault operation waits on a biometric prompt, which is as long as
      // a person takes, and the back gesture that dismisses that prompt is one
      // press away from the one that pops the screen.
      if (!_disposed) notifyListeners();
    }
  }
}
