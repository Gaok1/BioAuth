/// One decrypted look at the vault's metadata, reused across a paged walk.
///
/// A desktop lists by asking for one page at a time, and every page used to be
/// its own trip into the Keystore. The key is auth-per-use and each trip
/// decrypts the whole blob again, so a hundred-item vault cost the phone's
/// owner four biometric prompts for one click on the desktop — and none of
/// them sat behind a sheet, because listing releases no secret and so raises
/// none. Four unexplained fingerprint prompts is not a smaller version of one
/// explained prompt; it is the thing the approval sheet exists to prevent.
///
/// It is also what makes a walk a snapshot. The cursor is an offset into a
/// list sorted by when each item last changed, so an item edited between two
/// pages sorts back to the front and shifts everything behind it by one: the
/// desktop skipped an item and had no way to know. A walk now pages through
/// the list as it was when the walk began.
///
/// Metadata only, and never for longer than [ttl] — the length of a walk, not
/// the length of a session. Nothing here holds a secret: those stay behind
/// `fetch`, one at a time, in front of a user who was told which one.
library;

import '../../features/vault/vault_store.dart';

/// How long a snapshot may serve the pages of the walk that started it.
///
/// Long enough for a desktop to page through a full vault back to back, short
/// enough that it is worthless to anything that comes later. A walk that takes
/// longer than this pays for another unlock, which is the safe direction.
const Duration vaultListingTtl = Duration(seconds: 30);

class VaultListing {
  VaultListing({
    required VaultStore store,
    DateTime Function()? clock,
    Duration ttl = vaultListingTtl,
  }) : _store = store,
       _clock = clock ?? DateTime.now,
       _ttl = ttl;

  final VaultStore _store;
  final DateTime Function() _clock;
  final Duration _ttl;

  List<VaultItemSummary>? _items;
  DateTime? _takenAt;

  /// The vault's metadata, reading it again only when the walk demands it.
  ///
  /// [restart] is true for the first page of a walk, which is what an empty
  /// cursor means. A continuation reuses what the walk started from; if that
  /// has expired it is read again, which costs an unlock and may skip or
  /// repeat an item — the same as before this existed, and now the unusual
  /// case rather than every case.
  Future<List<VaultItemSummary>> items({required bool restart}) async {
    final taken = _takenAt;
    final held = _items;
    if (!restart &&
        held != null &&
        taken != null &&
        _clock().difference(taken) < _ttl) {
      return held;
    }
    final fresh = await _store.listAll();
    _items = fresh;
    _takenAt = _clock();
    return fresh;
  }

  /// Drops what is held. Called when the sessions that page through it end.
  void forget() {
    _items = null;
    _takenAt = null;
  }
}
