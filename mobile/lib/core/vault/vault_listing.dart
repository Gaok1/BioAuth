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
/// Metadata only, and never for longer than [vaultListingTtl] past the last
/// page anyone asked for — the length of a walk, not the length of a session.
/// Nothing here holds a secret: those stay behind `fetch`, one at a time, in
/// front of a user who was told which one.
library;

import 'dart:async';

import '../../features/vault/vault_store.dart';

/// How long a snapshot may sit unused before the next page has to read again.
///
/// Measured from the last page served, not from the start of the walk. A page
/// is a session -- the desktop dials, asks, and the phone closes -- so a full
/// vault of four thousand items is a hundred and twenty-eight dials and a
/// hundred and twenty-eight handshakes. Timed from the start, the walk this
/// exists to make cheap was the one walk guaranteed to outrun it, and outrunning
/// it costs the phone's owner an unexplained fingerprint mid-listing.
///
/// A walk that keeps asking keeps its snapshot; one that stops asking loses it
/// thirty seconds later, which is the liveness this bounds. Metadata only, and
/// still nothing that outlives the walk by more than that.
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
  DateTime? _usedAt;

  /// Enforces the TTL instead of only reporting it.
  ///
  /// The check in [items] is consulted when the next page arrives, which for a
  /// walk that simply stopped is never: the snapshot then sat in memory until
  /// the app left the foreground, whatever this file said about thirty
  /// seconds. It is the vault's metadata -- every item's name, username and
  /// address -- so the bound has to be something that happens rather than
  /// something that is checked.
  Timer? _expiry;

  /// The vault's metadata, reading it again only when the walk demands it.
  ///
  /// [restart] is true for the first page of a walk, which is what an empty
  /// cursor means. A continuation reuses what the walk started from; if that
  /// has gone unasked for longer than the TTL it is read again, which costs an
  /// unlock and may skip or repeat an item — the same as before this existed,
  /// and now the unusual case rather than every case.
  Future<List<VaultItemSummary>> items({required bool restart}) async {
    final used = _usedAt;
    final held = _items;
    if (!restart &&
        held != null &&
        used != null &&
        _clock().difference(used) < _ttl) {
      // A walk that is still walking keeps what it started from. The clock
      // this bounds is the gap between pages, not the length of the listing.
      _touch();
      return held;
    }
    final fresh = await _store.listAll();
    _items = fresh;
    _touch();
    return fresh;
  }

  /// Drops what is held. Called when the sessions that page through it end.
  void forget() {
    _expiry?.cancel();
    _expiry = null;
    _items = null;
    _usedAt = null;
  }

  /// Marks a page served and restarts the countdown to forgetting.
  void _touch() {
    _usedAt = _clock();
    _expiry?.cancel();
    _expiry = Timer(_ttl, forget);
  }
}
