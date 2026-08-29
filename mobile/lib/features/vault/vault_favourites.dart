/// Which vault items float to the top of the list.
///
/// Kept out of the vault itself, and that is a decision rather than a
/// shortcut. A favourite is display ordering: it says which items *this*
/// person reaches for on *this* phone, and the same vault opened from a work
/// laptop has a different answer. Putting it in the item would sync one
/// person's habit onto every device that reads the vault, and would cost a
/// schema version to carry a preference.
///
/// It also keeps a bare list of ids out of the encrypted blob's change
/// history: marking a favourite would otherwise rewrite and re-seal the whole
/// vault, which is a biometric prompt for a star.
///
/// The ids are opaque (`DEC-06`), so what is stored here says which items
/// exist and nothing about what they are.
library;

import 'package:shared_preferences/shared_preferences.dart';

import 'vault_store.dart';

const String _key = 'vault.favourites.v1';

class VaultFavourites {
  VaultFavourites();

  Set<String> _ids = const {};

  /// Reads what was starred before, so the first list is already ordered.
  ///
  /// A preference store that will not answer means no favourites, never a
  /// vault that will not open. Ordering is a convenience and unlocking is the
  /// feature; letting the first fail the second would be the worst trade in
  /// the app.
  Future<void> load() async {
    try {
      final preferences = await SharedPreferences.getInstance();
      _ids = (preferences.getStringList(_key) ?? const []).toSet();
    } on Object {
      _ids = const {};
    }
  }

  bool contains(String id) => _ids.contains(id);

  bool get isEmpty => _ids.isEmpty;

  Future<void> toggle(String id) async {
    final next = _ids.toSet();
    if (!next.remove(id)) next.add(id);
    _ids = next;
    await _write(next);
  }

  /// Forgets ids the vault no longer holds.
  ///
  /// Without this the list grows every time an item is deleted, and a restore
  /// onto a fresh vault would carry stars for items that are not there —
  /// harmless, but it would make the stored list a slowly growing record of
  /// everything the user ever starred.
  Future<void> prune(Iterable<String> livingIds) async {
    final living = livingIds.toSet();
    final kept = _ids.where(living.contains).toSet();
    if (kept.length == _ids.length) return;
    _ids = kept;
    await _write(kept);
  }

  /// Persists the set, keeping the in-memory copy either way.
  ///
  /// A failed write loses the star at the next launch and nothing else. The
  /// alternative — surfacing it — would put an error banner over a vault
  /// because a star did not save.
  Future<void> _write(Set<String> ids) async {
    try {
      final preferences = await SharedPreferences.getInstance();
      await preferences.setStringList(_key, ids.toList()..sort());
    } on Object {
      // Kept in memory for this session; see above.
    }
  }

  /// Favourites first, then the order the store gave.
  ///
  /// A stable partition rather than a sort: the store already returns items
  /// newest-first, and re-sorting the rest by name would silently discard that.
  List<VaultItemSummary> order(List<VaultItemSummary> items) {
    if (_ids.isEmpty) return items;
    return [
      ...items.where((item) => _ids.contains(item.id)),
      ...items.where((item) => !_ids.contains(item.id)),
    ];
  }
}
