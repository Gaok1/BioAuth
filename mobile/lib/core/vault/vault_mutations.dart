import 'package:flutter/foundation.dart';

/// Announces that the stored vault changed without the screen doing it.
///
/// Every write the desktop asks for lands in the same file the vault screen is
/// showing, and the screen reads that file exactly once, when it unlocks. So a
/// password created from the PC — the whole point of `vault.create` — did not
/// appear on the phone until the user locked the vault and unlocked it again,
/// which reads as the write having failed.
///
/// The signal deliberately does **not** carry a reload. Listing the vault
/// decrypts it, and the key is auth-per-use: a refresh this class triggered by
/// itself would raise a fingerprint prompt the user did not ask for, seconds
/// after the one they spent approving the write. The screen is told the list is
/// behind and offers the refresh; the biometric stays a consequence of a tap.
class VaultMutations extends ChangeNotifier {
  /// The instance the served frames and the screen share by default.
  ///
  /// They sit at opposite ends of the app — a session serving a desktop, and a
  /// tab the user is looking at — with no object in common to thread this
  /// through. Both take one in their constructor, so a test gets its own.
  static final VaultMutations shared = VaultMutations();

  /// Called after a write the desktop asked for has been stored.
  void recordWrite() => notifyListeners();
}
