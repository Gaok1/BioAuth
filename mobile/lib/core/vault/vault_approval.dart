/// The approval a desktop needs before the phone acts on its vault.
///
/// The Keystore prompt is a gesture, not an approval: it proves a finger was
/// on the sensor, and says nothing about what that finger agreed to. A person
/// holding an unlocked phone cannot tell a `sudo` prompt from a request for
/// their bank password, because both look like the same system dialog.
///
/// So the release of anything from the vault is two answers, not one: this
/// screen, which names the computer, the operation and the item, and then the
/// biometric the store demands per use. Refusing here means the phone never
/// asks the store, and the desktop is answered with the same generic refusal
/// it gets for a missing item.
library;

import 'dart:async';

enum VaultOperation { read, create, update, delete }

extension VaultOperationLabel on VaultOperation {
  /// What the user is being asked to allow, in the words of the thing itself.
  String get label => switch (this) {
    VaultOperation.read => 'Copiar a senha de',
    VaultOperation.create => 'Guardar um item novo:',
    VaultOperation.update => 'Alterar',
    VaultOperation.delete => 'Apagar',
  };

  /// Whether the operation hands a secret to the computer that asked.
  ///
  /// A write is destructive but reveals nothing; a read is the only one that
  /// puts a password somewhere the phone no longer controls, and the sheet
  /// says so.
  bool get releasesSecret => this == VaultOperation.read;
}

class VaultApprovalRequest {
  const VaultApprovalRequest({
    required this.id,
    required this.verifierName,
    required this.operation,
    required this.itemName,
    this.username = '',
    this.uri = '',
  });

  /// The frame's request id, so a second frame cannot displace a sheet that
  /// is already on screen waiting for an answer.
  final String id;

  /// The name the computer calls itself. Untrusted: it is whatever the paired
  /// desktop put in the frame, so the sheet presents it as a claim rather than
  /// as an identity the phone verified.
  final String verifierName;

  final VaultOperation operation;
  final String itemName;
  final String username;
  final String uri;

  /// The host the item belongs to, for the line the user actually reads.
  ///
  /// Falls back to the raw string when it does not parse: showing something
  /// odd is better than hiding a URI that is odd on purpose.
  String get domain {
    if (uri.isEmpty) return '';
    final parsed = Uri.tryParse(uri);
    final host = parsed?.host ?? '';
    return host.isEmpty ? uri : host;
  }
}

abstract interface class VaultApproval {
  /// Resolves true only if a human said yes to this exact request.
  Future<bool> confirm(VaultApprovalRequest request);
}

/// Approves nothing. The default wherever no screen is attached.
///
/// A vault served by a process with no UI must not release secrets on the
/// strength of a biometric the user was shown without context, so the absence
/// of a screen is a refusal rather than a silent pass.
class DenyVaultApproval implements VaultApproval {
  const DenyVaultApproval();

  @override
  Future<bool> confirm(VaultApprovalRequest request) async => false;
}

/// Bridges an arriving vault request to the sheet the user taps.
///
/// The same shape as `InteractiveAuthorizer`: the service suspends on a
/// completer, the UI completes it. Keeping it here rather than in the service
/// means the service stays free of Flutter, and every structural check has
/// already passed by the time a human sees anything.
class InteractiveVaultApproval implements VaultApproval {
  InteractiveVaultApproval({required this.onRequest});

  /// Called when a validated request needs a decision, to put it on screen.
  final void Function(VaultApprovalRequest request) onRequest;

  final Map<String, ({String shown, Completer<bool> completer})> _pending = {};

  /// Everything the sheet puts in front of the user, as one string.
  ///
  /// An answer covers what was on screen when it was given, and nothing else.
  /// The id alone cannot say that: it is chosen by the computer asking.
  static String _shown(VaultApprovalRequest request) => _fields([
    request.verifierName,
    request.operation.name,
    request.itemName,
    request.username,
    request.uri,
  ]);

  /// Length-prefixed rather than joined on a separator, because every field
  /// here is a string a computer chose and any separator is one it could put
  /// inside a name to make two different sheets read alike.
  static String _fields(List<String> values) =>
      values.map((value) => '${value.length}:$value').join();

  @override
  Future<bool> confirm(VaultApprovalRequest request) {
    // A repeat of a request already on screen waits on the same answer rather
    // than stacking a second sheet: the desktop retrying must not turn one
    // approval into two.
    final existing = _pending[request.id];
    if (existing != null) {
      if (existing.shown == _shown(request)) return existing.completer.future;
      // Same id, different request. The id comes from the computer asking, and
      // sessions run one frame each -- so two of them in flight at once are two
      // desktops, or one desktop on two credentials, and this map is shared by
      // all of them. Handing back the first one's answer would let an approval
      // the user gave for "guardar um item novo" settle a "copiar a senha de"
      // they were never shown. Refused, which the desktop can retry under an
      // id of its own.
      return Future.value(false);
    }

    final completer = Completer<bool>();
    _pending[request.id] = (shown: _shown(request), completer: completer);
    onRequest(request);
    return completer.future;
  }

  /// The UI side: the user tapped.
  void settle(String requestId, {required bool approved}) {
    final pending = _pending.remove(requestId);
    if (pending != null && !pending.completer.isCompleted) {
      pending.completer.complete(approved);
    }
  }

  /// The sheet went away without an answer — dismissed, or the session died.
  void abandon(String requestId) => settle(requestId, approved: false);

  /// This request's answer, from whichever side ends up giving it.
  ///
  /// Handed to the sheet so it can close itself when the answer came from
  /// somewhere else: a session that died, or the app leaving the foreground.
  /// Null once the request is settled, which is also the answer to "is this
  /// still worth showing".
  Future<bool>? answerFor(String requestId) =>
      _pending[requestId]?.completer.future;

  /// Refuses everything outstanding. Called when the app leaves the
  /// foreground: a sheet the user cannot see must not stay answerable.
  void abandonAll() {
    for (final id in _pending.keys.toList()) {
      abandon(id);
    }
  }

  Iterable<String> get pendingRequestIds => _pending.keys;
}
