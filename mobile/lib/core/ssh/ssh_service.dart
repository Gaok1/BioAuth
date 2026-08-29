/// Serves `ssh.sign` frames.
///
/// `SYS-02`. The desktop asks this phone to sign bytes the desktop chose. That
/// is the most powerful request in the protocol, and three things bound it —
/// all three enforced here, on this side, because a desktop that has been
/// taken over is exactly the case they exist for.
///
///   1. **The blob is re-parsed here.** The desktop's description is used for
///      nothing. If [accountInRequest] cannot name an account, nothing is
///      signed: there is no approving what cannot be read.
///   2. **The user approves, seeing the account and the destination.** The
///      destination is the computer's claim and is labelled as one — this
///      phone cannot check where a connection is going.
///   3. **A different key from every other purpose.** An SSH signature is one
///      a server accepts for as long as the key is authorized, and sharing a
///      key with `sudo` would make one approval buy the other.
library;

import 'dart:async';

import 'package:flutter/services.dart';

import '../protocol/application_frame.dart';
import '../protocol/ssh_payloads.dart';

/// What the user is asked before an SSH login is signed.
class SshApprovalRequest {
  const SshApprovalRequest({
    required this.id,
    required this.verifierName,
    required this.user,
    required this.destination,
  });

  /// The frame's request id, so a repeat cannot displace a sheet already up.
  final String id;

  /// The computer asking, as it calls itself. A claim, like everywhere else.
  final String verifierName;

  /// The account being signed in as, read from the blob **by this phone**.
  final String user;

  /// Where the computer says the connection is going, or empty when its `ssh`
  /// was too old to say. Empty is shown as unknown rather than hidden: not
  /// knowing is information the user should have.
  final String destination;
}

abstract interface class SshApproval {
  Future<bool> confirm(SshApprovalRequest request);
}

/// Approves nothing. The default wherever no screen is attached.
class DenySshApproval implements SshApproval {
  const DenySshApproval();

  @override
  Future<bool> confirm(SshApprovalRequest request) async => false;
}

/// Signs with the credential reserved for SSH.
///
/// Separate from the authorization signer on purpose. Passing a purpose to one
/// signer would put the two one argument apart, and the argument would
/// eventually be wrong.
abstract interface class SshSigner {
  /// Returns the raw `r || s` pair, or null when the user declined.
  Future<Uint8List?> sign(Uint8List data, {required String prompt});
}

class SshService {
  SshService({SshApproval? approval, SshSigner? signer})
    : _approval = approval ?? const DenySshApproval(),
      _signer = signer;

  final SshApproval _approval;
  final SshSigner? _signer;

  Future<Uint8List> handle(
    Uint8List frame, {
    required Uint8List sessionBinding,
    required bool authorized,
    DateTime? now,
  }) async {
    final request = ApplicationFrame.decode(frame);
    final moment = (now ?? DateTime.now()).toUtc();
    if (request.kind != ApplicationFrameKind.request ||
        !_sameBytes(request.sessionBinding, sessionBinding) ||
        request.isExpiredAt(moment)) {
      throw const FormatException('Frame ssh fora desta sessão');
    }
    // The session's credential has to be the SSH one. A session opened for
    // anything else cannot borrow this key by naming a different operation.
    if (!authorized) return _error(request, ApplicationErrorCode.rejected);

    final SshSignRequest decoded;
    try {
      decoded = SshSignRequest.decode(request.payload);
    } on FormatException {
      return _error(request, ApplicationErrorCode.invalidRequest);
    }

    // Read here, not taken from the frame. A desktop that could supply the
    // account would supply whichever one made approval likeliest.
    final account = accountInRequest(decoded.data);
    if (account == null) {
      return _error(request, ApplicationErrorCode.rejected);
    }

    final signer = _signer;
    if (signer == null) {
      return _error(request, ApplicationErrorCode.unavailable);
    }

    try {
      final approved = await _approval.confirm(
        SshApprovalRequest(
          id: request.requestId,
          verifierName: decoded.verifierName,
          user: account.user,
          destination: decoded.destination,
        ),
      );
      if (!approved) return _error(request, ApplicationErrorCode.rejected);

      final signature = await signer.sign(
        decoded.data,
        prompt: 'Entrar como ${account.user}',
      );
      if (signature == null || signature.length != sshSignatureLength) {
        return _error(request, ApplicationErrorCode.rejected);
      }
      return _reply(request, SshSignResponse(signature: signature).encode());
    } on PlatformException {
      // A refused biometric, a missing key and an invalidated one are one
      // answer on the wire, as everywhere else in this protocol.
      return _error(request, ApplicationErrorCode.rejected);
    } on Object {
      return _error(request, ApplicationErrorCode.unavailable);
    }
  }

  Uint8List _reply(ApplicationFrame request, Uint8List payload) =>
      _frame(request, ApplicationFrameKind.response, payload);

  Uint8List _error(ApplicationFrame request, ApplicationErrorCode code) =>
      _frame(request, ApplicationFrameKind.error, code.encode());

  Uint8List _frame(
    ApplicationFrame request,
    ApplicationFrameKind kind,
    Uint8List payload,
  ) => ApplicationFrame(
    protocolVersion: request.protocolVersion,
    kind: kind,
    requestId: request.requestId,
    sessionBinding: request.sessionBinding,
    operation: request.operation,
    issuedAt: request.issuedAt,
    expiresAt: request.expiresAt,
    payload: payload,
  ).encode();

  static bool _sameBytes(List<int> left, List<int> right) {
    if (left.length != right.length) return false;
    for (var index = 0; index < left.length; index++) {
      if (left[index] != right[index]) return false;
    }
    return true;
  }
}

/// Bridges an arriving sign request to the sheet the user taps.
///
/// The same shape as `InteractiveVaultApproval`, and separate from it for the
/// same reason the sheets are separate: one of them approves something that is
/// spent immediately and the other approves a session.
class InteractiveSshApproval implements SshApproval {
  InteractiveSshApproval({required this.onRequest});

  /// Called when a validated request needs a decision, to put it on screen.
  final void Function(SshApprovalRequest request) onRequest;

  final Map<String, Completer<bool>> _pending = {};

  @override
  Future<bool> confirm(SshApprovalRequest request) {
    // A retry of a request already on screen waits on the same answer rather
    // than stacking a second sheet: one login must not cost two approvals, and
    // two sheets is how a user approves the one they were not reading.
    final existing = _pending[request.id];
    if (existing != null) return existing.future;

    final completer = Completer<bool>();
    _pending[request.id] = completer;
    onRequest(request);
    return completer.future;
  }

  void settle(String requestId, {required bool approved}) {
    final completer = _pending.remove(requestId);
    if (completer != null && !completer.isCompleted) {
      completer.complete(approved);
    }
  }

  /// Refuses everything outstanding. A sheet the user can no longer see must
  /// not stay answerable.
  void abandonAll() {
    for (final id in _pending.keys.toList()) {
      settle(id, approved: false);
    }
  }

  Iterable<String> get pendingRequestIds => _pending.keys;
}
