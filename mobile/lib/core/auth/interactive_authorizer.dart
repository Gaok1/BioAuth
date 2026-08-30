/// Bridges the protocol core to the screen the user actually taps.
///
/// [PhoneAuthCore] owns the checks — session binding, validity window, replay,
/// policy — and asks one question at the end: does the user consent? That
/// question has to suspend until a human answers it, which is what this does.
///
/// Keeping the suspension here rather than in the core means the core stays
/// synchronous in its reasoning: by the time consent is asked for, every
/// cryptographic and structural check has already passed or the request never
/// reached the screen.
library;

import 'dart:async';

import '../../domain/authentication_request.dart';
import '../../domain/connection_phase.dart';
import '../session/phone_auth_core.dart';
import '../transport/auth_transport.dart';
import 'phone_authenticator.dart';

class InteractiveAuthorizer
    implements AuthorizationConsent, PhoneAuthenticator {
  InteractiveAuthorizer({required this.onRequest});

  /// Called when a validated request arrives, to put it on screen.
  final void Function(AuthenticationRequest request) onRequest;

  final Map<String, Completer<bool>> _consent = {};
  final Map<String, Completer<AuthorizationResult>> _outcome = {};

  /// The core side: shows the request and waits for a tap.
  @override
  Future<bool> confirm(
    AuthenticationRequest request,
    TransportSecurityProperties transport,
  ) {
    // Belt and braces. The core refuses a non-confidential session before it
    // gets here, and a bug that let one through must not reach a human who
    // would reasonably assume the channel was safe.
    if (!transport.confidential || !transport.peerAuthenticated) {
      return Future.value(false);
    }
    final completer = _consent.putIfAbsent(request.id, Completer<bool>.new);
    onRequest(request);
    return completer.future;
  }

  /// The UI side: releases the core, then waits for it to finish.
  ///
  /// The biometric prompt happens inside the core, after this returns control
  /// to it, so the result only arrives once the signature exists or the user
  /// dismissed the prompt.
  @override
  Future<AuthorizationResult> authorize(
    AuthenticationRequest request, {
    required void Function(ConnectionPhase phase) onPhase,
  }) {
    final consent = _consent.remove(request.id);
    if (consent == null) {
      // The session that carried this request is gone: it timed out, or the
      // desktop hung up. Nothing to sign against.
      return Future.error(
        StateError('Esta solicitação não está mais conectada'),
      );
    }
    // Created here rather than in [confirm], because this is the first moment
    // anyone waits on it. Creating it when the sheet went up meant a request
    // the user never answered still had a completer, and [abandon] failed it
    // into nothing — an unhandled asynchronous error every time a session
    // ended with an untouched prompt on screen, which is a routine event.
    final outcome = _outcome.putIfAbsent(
      request.id,
      Completer<AuthorizationResult>.new,
    );
    onPhase(ConnectionPhase.awaitingBiometric);
    consent.complete(true);
    return outcome.future;
  }

  /// The user denied it without a biometric prompt. The core still answers the
  /// desktop, with a denial.
  @override
  void cancel(String requestId) {
    _consent.remove(requestId)?.complete(false);
  }

  /// Called by the runner once the exchange finished, with what was sent.
  void settle(String requestId, AuthorizationResult result) {
    _outcome.remove(requestId)?.complete(result);
  }

  /// Called when a session ends without an answer, so nothing waits forever.
  void abandon(String requestId, Object reason) {
    _consent.remove(requestId)?.complete(false);
    final outcome = _outcome.remove(requestId);
    if (outcome != null && !outcome.isCompleted) outcome.completeError(reason);
  }

  /// Refuses every prompt still waiting to be tapped.
  ///
  /// Called when the app leaves the foreground: a sheet the user can no longer
  /// see must not stay answerable, or a tap landing on it as the phone comes
  /// back approves a `sudo` nobody read.
  ///
  /// Only the untapped ones. A request already in [_outcome] is one the user
  /// consented to and whose biometric prompt is in flight -- and on some
  /// devices that prompt is itself what puts the app in the background. This
  /// is the same distinction the lifecycle handler draws between `inactive`
  /// and `paused`, and getting it wrong here would refuse a request in the
  /// middle of the gesture approving it.
  void abandonUnanswered() {
    for (final id in _consent.keys.toList()) {
      _consent.remove(id)?.complete(false);
    }
  }

  Iterable<String> get pendingRequestIds => {
    ..._consent.keys,
    ..._outcome.keys,
  };
}
