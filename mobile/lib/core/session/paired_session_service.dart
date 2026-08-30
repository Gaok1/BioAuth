/// Holds a connection to a paired desktop and serves one authorization on it.
///
/// The desktop listens and the phone dials, but the *request* travels the other
/// way: the desktop parks the session and sends an `AuthRequest` when it needs
/// one. So the phone connects and waits, and one session carries exactly one
/// authorization — holding a channel open across requests would make a phone
/// that walked out of range look available until the first timeout.
library;

import 'dart:async';
import 'dart:typed_data';

import '../../domain/authentication_request.dart';
import '../pairing/pairing_record.dart';
import '../protocol/auth_response.dart';
import '../protocol/application_frame.dart';
import '../protocol/application_idempotency.dart';
import '../protocol/enrolment.dart';
import '../protocol/session_attach.dart';
import '../protocol/webauthn_relay.dart';
import '../locker/locker_service.dart';
import '../luks/luks_service.dart';
import '../ssh/ssh_service.dart';
import '../vault/vault_approval.dart';
import '../vault/vault_listing.dart';
import '../vault/vault_service.dart';
import '../../features/vault/vault_store.dart';
import '../transport/auth_transport.dart';
import '../transport/secure_session_establisher.dart';
import 'phone_auth_core.dart';

/// How long a connected phone waits for the desktop to ask for something.
///
/// Shorter than the desktop's 300-second idle timeout, so the phone reconnects
/// while the desktop still considers the previous session live.
const Duration pairedSessionIdleTimeout = Duration(minutes: 4);

/// The longest a session may spend waiting for the person to answer a request
/// that names no deadline of its own.
///
/// The protocol caps a request's validity at two minutes and the phone allows
/// another thirty seconds of clock skew when one arrives, so past this the
/// desktop has stopped waiting no matter what happens on the phone next.
///
/// A request that *does* name a deadline is bounded by that instead, and it is
/// always the shorter of the two. See [PairedSessionService._answered].
const Duration pairedSessionAnswerTimeout = Duration(minutes: 2, seconds: 30);

/// Thrown when nobody answered inside the window the desktop gave.
///
/// Not a [TimeoutException]: an idle session that was never asked anything is
/// ordinary and reconnects quietly, and this is a request that was asked and
/// went unanswered — the sheets it raised have to come down with it.
class PairedSessionAnswerExpired implements Exception {
  const PairedSessionAnswerExpired();

  @override
  String toString() => 'O pedido expirou antes de ser respondido';
}

class PairedSessionService {
  PairedSessionService({
    required AuthTransport transport,
    required BiometricAuthorizer authorizer,
    required AuthorizationConsent consent,
    VaultStore? vaultStore,
    VaultApproval? vaultApproval,
    SshApproval? sshApproval,
    SshSigner? sshSigner,
    LockerKeyGuardian? lockerGuardian,
    LuksKeyGuardian? luksGuardian,
    WebAuthnRelayHandler? webAuthn,
    Duration? answerTimeout,
    DateTime Function()? clock,
  }) : _answerTimeout = answerTimeout ?? pairedSessionAnswerTimeout,
       _webAuthn = webAuthn ?? const WebAuthnRelayHandler(),
       _transport = transport,
       _authorizer = authorizer,
       _consent = consent,
       _vaultStore = vaultStore,
       _vaultApproval = vaultApproval,
       _sshApproval = sshApproval,
       _sshSigner = sshSigner,
       _lockerGuardian = lockerGuardian ?? const NativeLockerKeyGuardian(),
       _luksGuardian = luksGuardian ?? const NativeLuksKeyGuardian(),
       _clock = clock;

  final AuthTransport _transport;
  final BiometricAuthorizer _authorizer;
  final AuthorizationConsent _consent;

  /// The parts of the vault and ssh services rather than the services.
  ///
  /// Both are built per session, because the approval they raise has to be
  /// attributable to the session that raised it: a session that dies with a
  /// sheet on screen must refuse that sheet and no other.
  final VaultStore? _vaultStore;

  /// Shared across sessions, because a paged listing is several of them.
  ///
  /// A session carries one request and closes, so the desktop walking a vault
  /// opens one per page. Built per session, the snapshot would be discarded
  /// between every page and each page would cost its own unlock -- which is
  /// the whole thing [VaultListing] exists to stop.
  late final VaultListing _listing = VaultListing(
    store: _vaultStore ?? const NativeVaultStore(),
  );
  final VaultApproval? _vaultApproval;
  final SshApproval? _sshApproval;
  final SshSigner? _sshSigner;

  /// Held rather than a built service, because a locker service is bound to one
  /// credential: the credential id goes into the wrapper's AAD, so the same key
  /// unwrapping for a different credential must not produce the same bytes.
  final LockerKeyGuardian _lockerGuardian;

  /// Held for the same reason, and it matters more here: the volume name
  /// and the credential id are both in the wrapper's AAD, so a blob wrapped
  /// for one volume cannot be unwrapped as another.
  final LuksKeyGuardian _luksGuardian;

  /// Whose request ids these are: one desktop, one of its credentials.
  ///
  /// A NUL joins them because neither part can contain one, so no pair of
  /// values can spell another pair's scope.
  static String _replayScope(PairingRecord record) =>
      '${record.verifierId}\u0000${record.credentialId}';

  /// Answers already given, so a re-sent request id is not served twice.
  ///
  /// Held here because this is the object that outlives a session, and a
  /// session is one request: the phone answers a frame, the desktop hangs up,
  /// and a retry arrives on a fresh connection. A cache belonging to anything
  /// narrower than this is consulted exactly once, when it is empty.
  final ApplicationIdempotency _retries = ApplicationIdempotency();

  /// How long one request may spend waiting for the person to answer.
  ///
  /// Injectable only so a test can watch the deadline pass without spending
  /// the two and a half minutes it describes.
  final Duration _answerTimeout;
  final DateTime Function()? _clock;
  // Keyed by credential: one loop dials each credential, so one session per
  // credential is live at a time. A desktop holding both a login and a vault
  // credential has two, and revoking the desktop has to reach both.
  // Keyed by verifier *and* credential. Credential alone is not a key: it is
  // chosen by the desktop, so two desktops can hand out the same id and the
  // second session would evict the first — which is a revocation that closes
  // nothing. Verifier alone is not a key either, since one computer can hold
  // several credentials and each has its own session.
  final Map<(String, String), SecureTransportSession> _active = {};
  final WebAuthnRelayHandler _webAuthn;
  final Set<String> _closed = {};
  bool _stopped = false;

  /// Stops discovery and closes sessions when the app leaves the foreground.
  Future<void> stop() async {
    if (_stopped) return;
    _stopped = true;
    await _transport.stop();
    await Future.wait(_active.values.toList().map(_close));
    // Nothing left to page through it, and it is the vault's metadata.
    _listing.forget();
  }

  /// Closes the live session with one verifier and refuses later ones.
  ///
  /// Revocation cannot wait for the idle timeout: until this returns, the
  /// phone still holds an authenticated channel to a desktop the user has
  /// just said they no longer trust.
  Future<void> closeDevice(String verifierId) async {
    _closed.add(verifierId);
    for (final entry in _active.entries.toList()) {
      if (entry.key.$1 != verifierId) continue;
      _active.remove(entry.key);
      await _close(entry.value);
    }
  }

  /// Lets a verifier be served again, after pairing with it afresh.
  void allowDevice(String verifierId) => _closed.remove(verifierId);

  static (String, String) _key(PairingRecord record) =>
      (record.verifierId, record.credentialId);

  Future<void> _close(SecureTransportSession session) async {
    try {
      await session.close();
    } on Object {
      // Every session is independent; one broken link must not keep the
      // others alive after the lifecycle owner has stopped.
    }
  }

  /// Bounds the time one request may spend waiting for a person.
  ///
  /// Every path to an answer ends in a prompt or a sheet, and every one of them
  /// waited for it forever. A request nobody answers is not rare -- the phone is
  /// in a pocket, the sheet is behind a game -- and holding it kept that
  /// credential's loop on a session the desktop had already given up on, so the
  /// computer sat there looking connected to a phone that would never answer.
  /// Whatever the answer eventually was, it went into a closed socket.
  ///
  /// [until] is the request's own deadline, when it carries one. The desktop
  /// refuses an answer that arrives after it, so every second of patience past
  /// that point is spent on a reply nobody can accept -- and the way this
  /// phone spends it is a biometric prompt and a decrypted secret. The sheet
  /// comes down at the deadline instead, which is the truth: the thing it was
  /// offering to approve is gone.
  Future<T> _answered<T>(Future<T> work, {DateTime? until}) {
    var window = _answerTimeout;
    if (until != null) {
      final left = until.difference((_clock ?? DateTime.now)());
      if (left < window) window = left.isNegative ? Duration.zero : left;
    }
    return work.timeout(
      window,
      onTimeout: () => throw const PairedSessionAnswerExpired(),
    );
  }

  /// When the desktop stops accepting an answer to [frame], if it says.
  ///
  /// A frame this cannot read is left to the handler, which answers a
  /// malformed request with an error of its own rather than throwing here.
  static DateTime? _deadlineOf(Uint8List frame) {
    try {
      return ApplicationFrame.decode(frame).expiresAt;
    } on Object {
      return null;
    }
  }

  /// Connects, waits for one request, answers it, and closes.
  ///
  /// Returns the response that was sent, or null when the desktop asked for
  /// nothing before the timeout. A null is not an error: the caller simply
  /// dials again.
  ///
  /// [onRequestRaised] fires with the id of every request this session puts in
  /// front of the user, so a caller cleaning up after a broken session can
  /// name what *this* session left pending instead of everything pending.
  Future<AuthResponse?> serveOne(
    PairingRecord record, {
    void Function()? onEstablished,
    void Function(String requestId)? onRequestRaised,
  }) async {
    if (_stopped) throw StateError('Serviço de sessões encerrado');
    if (_closed.contains(record.verifierId)) {
      throw StateError('Dispositivo revogado');
    }
    final outcome = await _transport.connect(
      TransportPeer(
        transportId: record.endpoint,
        displayName: record.verifierId,
      ),
      PairedVerifier(record.verifierIdentitySpki),
    );
    if (_stopped || _closed.contains(record.verifierId)) {
      await outcome.session.close();
      throw StateError('Serviço de sessões encerrado');
    }
    if (outcome.wasPairing) {
      // The transport reported first contact for a device that is already
      // paired. Nothing about that session is trusted.
      await outcome.session.close();
      throw StateError(
        'O computador respondeu como se nunca tivesse sido pareado',
      );
    }
    // Everything from here on owns the session, so everything from here on
    // has to give it back. The `finally` used to start below, after the attach
    // frame and the services were built -- and an attach that fails is not
    // exotic: it is the first write on a link that has just been established,
    // which over BLE is exactly where writes fail. That threw with the session
    // still open. On the LAN that leaks a socket; over the fallback it leaks
    // the phone's one GATT client, whose gate the next connection waits on
    // with no timeout at all. One failed write and the phone stops answering
    // over Bluetooth until it is restarted, silently, with nothing raised.
    StreamIterator<Uint8List>? frames;
    try {
      // Which of this phone's credentials the session is for. The desktop parks
      // one session per credential and picks the one matching the request it is
      // about to send; without this it picked whichever arrived last, and a
      // vault request going out over the login session comes back refused.
      await outcome.session.send(
        SessionAttach(credentialId: record.credentialId).encode(),
      );
      _active[_key(record)] = outcome.session;
      // The channel is authenticated from here on. Reporting it now is what
      // separates "connected" from "has already answered something": waiting for
      // a request would leave an idle, working link looking like it is still
      // dialling for up to the idle timeout.
      onEstablished?.call();

      final vault = VaultService(
        repository: _vaultStore,
        listing: _listing,
        retries: _retries,
        approval: onRequestRaised == null
            ? _vaultApproval
            : _ScopedVaultApproval(_vaultApproval, onRequestRaised),
      );
      final ssh = SshService(
        approval: onRequestRaised == null
            ? _sshApproval
            : _ScopedSshApproval(_sshApproval, onRequestRaised),
        signer: _sshSigner,
      );
      final core = PhoneAuthCore(
        authorizer: _authorizer,
        consent: onRequestRaised == null
            ? _consent
            : _SessionScopedConsent(_consent, onRequestRaised),
        policy: policyFor(record),
        clock: _clock,
      );
      final incoming = StreamIterator<Uint8List>(
        outcome.session.incomingFrames,
      );
      frames = incoming;
      if (!await incoming.moveNext().timeout(pairedSessionIdleTimeout)) {
        throw StateError('Desktop closed before sending a request');
      }
      final frame = incoming.current;
      if (WebAuthnRelayRequest.recognizes(frame)) {
        final request = WebAuthnRelayRequest.decode(
          frame,
          expectedVerifierId: record.verifierId,
        );
        final response = _webAuthn.perform(request);
        final nextFrame = incoming.moveNext().then((available) {
          if (!available) {
            throw StateError('Desktop closed the passkey session');
          }
          return incoming.current;
        });
        // A read that produced no frame is `null` rather than a throw, because
        // the race below has to be able to lose to it. Whichever side loses is
        // left with nobody awaiting it, and the loser is normally this one:
        // the outer `finally` cancels the iterator underneath it.
        final cancelled = nextFrame.then<(bool, Uint8List)?>(
          (value) => (true, value),
          onError: (Object _) => null,
        );
        var nativeSettled = false;
        try {
          // Bounded like every other path to a person. This one alone was not,
          // and it is the only one where the phone learns the exchange is over
          // solely by the desktop hanging up: the relay frame carries no
          // deadline of its own, so a half-open socket -- a lid closed, an
          // agent killed -- left the passkey prompt up and the session held
          // for as long as TCP took to notice, which is hours.
          final completed = await _answered(
            Future.any<(bool, Uint8List)?>([
              response.then((value) => (false, value)),
              cancelled,
            ]),
          );
          if (completed == null) {
            throw StateError('Desktop closed the passkey session');
          }
          if (completed.$1) {
            final cancel = WebAuthnRelayCancel.decode(completed.$2);
            if (cancel.requestId != request.requestId) {
              throw const FormatException(
                'Cancellation belongs to another request',
              );
            }
            await _webAuthn.cancel(request.requestId);
            nativeSettled = true;
          }
          final encoded = await response;
          nativeSettled = true;
          await outcome.session.send(encoded);
        } finally {
          if (!nativeSettled) {
            await _webAuthn.cancel(request.requestId);
          }
        }
        return null;
      }
      if (ApplicationFrame.recognizes(frame)) {
        // Which handler serves a frame is decided by the credential this
        // session was opened with, not by the operation name in it. A session
        // opened for the vault cannot reach the SSH key by asking for
        // `ssh.sign`, and the other way round.
        final purpose = record.purpose;
        final serving = switch (purpose) {
          CredentialPurpose.ssh => ssh.handle(
            frame,
            sessionBinding: outcome.session.sessionBinding,
            authorized: true,
          ),
          // The locker asks the Keystore for the gesture itself, naming the
          // file and the computer in the prompt, so there is no separate
          // `authorized` to pass: refusing the fingerprint is the refusal.
          CredentialPurpose.fileLocker =>
            LockerService(
              guardian: _lockerGuardian,
              credentialId: record.credentialId,
              retries: _retries,
            ).handle(
              frame,
              sessionBinding: outcome.session.sessionBinding,
              replayScope: _replayScope(record),
            ),
          // Same shape as the locker, and the same reason for it: the
          // Keystore raises the prompt itself, naming the volume and the
          // computer, so refusing the fingerprint is the refusal.
          CredentialPurpose.diskUnlock =>
            LuksService(
              guardian: _luksGuardian,
              credentialId: record.credentialId,
              retries: _retries,
            ).handle(
              frame,
              sessionBinding: outcome.session.sessionBinding,
              replayScope: _replayScope(record),
            ),
          _ => vault.handle(
            frame,
            sessionBinding: outcome.session.sessionBinding,
            authorized: purpose == CredentialPurpose.vault,
            replayScope: _replayScope(record),
          ),
        };
        await outcome.session.send(
          await _answered(serving, until: _deadlineOf(frame)),
        );
        return null;
      }
      return await _answered(core.serveFrame(outcome.session, frame));
    } on TimeoutException {
      // Nothing was asked for. Not an error: the desktop is simply idle.
      return null;
    } finally {
      await frames?.cancel();
      if (identical(_active[_key(record)], outcome.session)) {
        _active.remove(_key(record));
      }
      await _close(outcome.session);
    }
  }
}

/// Reports each request a single session raises, then defers to the real one.
///
/// Consent is process-wide: one screen, one queue, whichever session filled it.
/// That is right for showing the prompt and wrong for cleaning up after a
/// broken link, which needs to name only its own. This is the seam between the
/// two — it observes, it decides nothing.
class _SessionScopedConsent implements AuthorizationConsent {
  _SessionScopedConsent(this._inner, this._onRaised);

  final AuthorizationConsent _inner;
  final void Function(String requestId) _onRaised;

  @override
  Future<bool> confirm(
    AuthenticationRequest request,
    TransportSecurityProperties transport,
  ) {
    _onRaised(request.requestId);
    return _inner.confirm(request, transport);
  }
}

/// The same seam as [_SessionScopedConsent], for the vault's sheet.
///
/// A sheet is raised by one session and answered by a person, and the two can
/// be minutes apart -- long enough for the link to drop. Without this the
/// service could not say which sheets belonged to the session that died, so
/// none of them were withdrawn: the request stayed pending forever, and the
/// desktop's retry of the same request id waited on that same dead answer.
///
/// A null inner approval stays null-shaped: [VaultService] turns that into a
/// refusal, which is not this class's decision to pre-empt.
class _ScopedVaultApproval implements VaultApproval {
  _ScopedVaultApproval(this._inner, this._onRaised);

  final VaultApproval? _inner;
  final void Function(String requestId) _onRaised;

  @override
  Future<bool> confirm(VaultApprovalRequest request) {
    _onRaised(request.id);
    return (_inner ?? const DenyVaultApproval()).confirm(request);
  }
}

/// The same, for the sheet that approves an SSH signature.
class _ScopedSshApproval implements SshApproval {
  _ScopedSshApproval(this._inner, this._onRaised);

  final SshApproval? _inner;
  final void Function(String requestId) _onRaised;

  @override
  Future<bool> confirm(SshApprovalRequest request) {
    _onRaised(request.id);
    return (_inner ?? const DenySshApproval()).confirm(request);
  }
}

/// What the phone will carry for a paired verifier.
VerifierPolicy policyFor(PairingRecord record) => VerifierPolicy(
  verifierId: record.verifierId,
  credentialId: record.credentialId,
  permissions: const [VerifierPermission.any()],
  purpose: record.purpose.name,
);
