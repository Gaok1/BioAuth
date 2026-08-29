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

import '../pairing/pairing_record.dart';
import '../protocol/auth_response.dart';
import '../protocol/application_frame.dart';
import '../protocol/enrolment.dart';
import '../protocol/webauthn_relay.dart';
import '../ssh/ssh_service.dart';
import '../vault/vault_approval.dart';
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

class PairedSessionService {
  PairedSessionService({
    required AuthTransport transport,
    required BiometricAuthorizer authorizer,
    required AuthorizationConsent consent,
    VaultStore? vaultStore,
    VaultApproval? vaultApproval,
    SshApproval? sshApproval,
    SshSigner? sshSigner,
    DateTime Function()? clock,
  }) : _transport = transport,
       _authorizer = authorizer,
       _consent = consent,
       _vault = VaultService(repository: vaultStore, approval: vaultApproval),
       _ssh = SshService(approval: sshApproval, signer: sshSigner),
       _clock = clock;

  final AuthTransport _transport;
  final BiometricAuthorizer _authorizer;
  final AuthorizationConsent _consent;
  final VaultService _vault;
  final SshService _ssh;
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
  final WebAuthnRelayHandler _webAuthn = const WebAuthnRelayHandler();
  final Set<String> _closed = {};
  bool _stopped = false;

  /// Stops discovery and closes sessions when the app leaves the foreground.
  Future<void> stop() async {
    if (_stopped) return;
    _stopped = true;
    await _transport.stop();
    await Future.wait(_active.values.toList().map(_close));
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

  /// Connects, waits for one request, answers it, and closes.
  ///
  /// Returns the response that was sent, or null when the desktop asked for
  /// nothing before the timeout. A null is not an error: the caller simply
  /// dials again.
  Future<AuthResponse?> serveOne(
    PairingRecord record, {
    void Function()? onEstablished,
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
    _active[_key(record)] = outcome.session;
    // The channel is authenticated from here on. Reporting it now is what
    // separates "connected" from "has already answered something": waiting for
    // a request would leave an idle, working link looking like it is still
    // dialling for up to the idle timeout.
    onEstablished?.call();

    final core = PhoneAuthCore(
      authorizer: _authorizer,
      consent: _consent,
      policy: policyFor(record),
      clock: _clock,
    );
    final frames = StreamIterator<Uint8List>(outcome.session.incomingFrames);
    try {
      if (!await frames.moveNext().timeout(pairedSessionIdleTimeout)) {
        throw StateError('Desktop closed before sending a request');
      }
      final frame = frames.current;
      if (WebAuthnRelayRequest.recognizes(frame)) {
        final request = WebAuthnRelayRequest.decode(
          frame,
          expectedVerifierId: record.verifierId,
        );
        final response = _webAuthn.perform(request);
        final nextFrame = frames.moveNext().then((available) {
          if (!available) {
            throw StateError('Desktop closed the passkey session');
          }
          return frames.current;
        });
        var nativeSettled = false;
        try {
          final completed = await Future.any<(bool, Uint8List)>([
            response.then((value) => (false, value)),
            nextFrame.then((value) => (true, value)),
          ]);
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
        final response = purpose == CredentialPurpose.ssh
            ? await _ssh.handle(
                frame,
                sessionBinding: outcome.session.sessionBinding,
                authorized: true,
              )
            : await _vault.handle(
                frame,
                sessionBinding: outcome.session.sessionBinding,
                authorized: purpose == CredentialPurpose.vault,
              );
        await outcome.session.send(response);
        return null;
      }
      return await core.serveFrame(outcome.session, frame);
    } on TimeoutException {
      // Nothing was asked for. Not an error: the desktop is simply idle.
      return null;
    } finally {
      await frames.cancel();
      if (identical(_active[_key(record)], outcome.session)) {
        _active.remove(_key(record));
      }
      await _close(outcome.session);
    }
  }
}

/// What the phone will carry for a paired verifier.
VerifierPolicy policyFor(PairingRecord record) => VerifierPolicy(
  verifierId: record.verifierId,
  credentialId: record.credentialId,
  permissions: const [VerifierPermission.any()],
  purpose: record.purpose.name,
);
