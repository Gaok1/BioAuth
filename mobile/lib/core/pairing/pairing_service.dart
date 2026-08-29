/// Drives one pairing from a scanned code to a stored record.
///
/// The order below is forced by the desktop and is not arbitrary. The desktop
/// reads the enrolment immediately after the handshake and only then puts a
/// verification code on screen, so the phone must send the enrolment *before*
/// the user can compare codes. That is safe: an enrolment authorizes nothing.
/// The credential is inert until the user confirms on both screens and then
/// grants it permissions on the desktop.
library;

import 'dart:typed_data';

import 'package:phone_auth_native/phone_auth_native.dart';

import '../protocol/enrolment.dart';
import '../transport/auth_transport.dart';
import '../transport/pairing_bootstrap.dart';
import '../transport/secure_session_establisher.dart';
import 'pairing_record.dart';
import 'pairing_store.dart';

class PairingException implements Exception {
  const PairingException(this.message);

  final String message;

  @override
  String toString() => message;
}

/// A completed handshake awaiting the user's comparison of the two codes.
///
/// Nothing here is trusted yet. The scanned code authenticated the desktop to
/// the phone; [verificationCode] is what closes the other direction, against
/// someone who photographed the code and raced to pair their own device.
class PairingSession {
  PairingSession({
    required this.verificationCode,
    required this.proposed,
    required SecureTransportSession session,
    required PairingStore store,
  }) : _session = session,
       _store = store;

  final String verificationCode;
  final PairingRecord proposed;
  final SecureTransportSession _session;
  final PairingStore _store;
  bool _settled = false;

  /// The user says the codes match.
  Future<void> confirm() async {
    if (_settled) return;
    _settled = true;
    try {
      await _store.save(proposed);
    } on Object {
      // The record is the commit. If it cannot be written, this pairing did
      // not happen and the half-open transport is no longer useful.
      try {
        await _session.close();
      } on Object {
        // Preserve the storage error, which is the actionable failure.
      }
      rethrow;
    }
    // The desktop may close first after its own confirmation. Once the record
    // is durable, a dead socket cannot turn a successful pairing into a UI
    // failure or prevent the devices provider from being refreshed.
    try {
      await _session.close();
    } on Object {
      // Best effort after the local commit.
    }
  }

  /// The user says they do not, or backs out.
  ///
  /// Nothing is stored and the connection drops. There is no rejection frame in
  /// the protocol: the desktop's proposal is discarded by the user there too.
  Future<void> reject() async {
    if (_settled) return;
    _settled = true;
    await _session.close();
  }
}

/// The authorization credential offered during pairing.
///
/// Separate from the session identity key by design: opening a channel happens
/// with no user present and must never touch the key that approves a login.
abstract interface class AuthorizationCredential {
  /// The credential's public half, and how honestly its private half is stored.
  ///
  /// Takes the purpose because the key depends on it: an SSH login and a
  /// `sudo` must not be signed by the same key, or a signature made for one
  /// would be a signature the other accepts.
  Future<({Uint8List publicKey, String algorithm, KeyKind keyKind})> describe(
    CredentialPurpose purpose,
  );
}

class NativeAuthorizationCredential implements AuthorizationCredential {
  const NativeAuthorizationCredential({
    SecureAuthenticator authenticator = const PhoneAuthNative(),
  }) : _authenticator = authenticator;

  final SecureAuthenticator _authenticator;

  @override
  Future<({Uint8List publicKey, String algorithm, KeyKind keyKind})>
  describe(CredentialPurpose purpose) async {
    final key = purpose == CredentialPurpose.ssh
        ? await _authenticator.generateSshKey()
        : await _authenticator.generateKey();
    final capabilities = await _authenticator.getSecurityCapabilities();
    // Reported honestly, including when it is bad news: the verifier uses this
    // only to withhold authority, never to grant more of it.
    final keyKind = capabilities.strongBoxBacked
        ? KeyKind.strongBox
        : capabilities.hardwareBacked
        ? KeyKind.hardware
        : KeyKind.software;
    return (publicKey: key.bytes, algorithm: key.algorithm, keyKind: keyKind);
  }
}

class PairingService {
  PairingService({
    required AuthTransport transport,
    required PairingStore store,
    required this.deviceName,
    AuthorizationCredential credential = const NativeAuthorizationCredential(),
    DateTime Function()? clock,
  }) : _transport = transport,
       _store = store,
       _credential = credential,
       _clock = clock ?? DateTime.now;

  final AuthTransport _transport;
  final PairingStore _store;
  final AuthorizationCredential _credential;
  final String deviceName;
  final DateTime Function() _clock;

  /// Runs the handshake and the enrolment for a scanned code.
  Future<PairingSession> begin(String scannedUri) async {
    final PairingBootstrap bootstrap;
    try {
      bootstrap = PairingBootstrap.parse(scannedUri.trim());
    } on BootstrapException catch (error) {
      throw PairingException(
        'Este QR não é um código de pareamento: '
        '${error.message}',
      );
    }

    final now = _clock().toUtc();
    if (bootstrap.isExpiredAt(now.millisecondsSinceEpoch)) {
      throw const PairingException(
        'Este código expirou. Gere um novo no computador.',
      );
    }
    if (bootstrap.endpoint.isEmpty) {
      throw const PairingException(
        'Este código não traz um endereço para conectar.',
      );
    }

    final outcome = await _transport.connect(
      TransportPeer(
        transportId: bootstrap.endpoint,
        displayName: bootstrap.verifierId,
      ),
      ScannedVerifier(bootstrap),
    );
    if (!outcome.wasPairing) {
      await outcome.session.close();
      throw const PairingException('O computador não estava em pareamento.');
    }

    late final ({Uint8List publicKey, String algorithm, KeyKind keyKind})
    credential;
    final purpose = bootstrap.purpose;
    final credentialId = '${bootstrap.verifierId}-${purpose.name}-v1';
    try {
      credential = await _credential.describe(purpose);
      await outcome.session.send(
        Enrolment(
          deviceName: deviceName,
          credentialId: credentialId,
          algorithm: credential.algorithm,
          publicKey: credential.publicKey,
          keyKind: credential.keyKind,
          purpose: purpose,
        ).encode(),
      );
    } on Object {
      try {
        await outcome.session.close();
      } on Object {
        // Preserve the credential/enrolment error that caused the cleanup.
      }
      rethrow;
    }

    return PairingSession(
      verificationCode: outcome.verificationCode,
      proposed: PairingRecord(
        verifierId: outcome.verifierId,
        verifierIdentitySpki: outcome.verifierIdentitySpki,
        endpoint: bootstrap.endpoint,
        credentialId: credentialId,
        keyKind: credential.keyKind,
        purpose: purpose,
        pairedAt: now,
      ),
      session: outcome.session,
      store: _store,
    );
  }
}
