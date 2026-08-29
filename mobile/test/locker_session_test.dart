/// The locker, over a paired session.
///
/// The pieces existed and were tested one at a time — the container format,
/// the wrapper, the frames, the CLI — but no session ever handed a `locker.*`
/// frame to [LockerService]. Every purpose that was not SSH went to the vault,
/// which does not know these operations and, for a locker credential, was not
/// authorized anyway. So pairing a computer for the file locker produced a
/// credential that answered every request with a refusal.
library;

import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/locker/locker_service.dart';
import 'package:phone_auth/core/pairing/pairing_record.dart';
import 'package:phone_auth/core/protocol/application_frame.dart';
import 'package:phone_auth/core/protocol/enrolment.dart';
import 'package:phone_auth/core/protocol/locker_payloads.dart';
import 'package:phone_auth/core/session/paired_session_service.dart';
import 'package:phone_auth/core/session/phone_auth_core.dart';
import 'package:phone_auth/core/transport/auth_transport.dart';
import 'package:phone_auth/core/transport/secure_session_establisher.dart';
import 'package:phone_auth/domain/authentication_request.dart';

void main() {
  late _Guardian guardian;

  setUp(() => guardian = _Guardian());

  Future<ApplicationFrame> serve(CredentialPurpose purpose) async {
    final session = _Session();
    final service = PairedSessionService(
      transport: _Transport(session),
      authorizer: _UnusedAuthorizer(),
      consent: _UnusedConsent(),
      lockerGuardian: guardian,
    );
    final serving = service.serveOne(_record(purpose));
    await session.listening.future;
    session.deliver(_create());
    await serving;
    // The first frame out is the session attach; the answer is the last.
    return ApplicationFrame.decode(session.sent.last);
  }

  test('a locker credential reaches the key that wraps containers', () async {
    final answer = await serve(CredentialPurpose.fileLocker);

    expect(answer.kind, ApplicationFrameKind.response);
    expect(answer.operation, lockerCreateOperation);
    expect(guardian.fileName, 'tax return.pdf');
    // The credential the session was opened with, never one named in a frame:
    // it goes into the wrapper's AAD, so it decides what the wrapper opens.
    expect(guardian.credentialId, 'desktop-1-fileLocker-v1');
    expect(
      LockerWrapResponse.decode(answer.payload).credentialId,
      'desktop-1-fileLocker-v1',
    );
  });

  test('a vault credential cannot wrap a container by asking', () async {
    final answer = await serve(CredentialPurpose.vault);

    expect(answer.kind, ApplicationFrameKind.error);
    expect(
      guardian.credentialId,
      isNull,
      reason: 'which handler serves a frame is the credential, not the name',
    );
  });
}

PairingRecord _record(CredentialPurpose purpose) => PairingRecord(
  verifierId: 'desktop-1',
  verifierIdentitySpki: Uint8List.fromList([1, 2, 3]),
  endpoint: '192.0.2.1:42371',
  credentialId: 'desktop-1-${purpose.name}-v1',
  keyKind: KeyKind.hardware,
  purpose: purpose,
  pairedAt: DateTime.utc(2026, 8, 27),
);

final _now = DateTime.now().toUtc();

Uint8List _create() => ApplicationFrame(
  protocolVersion: 1,
  kind: ApplicationFrameKind.request,
  requestId: 'request-1',
  // What [_Session] reports, which is what the service checks against.
  sessionBinding: Uint8List(32),
  operation: lockerCreateOperation,
  issuedAt: _now,
  expiresAt: _now.add(const Duration(seconds: 60)),
  payload: LockerWrapRequest(
    verifierName: 'Workstation',
    fileName: 'tax return.pdf',
    plaintextLength: 100000,
    containerBinding: List<int>.generate(32, (index) => index),
    dataKey: List<int>.filled(32, 7),
  ).encode(),
).encode();

/// Records what it was asked to wrap. The cryptography is the Keystore's.
class _Guardian implements LockerKeyGuardian {
  String? credentialId;
  String? fileName;

  @override
  Future<Uint8List> wrap({
    required Uint8List binding,
    required String credentialId,
    required Uint8List dataKey,
    required String fileName,
    required String verifierName,
  }) async {
    this.credentialId = credentialId;
    this.fileName = fileName;
    return Uint8List.fromList(List<int>.filled(60, 4));
  }

  @override
  Future<Uint8List> unwrap({
    required Uint8List binding,
    required String credentialId,
    required Uint8List wrapper,
    required String fileName,
    required String verifierName,
    bool rekeying = false,
  }) async => throw UnimplementedError();
}

class _Transport implements AuthTransport {
  _Transport(this.session);

  final _Session session;

  @override
  TransportSecurityProperties get securityProperties => _properties;

  @override
  Future<void> start() async {}

  @override
  Future<void> stop() async {}

  @override
  Stream<TransportPeer> discoverPeers() => const Stream.empty();

  @override
  Future<SecureSessionOutcome> connect(
    TransportPeer peer,
    VerifierExpectation expectation,
  ) async => SecureSessionOutcome(
    session: session,
    verifierIdentitySpki: Uint8List.fromList([1, 2, 3]),
    verifierId: 'desktop-1',
    sessionId: 'session-1',
    verificationCode: '123456',
    wasPairing: false,
  );
}

class _Session implements SecureTransportSession {
  _Session() {
    _incoming = StreamController<Uint8List>(onListen: listening.complete);
  }

  late final StreamController<Uint8List> _incoming;
  final listening = Completer<void>();
  final sent = <Uint8List>[];

  void deliver(Uint8List frame) => _incoming.add(frame);

  @override
  String get originLabel => 'test';

  @override
  Uint8List get sessionBinding => Uint8List(32);

  @override
  TransportSecurityProperties get securityProperties => _properties;

  @override
  Stream<Uint8List> get incomingFrames => _incoming.stream;

  @override
  Future<void> send(Uint8List frame) async => sent.add(frame);

  @override
  Future<void> close() async {
    if (!_incoming.isClosed) unawaited(_incoming.close());
  }
}

class _UnusedAuthorizer implements BiometricAuthorizer {
  @override
  Future<AuthorizationProof> authorize({
    required AuthenticationRequest request,
    required Uint8List canonicalRequest,
    String purpose = 'authorization',
  }) => throw UnimplementedError();
}

class _UnusedConsent implements AuthorizationConsent {
  @override
  Future<bool> confirm(
    AuthenticationRequest request,
    TransportSecurityProperties transport,
  ) => throw UnimplementedError();
}

const _properties = TransportSecurityProperties(
  transportName: 'test',
  confidential: true,
  peerAuthenticated: true,
  requiresNetwork: true,
  proximitySignal: false,
  expectedLatency: Duration(milliseconds: 10),
);
