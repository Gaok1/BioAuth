/// The phone's side of `ssh.sign`.
///
/// Every test here is a way a key that opens shells gets used without its
/// owner meaning it. The desktop is assumed compromised in all of them,
/// because that is the case these checks exist for.
library;

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/protocol/application_frame.dart';
import 'package:phone_auth/core/protocol/ssh_payloads.dart';
import 'package:phone_auth/core/ssh/ssh_service.dart';

void main() {
  final binding = Uint8List.fromList(List<int>.generate(32, (i) => i));
  final now = DateTime.utc(2026, 8, 28, 18);

  Uint8List userauthBlob(String user, String method) {
    final out = <int>[];
    void string(List<int> value) {
      out.addAll([
        (value.length >> 24) & 0xff,
        (value.length >> 16) & 0xff,
        (value.length >> 8) & 0xff,
        value.length & 0xff,
      ]);
      out.addAll(value);
    }

    string('session-identifier'.codeUnits);
    out.add(50);
    string(user.codeUnits);
    string('ssh-connection'.codeUnits);
    string(method.codeUnits);
    out.add(1);
    string('ecdsa-sha2-nistp256'.codeUnits);
    string('key-blob'.codeUnits);
    return Uint8List.fromList(out);
  }

  Uint8List frame({
    required Uint8List data,
    String verifierName = 'Meu computador',
    String destination = 'SHA256:aaaa',
  }) => ApplicationFrame(
    protocolVersion: 1,
    kind: ApplicationFrameKind.request,
    requestId: 'request-1',
    sessionBinding: binding,
    operation: sshSignOperation,
    issuedAt: now,
    expiresAt: now.add(const Duration(minutes: 1)),
    payload: SshSignRequest(
      verifierName: verifierName,
      destination: destination,
      data: data,
    ).encode(),
  ).encode();

  Future<ApplicationFrame> serve(
    SshService service,
    Uint8List request, {
    bool authorized = true,
  }) async => ApplicationFrame.decode(
    await service.handle(
      request,
      sessionBinding: binding,
      authorized: authorized,
      now: now,
    ),
  );

  test('a well-formed login is approved, signed and answered', () async {
    final approval = _Recording(approve: true);
    final signer = _Signer();
    final service = SshService(approval: approval, signer: signer);

    final reply = await serve(
      service,
      frame(data: userauthBlob('alice', 'publickey')),
    );

    expect(reply.kind, ApplicationFrameKind.response);
    expect(
      SshSignResponse.decode(reply.payload).signature,
      hasLength(sshSignatureLength),
    );
    expect(signer.calls, 1);
  });

  /// The account shown is the one this phone read out of the blob. A desktop
  /// that could supply it would supply whichever one made approval likeliest.
  test('the account shown comes from the blob, not from the frame', () async {
    final approval = _Recording(approve: true);
    final service = SshService(approval: approval, signer: _Signer());

    await serve(service, frame(data: userauthBlob('deploy', 'publickey')));

    expect(approval.seen.single.user, 'deploy');
    expect(approval.seen.single.verifierName, 'Meu computador');
    expect(approval.seen.single.destination, 'SHA256:aaaa');
  });

  /// The whole safety property. A blob that is not a publickey userauth
  /// request never reaches the approval, let alone the key.
  test(
    'a blob that is not a login is refused before anything is asked',
    () async {
      for (final data in [
        Uint8List.fromList('bytes que alguém quer assinados'.codeUnits),
        userauthBlob('alice', 'hostbased'),
        userauthBlob('alice', 'password'),
        userauthBlob('', 'publickey'),
      ]) {
        final approval = _Recording(approve: true);
        final signer = _Signer();
        final service = SshService(approval: approval, signer: signer);

        final reply = await serve(service, frame(data: data));

        expect(reply.kind, ApplicationFrameKind.error);
        expect(approval.seen, isEmpty, reason: 'the user was asked about it');
        expect(signer.calls, 0, reason: 'the key was used');
      }
    },
  );

  test('a refusal never reaches the key', () async {
    final signer = _Signer();
    final service = SshService(
      approval: _Recording(approve: false),
      signer: signer,
    );

    final reply = await serve(
      service,
      frame(data: userauthBlob('alice', 'publickey')),
    );

    expect(reply.kind, ApplicationFrameKind.error);
    expect(
      ApplicationErrorCode.decode(reply.payload),
      ApplicationErrorCode.rejected,
    );
    expect(signer.calls, 0);
  });

  /// A session opened for something else must not borrow this key by naming a
  /// different operation.
  test('a session without the ssh credential is refused', () async {
    final signer = _Signer();
    final service = SshService(
      approval: _Recording(approve: true),
      signer: signer,
    );

    final reply = await serve(
      service,
      frame(data: userauthBlob('alice', 'publickey')),
      authorized: false,
    );

    expect(reply.kind, ApplicationFrameKind.error);
    expect(signer.calls, 0);
  });

  /// A build that forgets to wire the screen signs nothing, rather than
  /// falling back to a bare Keystore prompt with no context in it.
  test('a service with no approval attached signs nothing', () async {
    final signer = _Signer();
    final service = SshService(signer: signer);

    final reply = await serve(
      service,
      frame(data: userauthBlob('alice', 'publickey')),
    );

    expect(reply.kind, ApplicationFrameKind.error);
    expect(signer.calls, 0);
  });

  test(
    'a signature of the wrong length is refused rather than sent on',
    () async {
      final service = SshService(
        approval: _Recording(approve: true),
        signer: _Signer(length: 63),
      );

      final reply = await serve(
        service,
        frame(data: userauthBlob('alice', 'publickey')),
      );

      expect(reply.kind, ApplicationFrameKind.error);
    },
  );

  /// A refused biometric, a missing key and an invalidated one are one answer
  /// on the wire — the same taxonomy the vault uses.
  test('a keystore failure is the same refusal as a declined tap', () async {
    final declined = await serve(
      SshService(approval: _Recording(approve: false), signer: _Signer()),
      frame(data: userauthBlob('alice', 'publickey')),
    );
    final failed = await serve(
      SshService(
        approval: _Recording(approve: true),
        signer: _Signer(throws: true),
      ),
      frame(data: userauthBlob('alice', 'publickey')),
    );

    expect(failed.payload, declined.payload);
  });

  test('a frame for another session is refused outright', () async {
    final service = SshService(
      approval: _Recording(approve: true),
      signer: _Signer(),
    );

    expect(
      () => service.handle(
        frame(data: userauthBlob('alice', 'publickey')),
        sessionBinding: Uint8List(32),
        authorized: true,
        now: now,
      ),
      throwsFormatException,
    );
  });

  test('a malformed payload is an invalid request, not a refusal', () async {
    final service = SshService(
      approval: _Recording(approve: true),
      signer: _Signer(),
    );
    final bad = ApplicationFrame(
      protocolVersion: 1,
      kind: ApplicationFrameKind.request,
      requestId: 'request-1',
      sessionBinding: binding,
      operation: sshSignOperation,
      issuedAt: now,
      expiresAt: now.add(const Duration(minutes: 1)),
      payload: Uint8List.fromList([1, 2, 3]),
    ).encode();

    final reply = await serve(service, bad);

    expect(
      ApplicationErrorCode.decode(reply.payload),
      ApplicationErrorCode.invalidRequest,
    );
  });

  test('a tap that lands after the request expired signs nothing', () async {
    // A signature opens a session that outlives the tap, so one made against a
    // request the desktop already stopped accepting is worse than useless --
    // and producing it costs the owner a fingerprint.
    var moment = now;
    final signer = _Signer();
    final service = SshService(
      approval: _SlowApproval(
        () => moment = now.add(const Duration(minutes: 2)),
      ),
      signer: signer,
      clock: () => moment,
    );

    final reply = ApplicationFrame.decode(
      await service.handle(
        frame(data: userauthBlob('alice', 'publickey')),
        sessionBinding: binding,
        authorized: true,
      ),
    );

    expect(reply.kind, ApplicationFrameKind.error);
    expect(signer.calls, 0, reason: 'no fingerprint for a dead request');
  });
}

/// Someone who taps yes, long after being asked.
class _SlowApproval implements SshApproval {
  _SlowApproval(this.onAsked);

  final void Function() onAsked;

  @override
  Future<bool> confirm(SshApprovalRequest request) async {
    onAsked();
    return true;
  }
}

class _Recording implements SshApproval {
  _Recording({required this.approve});

  final bool approve;
  final List<SshApprovalRequest> seen = [];

  @override
  Future<bool> confirm(SshApprovalRequest request) async {
    seen.add(request);
    return approve;
  }
}

class _Signer implements SshSigner {
  _Signer({this.length = sshSignatureLength, this.throws = false});

  final int length;
  final bool throws;
  int calls = 0;

  @override
  Future<Uint8List?> sign(Uint8List data, {required String prompt}) async {
    calls++;
    if (throws) throw PlatformException(code: 'authentication_cancelled');
    return Uint8List(length);
  }
}
