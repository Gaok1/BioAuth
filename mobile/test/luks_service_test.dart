import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/luks/luks_service.dart';
import 'package:phone_auth/core/protocol/application_frame.dart';
import 'package:phone_auth/core/protocol/luks_payloads.dart';

class FakeLuksGuardian implements LuksKeyGuardian {
  bool refuse = false;
  int wraps = 0;

  @override
  Future<Uint8List> wrap({
    required Uint8List binding,
    required String credentialId,
    required Uint8List diskKey,
    required String volumeName,
    required String verifierName,
  }) async {
    if (refuse) throw StateError('cancelled');
    wraps++;
    return Uint8List.fromList(diskKey.map((byte) => byte ^ 0xa5).toList());
  }

  @override
  Future<Uint8List> unwrap({
    required Uint8List binding,
    required String credentialId,
    required Uint8List wrapper,
    required String volumeName,
    required String verifierName,
  }) async {
    if (refuse) throw StateError('cancelled');
    return Uint8List.fromList(wrapper.map((byte) => byte ^ 0xa5).toList());
  }
}

final sessionBinding = Uint8List.fromList(List<int>.filled(32, 3));
final volumeBinding = Uint8List.fromList(List<int>.generate(32, (i) => i));
final now = DateTime.fromMillisecondsSinceEpoch(1787745600000, isUtc: true);

Uint8List request(String operation, Uint8List payload, {Uint8List? binding}) =>
    ApplicationFrame(
      protocolVersion: 1,
      kind: ApplicationFrameKind.request,
      requestId: 'request-1',
      sessionBinding: binding ?? sessionBinding,
      operation: operation,
      issuedAt: now,
      expiresAt: now.add(const Duration(minutes: 1)),
      payload: payload,
    ).encode();

Uint8List enrollPayload() => LuksEnrollRequest(
  verifierName: 'Workstation',
  volumeName: 'cryptroot',
  volumeBinding: volumeBinding,
  diskKey: List<int>.filled(32, 7),
).encode();

Uint8List unlockPayload({String credentialId = 'disk-cred-1'}) =>
    LuksUnlockRequest(
      verifierName: 'Workstation',
      volumeName: 'cryptroot',
      volumeBinding: volumeBinding,
      credentialId: credentialId,
      wrapper: List<int>.filled(32, 7 ^ 0xa5),
    ).encode();

void main() {
  late FakeLuksGuardian guardian;
  late LuksService service;

  setUp(() {
    guardian = FakeLuksGuardian();
    service = LuksService(guardian: guardian, credentialId: 'disk-cred-1');
  });

  test('enrollment returns a wrapper bound to the phone credential', () async {
    final answer = ApplicationFrame.decode(
      await service.handle(
        request(luksEnrollOperation, enrollPayload()),
        sessionBinding: sessionBinding,
        now: now,
      ),
    );
    final payload = LuksEnrollResponse.decode(answer.payload);
    expect(answer.kind, ApplicationFrameKind.response);
    expect(payload.credentialId, 'disk-cred-1');
    expect(payload.wrapper, List<int>.filled(32, 7 ^ 0xa5));
  });

  test('unlock returns the exact random disk key', () async {
    final answer = ApplicationFrame.decode(
      await service.handle(
        request(luksUnlockOperation, unlockPayload()),
        sessionBinding: sessionBinding,
        now: now,
      ),
    );
    expect(
      LuksUnlockResponse.decode(answer.payload).diskKey,
      List.filled(32, 7),
    );
  });

  test(
    'enrollment retry reuses the result without another biometric',
    () async {
      for (final binding in [
        sessionBinding,
        Uint8List.fromList(List<int>.filled(32, 4)),
      ]) {
        await service.handle(
          request(luksEnrollOperation, enrollPayload(), binding: binding),
          sessionBinding: binding,
          now: now,
        );
      }
      expect(guardian.wraps, 1);
    },
  );

  test(
    'wrong credential, refusal and unknown operation disclose no key',
    () async {
      for (final input in [
        request(luksUnlockOperation, unlockPayload(credentialId: 'other')),
        request('vault.list', Uint8List(0)),
      ]) {
        final answer = ApplicationFrame.decode(
          await service.handle(input, sessionBinding: sessionBinding, now: now),
        );
        expect(answer.kind, ApplicationFrameKind.error);
        expect(answer.payload, isEmpty);
      }
      guardian.refuse = true;
      final refused = ApplicationFrame.decode(
        await service.handle(
          request(luksUnlockOperation, unlockPayload()),
          sessionBinding: sessionBinding,
          now: now,
        ),
      );
      expect(refused.kind, ApplicationFrameKind.error);
      expect(refused.payload, isEmpty);
    },
  );

  test('foreign or expired session frame is not answered', () async {
    final foreign = Uint8List.fromList(List<int>.filled(32, 9));
    expect(
      () => service.handle(
        request(luksUnlockOperation, unlockPayload(), binding: foreign),
        sessionBinding: sessionBinding,
        now: now,
      ),
      throwsFormatException,
    );
    expect(
      () => service.handle(
        request(luksUnlockOperation, unlockPayload()),
        sessionBinding: sessionBinding,
        now: now.add(const Duration(minutes: 2)),
      ),
      throwsFormatException,
    );
  });
}
