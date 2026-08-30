import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/protocol/luks_payloads.dart';

String hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main() {
  final unlock = LuksUnlockRequest(
    verifierName: 'Workstation',
    volumeName: 'cryptroot',
    volumeBinding: List.generate(32, (i) => i),
    credentialId: 'desktop-diskUnlock-v1',
    wrapper: Uint8List(60)..fillRange(0, 60, 9),
  );

  test('vetor de unlock é idêntico ao Rust', () {
    expect(
      hex(unlock.encode()),
      '86016b576f726b73746174696f6e696372797074726f6f745820000102030405'
      '060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f756465736b'
      '746f702d6469736b556e6c6f636b2d7631583c090909090909090909090909'
      '0909090909090909090909090909090909090909090909090909090909090909'
      '09090909090909090909090909090909',
    );
  });

  test('payloads validam tamanho, schema e forma canônica', () {
    expect(
      LuksUnlockRequest.decode(unlock.encode()).credentialId,
      'desktop-diskUnlock-v1',
    );
    final enroll = LuksEnrollRequest(
      verifierName: 'Workstation',
      volumeName: 'cryptroot',
      volumeBinding: Uint8List(32),
      diskKey: Uint8List(32),
    );
    expect(LuksEnrollRequest.decode(enroll.encode()).diskKey.length, 32);
    final response = LuksEnrollResponse(credentialId: 'disk-v1', wrapper: [1]);
    expect(LuksEnrollResponse.decode(response.encode()).wrapper, [1]);
    expect(
      LuksUnlockResponse.decode(
        LuksUnlockResponse(diskKey: Uint8List(32)).encode(),
      ).diskKey.length,
      32,
    );
    expect(
      () => LuksUnlockResponse(diskKey: Uint8List(31)).encode(),
      throwsFormatException,
    );
    final future = unlock.encode()..[1] = 2;
    expect(() => LuksUnlockRequest.decode(future), throwsFormatException);
  });
}
