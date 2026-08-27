import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/protocol/cbor.dart';
import 'package:phone_auth/core/protocol/enrolment.dart';

void main() {
  Enrolment fixture({
    KeyKind keyKind = KeyKind.strongBox,
    CredentialPurpose purpose = CredentialPurpose.authorization,
  }) => Enrolment(
    deviceName: 'Pixel 8',
    credentialId: 'desktop-1-sudo-v1',
    publicKey: Uint8List.fromList(List.filled(91, 7)),
    keyKind: keyKind,
    purpose: purpose,
  );

  test('round-trips through the wire format', () {
    final decoded = Enrolment.decode(fixture().encode());

    expect(decoded.deviceName, 'Pixel 8');
    expect(decoded.credentialId, 'desktop-1-sudo-v1');
    expect(decoded.algorithm, publicKeyEcP256Spki);
    expect(decoded.publicKey, fixture().publicKey);
    expect(decoded.keyKind, KeyKind.strongBox);
    expect(decoded.purpose, CredentialPurpose.authorization);
  });

  test('wire values are pinned', () {
    // The desktop stores these as its own enums. A reordering here would
    // silently turn a software key into a StrongBox one.
    expect(KeyKind.strongBox.index, 0);
    expect(KeyKind.hardware.index, 1);
    expect(KeyKind.software.index, 2);
    expect(CredentialPurpose.authorization.index, 0);
    expect(CredentialPurpose.diskUnlock.index, 1);
  });

  test('every key kind and purpose round-trips', () {
    for (final kind in KeyKind.values) {
      for (final purpose in CredentialPurpose.values) {
        final decoded = Enrolment.decode(
          fixture(keyKind: kind, purpose: purpose).encode(),
        );
        expect(decoded.keyKind, kind);
        expect(decoded.purpose, purpose);
      }
    }
  });

  test('an unknown key kind is refused', () {
    final writer = CborWriter()
      ..array(9)
      ..uint(3)
      ..uint(1)
      ..text('Pixel 8')
      ..text('cred-1')
      ..text(publicKeyEcP256Spki)
      ..bytes(List.filled(91, 7))
      ..uint(9)
      ..uint(0)
      ..uint(0);

    expect(
      () => Enrolment.decode(writer.takeBytes()),
      throwsA(isA<EnrolmentException>()),
    );
  });

  test('a non-zero reserved field is refused', () {
    final writer = CborWriter()
      ..array(9)
      ..uint(3)
      ..uint(1)
      ..text('Pixel 8')
      ..text('cred-1')
      ..text(publicKeyEcP256Spki)
      ..bytes(List.filled(91, 7))
      ..uint(0)
      ..uint(0)
      ..uint(1);

    expect(
      () => Enrolment.decode(writer.takeBytes()),
      throwsA(isA<EnrolmentException>()),
    );
  });

  test('an empty public key or blank name is refused', () {
    expect(
      () => Enrolment(
        deviceName: 'Pixel 8',
        credentialId: 'cred-1',
        publicKey: Uint8List(0),
        keyKind: KeyKind.hardware,
        purpose: CredentialPurpose.authorization,
      ),
      throwsA(isA<EnrolmentException>()),
    );
    expect(
      () => Enrolment(
        deviceName: '   ',
        credentialId: 'cred-1',
        publicKey: Uint8List.fromList(List.filled(91, 7)),
        keyKind: KeyKind.hardware,
        purpose: CredentialPurpose.authorization,
      ),
      throwsA(isA<EnrolmentException>()),
    );
  });

  test('a frame of another message type is refused', () {
    final writer = CborWriter()
      ..array(9)
      ..uint(1) // an AuthRequest type in an enrolment-shaped frame
      ..uint(1)
      ..text('Pixel 8')
      ..text('cred-1')
      ..text(publicKeyEcP256Spki)
      ..bytes(List.filled(91, 7))
      ..uint(0)
      ..uint(0)
      ..uint(0);

    expect(
      () => Enrolment.decode(writer.takeBytes()),
      throwsA(isA<EnrolmentException>()),
    );
  });
}
