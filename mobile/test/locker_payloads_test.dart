import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/protocol/application_frame.dart';
import 'package:phone_auth/core/protocol/locker_payloads.dart';

/// Vetor compartilhado com `phone-auth-protocol::locker`. Se um dos lados mudar
/// o formato sem o outro, este teste é o que quebra primeiro.
const String _wrapRequestVector =
    '86016b576f726b73746174696f6e6e7461782072657475726e2e7064661a000186a0'
    '5820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
    '58200707070707070707070707070707070707070707070707070707070707070707';

String _hex(Uint8List bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

Uint8List _unhex(String value) => Uint8List.fromList([
  for (var index = 0; index < value.length; index += 2)
    int.parse(value.substring(index, index + 2), radix: 16),
]);

LockerWrapRequest _wrapRequest() => LockerWrapRequest(
  verifierName: 'Workstation',
  fileName: 'tax return.pdf',
  plaintextLength: 100000,
  containerBinding: List<int>.generate(32, (index) => index),
  dataKey: List<int>.filled(32, 7),
);

LockerUnwrapRequest _unwrapRequest() => LockerUnwrapRequest(
  verifierName: 'Workstation',
  fileName: 'tax return.pdf.balock',
  plaintextLength: 100000,
  containerBinding: List<int>.generate(32, (index) => index),
  credentialId: 'locker-cred-1',
  wrapper: List<int>.filled(60, 9),
);

void main() {
  test('o pedido de embrulho bate byte a byte com o vetor do Rust', () {
    expect(_hex(_wrapRequest().encode()), _wrapRequestVector);

    final decoded = LockerWrapRequest.decode(_unhex(_wrapRequestVector));
    expect(decoded.verifierName, 'Workstation');
    expect(decoded.fileName, 'tax return.pdf');
    expect(decoded.plaintextLength, 100000);
    expect(decoded.dataKey.length, lockerDataKeyLength);
  });

  test('todos os payloads sobrevivem a uma ida e volta', () {
    final response = LockerWrapResponse(
      credentialId: 'locker-cred-1',
      wrapper: List<int>.filled(60, 3),
    );
    expect(
      _hex(LockerWrapResponse.decode(response.encode()).wrapper),
      _hex(response.wrapper),
    );

    final unwrap = LockerUnwrapRequest.decode(_unwrapRequest().encode());
    expect(unwrap.credentialId, 'locker-cred-1');
    expect(unwrap.fileName, 'tax return.pdf.balock');

    final key = LockerUnwrapResponse(dataKey: List<int>.filled(32, 5));
    expect(
      _hex(LockerUnwrapResponse.decode(key.encode()).dataKey),
      _hex(key.dataKey),
    );
  });

  test('um payload não desliza para o lugar de outro', () {
    // As três operações compartilham a sessão e diferem só pela operação, então
    // decodificar um pedido como outro precisa falhar.
    expect(
      () => LockerWrapRequest.decode(_unwrapRequest().encode()),
      throwsFormatException,
    );
    expect(
      () => LockerUnwrapRequest.decode(_wrapRequest().encode()),
      throwsFormatException,
    );
    expect(
      () => LockerUnwrapResponse.decode(_wrapRequest().encode()),
      throwsFormatException,
    );
  });

  test('chave e wrapper fora do tamanho são recusados', () {
    for (final length in [0, 31, 33]) {
      expect(
        () =>
            LockerUnwrapResponse(dataKey: List<int>.filled(length, 1)).encode(),
        throwsFormatException,
        reason: 'chave de $length bytes',
      );
    }
    for (final length in [0, lockerMaxWrapperBytes + 1]) {
      expect(
        () => LockerWrapResponse(
          credentialId: 'cred',
          wrapper: List<int>.filled(length, 1),
        ).encode(),
        throwsFormatException,
        reason: 'wrapper de $length bytes',
      );
    }
  });

  test('schema desconhecido e bytes sobrando falham fechado', () {
    final encoded = _wrapRequest().encode();

    final foreignSchema = Uint8List.fromList(encoded);
    foreignSchema[1] = 0x02;
    expect(
      () => LockerWrapRequest.decode(foreignSchema),
      throwsFormatException,
    );

    expect(
      () => LockerWrapRequest.decode(Uint8List.fromList([...encoded, 0x00])),
      throwsFormatException,
    );
  });

  test('o envelope aceita as três operações do locker', () {
    for (final operation in [
      lockerCreateOperation,
      lockerUnlockOperation,
      lockerRekeyOperation,
    ]) {
      final frame = ApplicationFrame(
        protocolVersion: 1,
        kind: ApplicationFrameKind.request,
        requestId: 'request-1',
        sessionBinding: List<int>.filled(32, 0),
        operation: operation,
        issuedAt: DateTime.fromMillisecondsSinceEpoch(
          1787745600000,
          isUtc: true,
        ),
        expiresAt: DateTime.fromMillisecondsSinceEpoch(
          1787745660000,
          isUtc: true,
        ),
        payload: _wrapRequest().encode(),
      );
      expect(() => frame.encode(), returnsNormally, reason: operation);
    }
  });
}
