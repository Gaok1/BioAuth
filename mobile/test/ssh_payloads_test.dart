/// The `ssh.sign` payloads, and the bytes they must share with Rust.
///
/// The vectors below are the same strings pinned in
/// `desktop/crates/phone-auth-protocol/tests/ssh_sign_payloads.rs`. Changing
/// one without the other is the bug they exist to catch: two encoders that
/// drift apart produce a phone that refuses every request from its own
/// desktop, with a message about a malformed payload.
library;

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/protocol/ssh_payloads.dart';

String _hex(Uint8List bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

Uint8List _unhex(String value) => Uint8List.fromList([
  for (var index = 0; index < value.length; index += 2)
    int.parse(value.substring(index, index + 2), radix: 16),
]);

/// Shared with the Rust suite, byte for byte.
const _signRequestVector =
    '8401674465736b746f706b5348413235363a6161616143010203';
const _signResponseVector =
    '82015840000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d'
    '1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f';

/// The blob RFC 4252 §7 defines, which is what a real client asks to sign.
Uint8List _userauthBlob(String user, String service, String method) {
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
  string(service.codeUnits);
  string(method.codeUnits);
  out.add(1);
  string('ecdsa-sha2-nistp256'.codeUnits);
  string('key-blob'.codeUnits);
  return Uint8List.fromList(out);
}

void main() {
  test('um pedido de assinatura reproduz os bytes do Rust', () {
    final request = SshSignRequest(
      verifierName: 'Desktop',
      destination: 'SHA256:aaaa',
      data: Uint8List.fromList([1, 2, 3]),
    );

    expect(_hex(request.encode()), _signRequestVector);

    final decoded = SshSignRequest.decode(_unhex(_signRequestVector));
    expect(decoded.verifierName, 'Desktop');
    expect(decoded.destination, 'SHA256:aaaa');
    expect(decoded.data, [1, 2, 3]);
  });

  test('uma resposta de assinatura reproduz os bytes do Rust', () {
    final response = SshSignResponse(
      signature: Uint8List.fromList(List<int>.generate(64, (index) => index)),
    );

    expect(_hex(response.encode()), _signResponseVector);
    expect(
      SshSignResponse.decode(_unhex(_signResponseVector)).signature,
      response.signature,
    );
  });

  test('assinatura de tamanho errado é recusada', () {
    for (final length in [0, 63, 65, 128]) {
      expect(
        () => SshSignResponse(signature: Uint8List(length)).encode(),
        throwsFormatException,
        reason: '$length bytes',
      );
    }
  });

  test('payload não canônico é recusado', () {
    final payload = _unhex(_signRequestVector);
    final extended = Uint8List.fromList([...payload, 0]);

    expect(() => SshSignRequest.decode(extended), throwsFormatException);
  });

  test('truncar em qualquer ponto é recusado', () {
    final payload = _unhex(_signRequestVector);

    for (var cut = 0; cut < payload.length; cut++) {
      expect(
        () => SshSignRequest.decode(Uint8List.sublistView(payload, 0, cut)),
        throwsA(anything),
        reason: 'truncado em $cut bytes foi aceito',
      );
    }
  });

  /// A propriedade de segurança inteira: o telefone lê o blob **ele mesmo** e
  /// não assina nada para o qual não consiga nomear uma conta. Sem isso um
  /// desktop comprometido tem um oráculo de assinatura cega.
  group('só um userauth publickey tem conta', () {
    test('um pedido bem formado é lido', () {
      final account = accountInRequest(
        _userauthBlob('alice', 'ssh-connection', 'publickey'),
      );

      expect(account?.user, 'alice');
      expect(account?.service, 'ssh-connection');
    });

    test('qualquer outra coisa não tem conta', () {
      for (final blob in [
        Uint8List(0),
        Uint8List.fromList('bytes arbitrários para assinar'.codeUnits),
        _userauthBlob('alice', 'ssh-connection', 'hostbased'),
        _userauthBlob('alice', 'ssh-connection', 'password'),
        // Conta vazia: um pedido que não nomeia ninguém não é mostrável.
        _userauthBlob('', 'ssh-connection', 'publickey'),
      ]) {
        expect(
          accountInRequest(blob),
          isNull,
          reason: 'leu uma conta de algo que não é userauth publickey',
        );
      }
    });

    /// Isto roda no telefone, sobre dados que o desktop escolheu. Nada aqui
    /// pode lançar: exceção aqui é telefone que quebra com um frame recebido.
    test('bytes arbitrários nunca produzem conta nem exceção', () {
      var state = 0xC0FFEE;
      for (var attempt = 0; attempt < 3000; attempt++) {
        final bytes = <int>[];
        for (var index = 0; index < state % 96; index++) {
          state = (state * 1664525 + 1013904223) & 0xffffffff;
          bytes.add((state >> 16) & 0xff);
        }
        expect(
          () => accountInRequest(Uint8List.fromList(bytes)),
          returnsNormally,
          reason: 'lançou na tentativa $attempt',
        );
      }
    });

    /// Um comprimento é um número que quem montou o blob escolheu. Declarar
    /// mais do que existe tem que falhar na leitura, não fatiar fora do fim.
    test('comprimento maior que o conteúdo não estoura', () {
      final blob = Uint8List.fromList([0xff, 0xff, 0xff, 0xff, 1, 2, 3]);

      expect(accountInRequest(blob), isNull);
    });
  });
}
