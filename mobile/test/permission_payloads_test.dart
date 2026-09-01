import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/protocol/permission_payloads.dart';

Permission grant(String service) => Permission(
  service: service,
  action: permissionWildcard,
  resource: permissionWildcard,
  user: 'gaok1',
);

void main() {
  test('uma requisição sobrevive à ida e volta', () {
    final request = PermissionSyncRequest(
      verifierName: 'Workstation',
      revision: 7,
      permissions: [grant('sudo'), grant('login')],
    );

    final decoded = PermissionSyncRequest.decode(request.encode());

    expect(decoded.verifierName, 'Workstation');
    expect(decoded.revision, 7);
    expect(decoded.permissions, [grant('sudo'), grant('login')]);
  });

  test('uma resposta sobrevive à ida e volta', () {
    final response = PermissionSyncResponse(
      revision: 9,
      permissions: [grant('vault')],
    );

    final decoded = PermissionSyncResponse.decode(response.encode());

    expect(decoded.revision, 9);
    expect(decoded.permissions, [grant('vault')]);
  });

  /// Conjunto vazio é uma resposta legítima — é a que uma revogação produz — e
  /// não pode ser confundido com payload malformado.
  test('não conceder nada é um conjunto como outro qualquer', () {
    final decoded = PermissionSyncResponse.decode(
      const PermissionSyncResponse(revision: 3, permissions: []).encode(),
    );

    expect(decoded.permissions, isEmpty);
    expect(decoded.revision, 3);
  });

  test('a revisão maior vence de qualquer assento', () {
    expect(reconcile(5, 4, phoneWinsTies: true), PermissionWinner.mine);
    expect(reconcile(5, 4, phoneWinsTies: false), PermissionWinner.mine);
    expect(reconcile(4, 5, phoneWinsTies: true), PermissionWinner.theirs);
    expect(reconcile(4, 5, phoneWinsTies: false), PermissionWinner.theirs);
  });

  /// Os dois assentos têm que chegar à mesma conclusão sobre o mesmo par de
  /// revisões, senão sincronizar deixa os lados mais distantes do que achou.
  test('o empate fica com o celular, visto dos dois assentos', () {
    expect(reconcile(6, 6, phoneWinsTies: true), PermissionWinner.mine);
    expect(reconcile(6, 6, phoneWinsTies: false), PermissionWinner.theirs);
  });

  test('um lado nunca editado perde', () {
    expect(reconcile(0, 1, phoneWinsTies: false), PermissionWinner.theirs);
    expect(reconcile(0, 1, phoneWinsTies: true), PermissionWinner.theirs);
    expect(reconcile(1, 0, phoneWinsTies: false), PermissionWinner.mine);
    expect(reconcile(1, 0, phoneWinsTies: true), PermissionWinner.mine);
  });

  /// A primeira sincronização de um pareamento anterior a esta feature, que é
  /// todo pareamento que existe hoje. Os dois mandam zero e o desempate não
  /// pode rodar: o zero do computador quer dizer "concedido pela bandeja e
  /// nunca mexido", o do celular quer dizer "nunca teve permissão nenhuma".
  /// Tratados como reivindicações iguais, o celular responde com o conjunto
  /// vazio, o computador guarda, e sincronizar um pareamento em uso o revoga.
  test('a primeira sincronização preserva o que o computador já concedia', () {
    expect(reconcile(0, 0, phoneWinsTies: true), PermissionWinner.theirs);
    expect(reconcile(0, 0, phoneWinsTies: false), PermissionWinner.mine);
  });

  test('um conjunto maior que o limite é recusado antes de alocar', () {
    final oversized = PermissionSyncResponse(
      revision: 1,
      permissions: List.generate(maxPermissions + 1, (_) => grant('sudo')),
    );

    expect(oversized.encode, throwsFormatException);
  });

  /// Vazio do lado que aplica não é coringa, é um valor que nada casa.
  test('uma concessão com campo vazio é recusada', () {
    for (final empty in ['service', 'action', 'resource', 'user']) {
      final permission = Permission(
        service: empty == 'service' ? '' : 'sudo',
        action: empty == 'action' ? '' : permissionWildcard,
        resource: empty == 'resource' ? '' : permissionWildcard,
        user: empty == 'user' ? '' : 'gaok1',
      );
      expect(
        PermissionSyncResponse(revision: 1, permissions: [permission]).encode,
        throwsFormatException,
        reason: 'um `$empty` vazio passou',
      );
    }
  });

  test('um payload não canônico é recusado', () {
    final payload = const PermissionSyncResponse(
      revision: 1,
      permissions: [],
    ).encode();

    expect(
      () => PermissionSyncResponse.decode(Uint8List.fromList([...payload, 0])),
      throwsFormatException,
    );
  });

  /// O teste que faz esta feature ser uma só e não duas.
  ///
  /// Os dois lados codificam o mesmo significado, em linguagens diferentes,
  /// mantidos por mãos diferentes. Se um deles ordenar um campo de outro jeito,
  /// ou escrever um inteiro num tamanho diferente, tudo continua compilando e
  /// tudo continua passando nos testes de ida e volta de cada lado — e o par
  /// só descobre em campo, como "o celular respondeu uma requisição diferente".
  ///
  /// Os bytes abaixo saíram de `phone_auth_protocol::permissions` em Rust. Não
  /// são um formato inventado aqui: são o formato, e este teste é o contrato.
  test('os bytes batem com os que o computador escreve', () {
    const requestFromRust =
        '84016b576f726b73746174696f6e078284647375646f612a612a6567616f6b31'
        '8465'
        '6c6f67696e66756e6c6f636b612a6567616f6b31';
    const responseFromRust = '8301098184657661756c746472656164612a6567616f6b31';

    final request = PermissionSyncRequest(
      verifierName: 'Workstation',
      revision: 7,
      permissions: [
        grant('sudo'),
        const Permission(
          service: 'login',
          action: 'unlock',
          resource: permissionWildcard,
          user: 'gaok1',
        ),
      ],
    );
    final response = PermissionSyncResponse(
      revision: 9,
      permissions: [
        const Permission(
          service: 'vault',
          action: 'read',
          resource: permissionWildcard,
          user: 'gaok1',
        ),
      ],
    );

    expect(_hex(request.encode()), requestFromRust);
    expect(_hex(response.encode()), responseFromRust);

    // E de volta: o que o computador manda tem que decodificar aqui.
    final decoded = PermissionSyncRequest.decode(_bytes(requestFromRust));
    expect(decoded.verifierName, 'Workstation');
    expect(decoded.revision, 7);
    expect(decoded.permissions.first.service, 'sudo');
  });

  test('um payload de outro schema é recusado', () {
    final payload = const PermissionSyncResponse(
      revision: 1,
      permissions: [],
    ).encode();
    // O schema é o segundo item do array; trocá-lo é o que um par de outra
    // versão manda.
    final wrong = Uint8List.fromList(payload);
    wrong[1] = permissionsSchema + 1;

    expect(() => PermissionSyncResponse.decode(wrong), throwsFormatException);
  });
}

String _hex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

Uint8List _bytes(String hex) => Uint8List.fromList([
  for (var i = 0; i < hex.length; i += 2)
    int.parse(hex.substring(i, i + 2), radix: 16),
]);
