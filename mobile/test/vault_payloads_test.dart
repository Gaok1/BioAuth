import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/protocol/vault_payloads.dart';

/// Vetor compartilhado com `phone-auth-protocol::vault`. Se um dos lados mudar
/// o formato sem o outro, este teste é o que quebra primeiro.
const String _fetchResponseVector =
    '8401666974656d2d3103781c636f727265637420686f7273652062617474657279'
    '20737461706c65';

/// Mesmo vetor, agora para o pedido de gravação. O `create` é o payload onde
/// discordar é pior: um campo lido no offset errado guarda a senha com o nome
/// de outra entrada. Fixado em `phone-auth-protocol::vault`.
const String _createRequestVector =
    '87016b576f726b73746174696f6e016e5265636f7665727920636f64657360'
    '6069313131312d32323232';

String _hex(Uint8List bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

Uint8List _unhex(String value) => Uint8List.fromList([
  for (var index = 0; index < value.length; index += 2)
    int.parse(value.substring(index, index + 2), radix: 16),
]);

VaultItemSummary _summary() => VaultItemSummary(
  id: 'item-1',
  revision: 3,
  kind: VaultItemKind.login,
  name: 'GitHub',
  username: 'luis',
  uri: 'https://github.com',
  updatedAtMs: 1700000000000,
);

void main() {
  test('a resposta de fetch bate byte a byte com o vetor do Rust', () {
    final response = VaultFetchResponse(
      itemId: 'item-1',
      revision: 3,
      secret: 'correct horse battery staple',
    );
    expect(_hex(response.encode()), _fetchResponseVector);

    final decoded = VaultFetchResponse.decode(_unhex(_fetchResponseVector));
    expect(decoded.itemId, 'item-1');
    expect(decoded.revision, 3);
    expect(decoded.secret, 'correct horse battery staple');
  });

  test('todo payload do cofre faz round trip', () {
    final listRequest = VaultListRequest(verifierName: 'Workstation');
    expect(
      VaultListRequest.decode(listRequest.encode()).verifierName,
      'Workstation',
    );

    final listResponse = VaultListResponse(
      items: [_summary()],
      nextCursor: 'page-2',
    );
    final decodedList = VaultListResponse.decode(listResponse.encode());
    expect(decodedList.items, [_summary()]);
    expect(decodedList.nextCursor, 'page-2');

    final fetchRequest = VaultFetchRequest(
      verifierName: 'Workstation',
      itemId: 'item-1',
    );
    expect(VaultFetchRequest.decode(fetchRequest.encode()).itemId, 'item-1');

    final create = VaultCreateRequest(
      verifierName: 'Workstation',
      kind: VaultItemKind.note,
      name: 'Recovery codes',
      secret: '1111-2222',
    );
    expect(_hex(create.encode()), _createRequestVector);
    final decodedCreate = VaultCreateRequest.decode(create.encode());
    expect(decodedCreate.kind, VaultItemKind.note);
    expect(decodedCreate.username, '');
    expect(decodedCreate.secret, '1111-2222');

    final update = VaultUpdateRequest(
      verifierName: 'Workstation',
      itemId: 'item-1',
      expectedRevision: 3,
      kind: VaultItemKind.login,
      name: 'GitHub',
      username: 'luis',
      uri: 'https://github.com',
      secret: 'new-password',
    );
    expect(VaultUpdateRequest.decode(update.encode()).expectedRevision, 3);

    final write = VaultWriteResponse(itemId: 'item-1', revision: 4);
    expect(VaultWriteResponse.decode(write.encode()), write);

    final delete = VaultDeleteRequest(
      verifierName: 'Workstation',
      itemId: 'item-1',
      expectedRevision: 4,
    );
    expect(VaultDeleteRequest.decode(delete.encode()).expectedRevision, 4);

    final deleted = VaultDeleteResponse(itemId: 'item-1');
    expect(VaultDeleteResponse.decode(deleted.encode()).itemId, 'item-1');
  });

  test('uma página vazia é resposta legítima', () {
    final empty = VaultListResponse(items: []);
    final decoded = VaultListResponse.decode(empty.encode());
    expect(decoded.items, isEmpty);
    expect(decoded.nextCursor, '');
  });

  test('campos opcionais podem ser vazios, mas o nome não', () {
    expect(
      () => VaultItemSummary(
        id: 'item-1',
        revision: 1,
        kind: VaultItemKind.note,
        name: '   ',
        username: '',
        uri: '',
        updatedAtMs: 0,
      ).validate(),
      throwsFormatException,
    );

    VaultItemSummary(
      id: 'item-1',
      revision: 1,
      kind: VaultItemKind.note,
      name: 'Nota',
      username: '',
      uri: '',
      updatedAtMs: 0,
    ).validate();
  });

  test('revisão zero é recusada', () {
    expect(
      () => VaultWriteResponse(itemId: 'item-1', revision: 0).encode(),
      throwsFormatException,
    );
    expect(
      () => VaultDeleteRequest(
        verifierName: 'Workstation',
        itemId: 'item-1',
        expectedRevision: 0,
      ).encode(),
      throwsFormatException,
    );
  });

  test('prefixo de tamanho mentiroso não chega a alocar', () {
    // Montado à mão de propósito: o writer nunca produziria esta contagem.
    // array(3), schema 1, array(2^32-1).
    final hostile = Uint8List.fromList([
      0x83,
      0x01,
      0x9a,
      0xff,
      0xff,
      0xff,
      0xff,
    ]);
    expect(() => VaultListResponse.decode(hostile), throwsFormatException);
  });

  test('schema desconhecido falha fechado', () {
    // array(2), schema 2, "item-1"
    final future = Uint8List.fromList([
      0x82,
      0x02,
      0x66,
      ...'item-1'.codeUnits,
    ]);
    expect(() => VaultDeleteResponse.decode(future), throwsFormatException);
  });

  test('tipo de item desconhecido falha fechado', () {
    // Um a mais que o último tipo conhecido. Escrito assim para que
    // acrescentar um tipo não faça este teste passar a exercitar um valor
    // válido — que é exatamente o que aconteceu quando `totp` entrou como 2.
    expect(
      () => VaultItemKind.fromWire(VaultItemKind.values.length),
      throwsFormatException,
    );
    expect(() => VaultItemKind.fromWire(255), throwsFormatException);
  });

  test('o tipo totp atravessa o fio', () {
    expect(VaultItemKind.fromWire(2), VaultItemKind.totp);
    expect(VaultItemKind.totp.wire, 2);
  });

  test('segredo vazio é recusado', () {
    expect(
      () => VaultFetchResponse(
        itemId: 'item-1',
        revision: 1,
        secret: '',
      ).encode(),
      throwsFormatException,
    );
  });
}
