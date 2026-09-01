import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/permissions/permission_service.dart';
import 'package:phone_auth/core/permissions/permission_store.dart';
import 'package:phone_auth/core/protocol/application_frame.dart';
import 'package:phone_auth/core/protocol/permission_payloads.dart';

class _MemoryStore implements PermissionStore {
  final Map<String, PermissionSet> _entries = {};
  int writes = 0;

  @override
  Future<PermissionSet> read(String verifierId, String credentialId) async =>
      _entries['$verifierId $credentialId'] ?? PermissionSet.never;

  @override
  Future<void> write(
    String verifierId,
    String credentialId,
    PermissionSet set,
  ) async {
    writes++;
    _entries['$verifierId $credentialId'] = set;
  }

  @override
  Future<Map<String, PermissionSet>> readAll(String verifierId) async => {
    for (final entry in _entries.entries)
      if (entry.key.startsWith('$verifierId '))
        entry.key.substring(verifierId.length + 1): entry.value,
  };

  @override
  Future<void> forget(String verifierId) async =>
      _entries.removeWhere((key, _) => key.startsWith('$verifierId '));
}

final _binding = Uint8List.fromList(List<int>.generate(32, (i) => i));

Permission grant(String service) => Permission(
  service: service,
  action: permissionWildcard,
  resource: permissionWildcard,
  user: 'gaok1',
);

Uint8List requestFrame(PermissionSyncRequest request) => ApplicationFrame(
  protocolVersion: 1,
  kind: ApplicationFrameKind.request,
  requestId: 'req-permissions-1',
  sessionBinding: _binding,
  operation: permissionsSyncOperation,
  issuedAt: DateTime.utc(2026, 9, 1, 12),
  expiresAt: DateTime.utc(2026, 9, 1, 12, 2),
  payload: request.encode(),
).encode();

DateTime inWindow() => DateTime.utc(2026, 9, 1, 12, 1);

void main() {
  PermissionService serviceWith(_MemoryStore store) => PermissionService(
    store: store,
    verifierId: 'desk-1',
    credentialId: 'cred-1',
    clock: inWindow,
  );

  Future<PermissionSyncResponse> ask(
    PermissionService service,
    PermissionSyncRequest request,
  ) async {
    final reply = ApplicationFrame.decode(
      await service.handle(requestFrame(request), sessionBinding: _binding),
    );
    expect(
      reply.kind,
      ApplicationFrameKind.response,
      reason: 'a sincronização foi recusada',
    );
    return PermissionSyncResponse.decode(reply.payload);
  }

  /// O caso que **todo pareamento existente hoje** encontra na primeira
  /// sincronização, e o único em que esta feature poderia causar dano de
  /// verdade: o computador tem concessões e revisão zero, este celular nunca
  /// teve permissão nenhuma. Se o zero duplo caísse no desempate, este lado
  /// venceria com a lista vazia, o computador guardaria, e sincronizar um
  /// pareamento em uso o revogaria — sem ninguém ter pedido nada.
  test(
    'a primeira sincronização devolve o que o computador já concedia',
    () async {
      final store = _MemoryStore();
      final answer = await ask(
        serviceWith(store),
        PermissionSyncRequest(
          verifierName: 'Workstation',
          revision: 0,
          permissions: [grant('sudo'), grant('login')],
        ),
      );

      expect(answer.permissions, [grant('sudo'), grant('login')]);
      expect(answer.revision, 0);
    },
  );

  /// Editado aqui e não lá: este lado vence e o computador adota.
  test('uma edição no celular vence uma revisão mais antiga do PC', () async {
    final store = _MemoryStore();
    await store.write(
      'desk-1',
      'cred-1',
      const PermissionSet(
        revision: 0,
        permissions: [],
      ).edited([grant('vault')]),
    );

    final answer = await ask(
      serviceWith(store),
      PermissionSyncRequest(
        verifierName: 'Workstation',
        revision: 0,
        permissions: [grant('sudo')],
      ),
    );

    expect(answer.permissions, [grant('vault')]);
    expect(answer.revision, 1);
  });

  /// E o contrário: editado lá e não aqui, este lado adota e grava.
  test('uma edição no PC é adotada e guardada', () async {
    final store = _MemoryStore();
    await store.write(
      'desk-1',
      'cred-1',
      const PermissionSet(revision: 1, permissions: []),
    );

    final answer = await ask(
      serviceWith(store),
      PermissionSyncRequest(
        verifierName: 'Workstation',
        revision: 4,
        permissions: [grant('sudo')],
      ),
    );

    expect(answer.revision, 4);
    expect(answer.permissions, [grant('sudo')]);
    expect(await store.read('desk-1', 'cred-1'), isA<PermissionSet>());
    expect((await store.read('desk-1', 'cred-1')).permissions, [grant('sudo')]);
  });

  /// Uma sessão ociosa sincroniza a cada conexão. Regravar o que já está no
  /// disco toda vez é uma escrita por sessão para dizer "continua igual".
  test('nada é gravado quando este lado já estava certo', () async {
    final store = _MemoryStore();
    await store.write(
      'desk-1',
      'cred-1',
      const PermissionSet(revision: 5, permissions: []),
    );
    store.writes = 0;

    await ask(
      serviceWith(store),
      PermissionSyncRequest(
        verifierName: 'Workstation',
        revision: 2,
        permissions: [grant('sudo')],
      ),
    );

    expect(store.writes, 0);
  });

  /// Um frame de outra sessão não é um pedido malformado, é um pedido que não
  /// é desta conversa. Recusado antes de qualquer leitura do disco.
  test('um frame de outra sessão é recusado', () async {
    final store = _MemoryStore();
    expect(
      () => serviceWith(store).handle(
        requestFrame(
          const PermissionSyncRequest(
            verifierName: 'Workstation',
            revision: 1,
            permissions: [],
          ),
        ),
        sessionBinding: Uint8List(32),
      ),
      throwsFormatException,
    );
  });

  /// O envelope tem uma lista fechada de prefixos, e ela é a razão de um
  /// namespace novo ser uma mudança em dois arquivos. Esquecer o segundo é
  /// silencioso de um jeito que merece teste: todo payload continua indo e
  /// voltando, todo teste de unidade dos dois lados continua passando, e a
  /// operação é recusada pelo envelope antes de alguém olhar o conteúdo. Foi
  /// exatamente assim que `permissions.sync` se comportou na primeira vez que
  /// foi ligado ponta a ponta.
  ///
  /// `desktop/crates/phone-auth-protocol/src/application.rs` tem a mesma lista.
  test('todo namespace com handler passa pelo envelope', () {
    for (final operation in [
      'vault.list',
      'locker.unlock',
      'luks.enroll',
      'ssh.sign',
      permissionsSyncOperation,
    ]) {
      expect(
        () => ApplicationFrame(
          protocolVersion: 1,
          kind: ApplicationFrameKind.request,
          requestId: 'req-1',
          sessionBinding: _binding,
          operation: operation,
          issuedAt: DateTime.utc(2026, 9, 1, 12),
          expiresAt: DateTime.utc(2026, 9, 1, 12, 2),
          payload: Uint8List(0),
        ).encode(),
        returnsNormally,
        reason: '`$operation` tem handler e nao passa pelo envelope',
      );
    }
  });

  test('um payload ilegível vira erro e não uma concessão', () async {
    final store = _MemoryStore();
    final frame = ApplicationFrame(
      protocolVersion: 1,
      kind: ApplicationFrameKind.request,
      requestId: 'req-permissions-1',
      sessionBinding: _binding,
      operation: permissionsSyncOperation,
      issuedAt: DateTime.utc(2026, 9, 1, 12),
      expiresAt: DateTime.utc(2026, 9, 1, 12, 2),
      payload: Uint8List.fromList([9, 9, 9]),
    ).encode();

    final reply = ApplicationFrame.decode(
      await serviceWith(store).handle(frame, sessionBinding: _binding),
    );

    expect(reply.kind, ApplicationFrameKind.error);
    expect(store.writes, 0);
  });
}
