import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/protocol/application_frame.dart';
import 'package:phone_auth/core/protocol/vault_payloads.dart' as wire;
import 'package:phone_auth/core/vault/vault_service.dart';
import 'package:phone_auth/features/vault/vault_store.dart' as store;

void main() {
  final binding = Uint8List.fromList(List<int>.generate(32, (i) => i));
  final now = DateTime.utc(2026, 8, 28, 18);

  Uint8List request(String operation, Uint8List payload) => ApplicationFrame(
    protocolVersion: 1,
    kind: ApplicationFrameKind.request,
    requestId: 'request-1',
    sessionBinding: binding,
    operation: operation,
    issuedAt: now,
    expiresAt: now.add(const Duration(minutes: 1)),
    payload: payload,
  ).encode();

  test('serves all five vault operations through the store', () async {
    final repository = _VaultStore();
    final service = VaultService(repository: repository);

    final listed = await service.handle(
      request(
        wire.vaultListOperation,
        wire.VaultListRequest(verifierName: 'Desktop').encode(),
      ),
      sessionBinding: binding,
      authorized: true,
      now: now,
    );
    expect(
      wire.VaultListResponse.decode(
        ApplicationFrame.decode(listed).payload,
      ).items.single.name,
      'Example',
    );

    final fetched = await service.handle(
      request(
        wire.vaultFetchOperation,
        wire.VaultFetchRequest(verifierName: 'Desktop', itemId: 'one').encode(),
      ),
      sessionBinding: binding,
      authorized: true,
      now: now,
    );
    expect(
      wire.VaultFetchResponse.decode(
        ApplicationFrame.decode(fetched).payload,
      ).secret,
      'hunter2',
    );

    final created = await service.handle(
      request(
        wire.vaultCreateOperation,
        wire.VaultCreateRequest(
          verifierName: 'Desktop',
          kind: wire.VaultItemKind.note,
          name: 'Note',
          username: '',
          uri: '',
          secret: 'body',
        ).encode(),
      ),
      sessionBinding: binding,
      authorized: true,
      now: now,
    );
    expect(
      wire.VaultWriteResponse.decode(
        ApplicationFrame.decode(created).payload,
      ).revision,
      1,
    );

    final updated = await service.handle(
      request(
        wire.vaultUpdateOperation,
        wire.VaultUpdateRequest(
          verifierName: 'Desktop',
          itemId: 'one',
          expectedRevision: 1,
          kind: wire.VaultItemKind.login,
          name: 'Updated',
          username: 'alice',
          uri: 'https://example.com',
          secret: 'new-secret',
        ).encode(),
      ),
      sessionBinding: binding,
      authorized: true,
      now: now,
    );
    expect(
      wire.VaultWriteResponse.decode(
        ApplicationFrame.decode(updated).payload,
      ).revision,
      2,
    );

    final deleted = await service.handle(
      request(
        wire.vaultDeleteOperation,
        wire.VaultDeleteRequest(
          verifierName: 'Desktop',
          itemId: 'one',
          expectedRevision: 2,
        ).encode(),
      ),
      sessionBinding: binding,
      authorized: true,
      now: now,
    );
    expect(
      wire.VaultDeleteResponse.decode(
        ApplicationFrame.decode(deleted).payload,
      ).itemId,
      'one',
    );
  });

  test(
    'missing, stale and unauthorized requests disclose the same error',
    () async {
      Future<Uint8List> refusal(String code, {bool authorized = true}) {
        final service = VaultService(repository: _FailingStore(code));
        return service.handle(
          request(
            wire.vaultFetchOperation,
            wire.VaultFetchRequest(
              verifierName: 'Desktop',
              itemId: 'secret-item',
            ).encode(),
          ),
          sessionBinding: binding,
          authorized: authorized,
          now: now,
        );
      }

      final missing = ApplicationFrame.decode(await refusal('not_found'));
      final stale = ApplicationFrame.decode(await refusal('revision_conflict'));
      final unauthorized = ApplicationFrame.decode(
        await refusal('not_found', authorized: false),
      );
      expect(missing.kind, ApplicationFrameKind.error);
      expect(missing.payload, stale.payload);
      expect(missing.payload, unauthorized.payload);
      expect(
        ApplicationErrorCode.decode(missing.payload),
        ApplicationErrorCode.rejected,
      );
    },
  );
}

class _VaultStore extends store.VaultStore {
  var revision = 1;

  @override
  Future<store.VaultPage> listPage([String? cursor]) async => store.VaultPage(
    items: [
      store.VaultItemSummary(
        id: 'one',
        revision: revision,
        kind: store.VaultItemKind.login,
        name: 'Example',
        username: 'alice',
        uri: 'https://example.com',
        updatedAt: DateTime.utc(2026),
      ),
    ],
  );

  @override
  Future<store.VaultSecret> fetch(String id) async =>
      store.VaultSecret(id: id, revision: revision, secret: 'hunter2');

  @override
  Future<store.VaultWrite> create(store.VaultItemInput item) async =>
      const store.VaultWrite(id: 'two', revision: 1);

  @override
  Future<store.VaultWrite> update(
    store.VaultItemSummary current,
    store.VaultItemInput item,
  ) async {
    revision++;
    return store.VaultWrite(id: current.id, revision: revision);
  }

  @override
  Future<void> delete(store.VaultItemSummary item) async {}
}

class _FailingStore extends _VaultStore {
  _FailingStore(this.code);
  final String code;

  @override
  Future<store.VaultSecret> fetch(String id) =>
      Future.error(PlatformException(code: code));
}
