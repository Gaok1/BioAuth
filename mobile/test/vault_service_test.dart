import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/protocol/application_frame.dart';
import 'package:phone_auth/core/protocol/vault_payloads.dart' as wire;
import 'package:phone_auth/core/vault/vault_approval.dart';
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
    final approval = _RecordingApproval(approve: true);
    final service = VaultService(repository: repository, approval: approval);

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
        final service = VaultService(
          repository: _FailingStore(code),
          approval: _RecordingApproval(approve: true),
        );
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

  test('the desktop flow costs one prompt per thing it asks for', () async {
    // List, pick, fetch is what the tray's vault panel does. Building the
    // sheet used to go to the store for the item's name, which is a second
    // Keystore prompt with nothing on screen explaining it -- raised seconds
    // after the listing had already decrypted that exact metadata, in order
    // to build the sheet that explains the third. `VaultListing` names that
    // as the thing the approval sheet exists to prevent.
    final repository = _ListCountingStore();
    final service = VaultService(
      repository: repository,
      approval: _RecordingApproval(approve: true),
    );

    await service.handle(
      request(
        wire.vaultListOperation,
        wire.VaultListRequest(verifierName: 'Desktop').encode(),
      ),
      sessionBinding: binding,
      authorized: true,
      now: now,
    );
    expect(repository.unlocks, 1, reason: 'the listing reads the vault once');

    await service.handle(
      request(
        wire.vaultFetchOperation,
        wire.VaultFetchRequest(verifierName: 'Desktop', itemId: 'one').encode(),
      ),
      sessionBinding: binding,
      authorized: true,
      now: now,
    );
    expect(
      repository.unlocks,
      2,
      reason:
          'the sheet is worded from the snapshot the listing just took, so '
          'the only further unlock is the fetch the user approved',
    );
  });

  test('a refused approval never reaches the store', () async {
    final repository = _CountingStore();
    final service = VaultService(
      repository: repository,
      approval: _RecordingApproval(approve: false),
    );

    for (final payload in [
      (
        wire.vaultFetchOperation,
        wire.VaultFetchRequest(verifierName: 'Desktop', itemId: 'one').encode(),
      ),
      (
        wire.vaultDeleteOperation,
        wire.VaultDeleteRequest(
          verifierName: 'Desktop',
          itemId: 'one',
          expectedRevision: 1,
        ).encode(),
      ),
    ]) {
      final answer = ApplicationFrame.decode(
        await service.handle(
          request(payload.$1, payload.$2),
          sessionBinding: binding,
          authorized: true,
          now: now,
        ),
      );
      expect(answer.kind, ApplicationFrameKind.error);
      expect(
        ApplicationErrorCode.decode(answer.payload),
        ApplicationErrorCode.rejected,
        reason: 'a refusal must be the same code a missing item gets',
      );
    }

    expect(repository.fetches, 0, reason: 'the keystore was never unlocked');
    expect(repository.writes, 0);
  });

  /// The sheet is what turns a Keystore prompt into an approval, so a build
  /// that forgets to wire one must serve nothing rather than fall back to the
  /// bare prompt.
  test(
    'a service with no approval attached refuses to release anything',
    () async {
      final repository = _CountingStore();
      final service = VaultService(repository: repository);

      final fetched = ApplicationFrame.decode(
        await service.handle(
          request(
            wire.vaultFetchOperation,
            wire.VaultFetchRequest(
              verifierName: 'Desktop',
              itemId: 'one',
            ).encode(),
          ),
          sessionBinding: binding,
          authorized: true,
          now: now,
        ),
      );

      expect(fetched.kind, ApplicationFrameKind.error);
      expect(repository.fetches, 0);
    },
  );

  test('listing needs no approval, because it releases no secret', () async {
    final approval = _RecordingApproval(approve: false);
    final service = VaultService(repository: _VaultStore(), approval: approval);

    final listed = ApplicationFrame.decode(
      await service.handle(
        request(
          wire.vaultListOperation,
          wire.VaultListRequest(verifierName: 'Desktop').encode(),
        ),
        sessionBinding: binding,
        authorized: true,
        now: now,
      ),
    );

    expect(listed.kind, ApplicationFrameKind.response);
    expect(
      approval.seen,
      isEmpty,
      reason: 'a sheet on every list trains the user to dismiss them',
    );
  });

  /// The desktop sends an id; the name on the sheet comes from the phone's own
  /// store. A desktop that could supply the name could label a request for the
  /// bank password "Spotify" and get it approved.
  test(
    'the sheet describes the item the phone holds, not what was sent',
    () async {
      final approval = _RecordingApproval(approve: true);
      final service = VaultService(
        repository: _VaultStore(),
        approval: approval,
      );

      await service.handle(
        request(
          wire.vaultFetchOperation,
          wire.VaultFetchRequest(
            verifierName: 'Meu PC',
            itemId: 'one',
          ).encode(),
        ),
        sessionBinding: binding,
        authorized: true,
        now: now,
      );

      final shown = approval.seen.single;
      expect(shown.verifierName, 'Meu PC');
      expect(shown.operation, VaultOperation.read);
      expect(shown.itemName, 'Example');
      expect(shown.username, 'alice');
      expect(shown.domain, 'example.com', reason: 'the host, not the full URI');
    },
  );

  /// An id nothing matches still gets a sheet. Answering faster for an item
  /// that is not there is exactly what lets a paired desktop enumerate a vault
  /// it is not allowed to read.
  test('an unknown id is still put to the user', () async {
    final approval = _RecordingApproval(approve: false);
    final service = VaultService(repository: _VaultStore(), approval: approval);

    await service.handle(
      request(
        wire.vaultFetchOperation,
        wire.VaultFetchRequest(
          verifierName: 'Desktop',
          itemId: 'nao-existe',
        ).encode(),
      ),
      sessionBinding: binding,
      authorized: true,
      now: now,
    );

    expect(approval.seen, hasLength(1));
    expect(approval.seen.single.itemName, 'Item desconhecido');
  });
  test('a tap that lands after the request expired unlocks nothing', () async {
    // The window is checked before the sheet goes up, and the sheet waits on a
    // person. This frame is good for a minute; this user answers after two.
    final repository = _CountingStore();
    var moment = now;
    final service = VaultService(
      repository: repository,
      approval: _SlowApproval(
        () => moment = now.add(const Duration(minutes: 2)),
      ),
      clock: () => moment,
    );

    final answered = await service.handle(
      request(
        wire.vaultFetchOperation,
        wire.VaultFetchRequest(verifierName: 'Desktop', itemId: 'one').encode(),
      ),
      sessionBinding: binding,
      authorized: true,
    );

    expect(ApplicationFrame.decode(answered).kind, ApplicationFrameKind.error);
    expect(
      repository.fetches,
      0,
      reason:
          'the desktop stopped accepting an answer at expiresAt, so unlocking '
          'here spends a fingerprint to decrypt a secret into a session that '
          'is already gone',
    );
  });
}

/// Someone who taps yes, long after being asked.
class _SlowApproval implements VaultApproval {
  _SlowApproval(this.onAsked);

  final void Function() onAsked;

  @override
  Future<bool> confirm(VaultApprovalRequest request) async {
    onAsked();
    return true;
  }
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
  Future<List<store.VaultItemSummary>?> delete(
    store.VaultItemSummary item,
  ) async => null;
}

class _RecordingApproval implements VaultApproval {
  _RecordingApproval({required this.approve});

  final bool approve;
  final List<VaultApprovalRequest> seen = [];

  @override
  Future<bool> confirm(VaultApprovalRequest request) async {
    seen.add(request);
    return approve;
  }
}

/// A store that would hand over the secret if anything ever asked it to.
///
/// Used to prove a refusal never reaches storage: the assertion is on this
/// counter, not on the reply, because a service that fetched and then answered
/// `rejected` would look identical on the wire and have already unlocked the
/// key.
class _CountingStore extends _VaultStore {
  int fetches = 0;
  int writes = 0;

  @override
  Future<store.VaultSecret> fetch(String id) {
    fetches++;
    return super.fetch(id);
  }

  @override
  Future<store.VaultWrite> create(store.VaultItemInput item) {
    writes++;
    return super.create(item);
  }

  @override
  Future<List<store.VaultItemSummary>?> delete(store.VaultItemSummary item) {
    writes++;
    return super.delete(item);
  }
}

/// Counts trips into the store, which on the real one is a Keystore prompt.
class _ListCountingStore extends _VaultStore {
  int unlocks = 0;

  @override
  Future<store.VaultPage> listPage([String? cursor]) {
    unlocks++;
    return super.listPage(cursor);
  }

  @override
  Future<store.VaultSecret> fetch(String id) {
    unlocks++;
    return super.fetch(id);
  }
}

class _FailingStore extends _VaultStore {
  _FailingStore(this.code);
  final String code;

  @override
  Future<store.VaultSecret> fetch(String id) =>
      Future.error(PlatformException(code: code));
}
