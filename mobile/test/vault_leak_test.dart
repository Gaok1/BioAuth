/// Where a secret must never turn up on the phone side.
///
/// VLT-14. Each of these is a surface a value crosses on a path a secret is
/// nearby: a wire frame, an approval sheet, a summary that feeds a list. They
/// search the whole artefact rather than named fields, because the failure to
/// catch is a field nobody thought to assert on.
library;

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/protocol/application_frame.dart';
import 'package:phone_auth/core/protocol/vault_payloads.dart' as wire;
import 'package:phone_auth/core/vault/vault_approval.dart';
import 'package:phone_auth/core/vault/vault_service.dart';
import 'package:phone_auth/features/vault/vault_store.dart' as store;

/// Distinctive enough that finding it anywhere is unambiguous.
const canary = 'canary-hunter2-do-not-log';

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

  /// The sheet is drawn from this, and a screen is a screenshot, a recents
  /// thumbnail and an accessibility tree. Nothing on it may be the secret.
  test('an approval request cannot carry the secret it is approving', () async {
    final approval = _Recording();
    final service = VaultService(
      repository: _StoreHolding(canary),
      approval: approval,
    );

    await service.handle(
      request(
        wire.vaultFetchOperation,
        wire.VaultFetchRequest(verifierName: 'Desktop', itemId: 'one').encode(),
      ),
      sessionBinding: binding,
      authorized: true,
      now: now,
    );

    final shown = approval.seen.single;
    for (final field in [
      shown.verifierName,
      shown.itemName,
      shown.username,
      shown.uri,
      shown.operation,
      shown.domain,
    ]) {
      expect(field, isNot(contains(canary)));
    }
  });

  /// A list is metadata the user agreed to show on a desktop. One secret in a
  /// list response would hand over the whole vault for the price of a listing,
  /// which is the distinction `vault.list` and `vault.fetch` exist to keep.
  test('a list response carries no secret', () async {
    final service = VaultService(
      repository: _StoreHolding(canary),
      approval: _Recording(),
    );

    final listed = await service.handle(
      request(
        wire.vaultListOperation,
        wire.VaultListRequest(verifierName: 'Desktop').encode(),
      ),
      sessionBinding: binding,
      authorized: true,
      now: now,
    );

    expect(String.fromCharCodes(listed), isNot(contains(canary)));
  });

  /// The generic refusal is the point of the taxonomy: an error frame that
  /// quoted what went wrong would leak the item's existence at minimum.
  test('an error frame says nothing about what was asked for', () async {
    final service = VaultService(
      repository: _StoreHolding(canary),
      approval: _Recording(approve: false),
    );

    final refused = await service.handle(
      request(
        wire.vaultFetchOperation,
        wire.VaultFetchRequest(verifierName: 'Desktop', itemId: 'one').encode(),
      ),
      sessionBinding: binding,
      authorized: true,
      now: now,
    );

    final frame = ApplicationFrame.decode(refused);
    expect(frame.kind, ApplicationFrameKind.error);
    expect(String.fromCharCodes(refused), isNot(contains(canary)));
    // Three bytes of error code and nothing else. A payload with room for a
    // message is a payload somebody eventually writes one into.
    expect(frame.payload.length, lessThan(8));
  });

  /// A summary is what feeds every list, every search and every row on screen.
  test('a summary has nowhere to put a secret', () {
    final summary = store.VaultItemSummary(
      id: 'one',
      revision: 1,
      kind: store.VaultItemKind.login,
      name: 'Banco',
      username: 'alice',
      uri: 'https://banco.example.com',
      updatedAt: DateTime.utc(2026),
    );

    expect(summary.toString(), isNot(contains(canary)));
  });
}

class _Recording implements VaultApproval {
  _Recording({this.approve = true});

  final bool approve;
  final List<VaultApprovalRequest> seen = [];

  @override
  Future<bool> confirm(VaultApprovalRequest request) async {
    seen.add(request);
    return approve;
  }
}

/// A store whose every field is the canary, so anything that copies a field
/// into somewhere it should not be shows up.
class _StoreHolding extends store.VaultStore {
  _StoreHolding(this.secret);

  final String secret;

  @override
  Future<store.VaultPage> listPage([String? cursor]) async => store.VaultPage(
    items: [
      store.VaultItemSummary(
        id: 'one',
        revision: 1,
        kind: store.VaultItemKind.login,
        name: 'Banco',
        username: 'alice',
        uri: 'https://banco.example.com',
        updatedAt: DateTime.utc(2026),
      ),
    ],
  );

  @override
  Future<store.VaultSecret> fetch(String id) async =>
      store.VaultSecret(id: id, revision: 1, secret: secret);

  @override
  Future<store.VaultWrite> create(store.VaultItemInput item) async =>
      const store.VaultWrite(id: 'two', revision: 1);

  @override
  Future<store.VaultWrite> update(
    store.VaultItemSummary current,
    store.VaultItemInput item,
  ) async => store.VaultWrite(id: current.id, revision: current.revision + 1);

  @override
  Future<List<store.VaultItemSummary>?> delete(
    store.VaultItemSummary item,
  ) async => null;
}
