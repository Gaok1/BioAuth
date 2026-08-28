import 'package:flutter/services.dart';

import '../../features/vault/vault_store.dart' as store;
import '../protocol/application_frame.dart';
import '../protocol/vault_payloads.dart' as wire;

/// Serves vault application frames without exposing storage failure details.
class VaultService {
  VaultService({store.VaultStore? repository})
    : _store = repository ?? const store.NativeVaultStore();

  final store.VaultStore _store;

  Future<Uint8List> handle(
    Uint8List frame, {
    required Uint8List sessionBinding,
    required bool authorized,
    DateTime? now,
  }) async {
    final request = ApplicationFrame.decode(frame);
    final moment = (now ?? DateTime.now()).toUtc();
    if (request.kind != ApplicationFrameKind.request ||
        !_sameBytes(request.sessionBinding, sessionBinding) ||
        request.isExpiredAt(moment)) {
      throw const FormatException('Frame de cofre fora desta sessão');
    }
    if (!authorized) return _error(request, ApplicationErrorCode.rejected);

    late final Future<Uint8List> operation;
    try {
      operation = switch (request.operation) {
        wire.vaultListOperation => _list(
          wire.VaultListRequest.decode(request.payload),
        ),
        wire.vaultFetchOperation => _fetch(
          wire.VaultFetchRequest.decode(request.payload),
        ),
        wire.vaultCreateOperation => _create(
          wire.VaultCreateRequest.decode(request.payload),
        ),
        wire.vaultUpdateOperation => _update(
          wire.VaultUpdateRequest.decode(request.payload),
        ),
        wire.vaultDeleteOperation => _delete(
          wire.VaultDeleteRequest.decode(request.payload),
        ),
        _ => throw const FormatException('Operação de cofre desconhecida'),
      };
    } on FormatException {
      return _error(request, ApplicationErrorCode.invalidRequest);
    }

    try {
      return _reply(request, await operation);
    } on PlatformException {
      // not_found, revision_conflict and biometric refusal are intentionally
      // indistinguishable on the wire.
      return _error(request, ApplicationErrorCode.rejected);
    } on Object {
      return _error(request, ApplicationErrorCode.unavailable);
    }
  }

  Future<Uint8List> _list(wire.VaultListRequest request) async {
    final page = await _store.listPage(
      request.cursor.isEmpty ? null : request.cursor,
    );
    return wire.VaultListResponse(
      items: [
        for (final item in page.items)
          wire.VaultItemSummary(
            id: item.id,
            revision: item.revision,
            kind: wire.VaultItemKind.values[item.kind.index],
            name: item.name,
            username: item.username,
            uri: item.uri,
            updatedAtMs: item.updatedAt.millisecondsSinceEpoch,
          ),
      ],
      nextCursor: page.nextCursor ?? '',
    ).encode();
  }

  Future<Uint8List> _fetch(wire.VaultFetchRequest request) async {
    final item = await _store.fetch(request.itemId);
    return wire.VaultFetchResponse(
      itemId: item.id,
      revision: item.revision,
      secret: item.secret,
    ).encode();
  }

  Future<Uint8List> _create(wire.VaultCreateRequest request) async {
    final written = await _store.create(_input(request));
    return wire.VaultWriteResponse(
      itemId: written.id,
      revision: written.revision,
    ).encode();
  }

  Future<Uint8List> _update(wire.VaultUpdateRequest request) async {
    final current = store.VaultItemSummary(
      id: request.itemId,
      revision: request.expectedRevision,
      kind: store.VaultItemKind.values[request.kind.index],
      name: request.name,
      username: request.username,
      uri: request.uri,
      updatedAt: DateTime.fromMillisecondsSinceEpoch(0, isUtc: true),
    );
    final written = await _store.update(current, _input(request));
    return wire.VaultWriteResponse(
      itemId: written.id,
      revision: written.revision,
    ).encode();
  }

  Future<Uint8List> _delete(wire.VaultDeleteRequest request) async {
    await _store.delete(
      store.VaultItemSummary(
        id: request.itemId,
        revision: request.expectedRevision,
        kind: store.VaultItemKind.login,
        name: request.itemId,
        username: '',
        uri: '',
        updatedAt: DateTime.fromMillisecondsSinceEpoch(0, isUtc: true),
      ),
    );
    return wire.VaultDeleteResponse(itemId: request.itemId).encode();
  }

  store.VaultItemInput _input(Object request) {
    final (kind, name, username, uri, secret) = switch (request) {
      wire.VaultCreateRequest value => (
        value.kind,
        value.name,
        value.username,
        value.uri,
        value.secret,
      ),
      wire.VaultUpdateRequest value => (
        value.kind,
        value.name,
        value.username,
        value.uri,
        value.secret,
      ),
      _ => throw ArgumentError.value(request),
    };
    return store.VaultItemInput(
      kind: store.VaultItemKind.values[kind.index],
      name: name,
      username: username,
      uri: uri,
      secret: secret,
    );
  }

  Uint8List _reply(ApplicationFrame request, Uint8List payload) =>
      _frame(request, ApplicationFrameKind.response, payload);

  Uint8List _error(ApplicationFrame request, ApplicationErrorCode code) =>
      _frame(request, ApplicationFrameKind.error, code.encode());

  Uint8List _frame(
    ApplicationFrame request,
    ApplicationFrameKind kind,
    Uint8List payload,
  ) => ApplicationFrame(
    protocolVersion: request.protocolVersion,
    kind: kind,
    requestId: request.requestId,
    sessionBinding: request.sessionBinding,
    operation: request.operation,
    issuedAt: request.issuedAt,
    expiresAt: request.expiresAt,
    payload: payload,
  ).encode();

  static bool _sameBytes(List<int> left, List<int> right) {
    if (left.length != right.length) return false;
    for (var index = 0; index < left.length; index++) {
      if (left[index] != right[index]) return false;
    }
    return true;
  }
}
