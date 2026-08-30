import 'package:flutter/services.dart';

import '../../features/vault/vault_store.dart' as store;
import '../protocol/application_frame.dart';
import '../protocol/vault_payloads.dart' as wire;
import 'vault_approval.dart';
import 'vault_listing.dart';

/// Serves vault application frames without exposing storage failure details.
class VaultService {
  VaultService({
    store.VaultStore? repository,
    VaultApproval? approval,
    VaultListing? listing,
  }) : _store = repository ?? const store.NativeVaultStore(),
       // Its own by default, which is correct and gives up the snapshot
       // between sessions -- and a paged walk is several sessions. The
       // session service passes a shared one for exactly that reason.
       _listing =
           listing ??
           VaultListing(store: repository ?? const store.NativeVaultStore()),
       // Defaulting to a refusal rather than to a pass is deliberate. A build
       // that forgets to wire the sheet serves an empty list and nothing else,
       // which is a visible bug; defaulting the other way would serve secrets
       // behind a bare Keystore prompt, which is an invisible one.
       _approval = approval ?? const DenyVaultApproval();

  final store.VaultStore _store;
  final VaultListing _listing;
  final VaultApproval _approval;

  /// How many summaries go in one response.
  ///
  /// A frame is capped at 6144 bytes, so this is a wire limit rather than a
  /// storage one. The native store pages at the same number.
  static const int _pageSize = 32;

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

    // Decoding is separated from running so that a malformed payload is an
    // `invalidRequest` and a refused operation is a `rejected`, without the
    // approval sheet sitting inside a `try` that would swallow its answer.
    late final Object decoded;
    try {
      decoded = switch (request.operation) {
        wire.vaultListOperation => wire.VaultListRequest.decode(
          request.payload,
        ),
        wire.vaultFetchOperation => wire.VaultFetchRequest.decode(
          request.payload,
        ),
        wire.vaultCreateOperation => wire.VaultCreateRequest.decode(
          request.payload,
        ),
        wire.vaultUpdateOperation => wire.VaultUpdateRequest.decode(
          request.payload,
        ),
        wire.vaultDeleteOperation => wire.VaultDeleteRequest.decode(
          request.payload,
        ),
        _ => throw const FormatException('Operação de cofre desconhecida'),
      };
    } on FormatException {
      return _error(request, ApplicationErrorCode.invalidRequest);
    }

    try {
      // Listing is the one operation that needs no approval: it releases no
      // secret, and a sheet on every list would train the user to dismiss the
      // one that matters.
      if (decoded is wire.VaultListRequest) {
        return _reply(request, await _list(decoded));
      }

      final approved = await _approval.confirm(
        await _describe(request.requestId, decoded),
      );
      // The same code a missing item gets. Whether the user said no, the item
      // was never there, or the revision had moved on is not something the
      // desktop is told — see `protocol-application.md`.
      if (!approved) return _error(request, ApplicationErrorCode.rejected);

      return _reply(request, await _run(decoded));
    } on PlatformException {
      // not_found, revision_conflict and biometric refusal are intentionally
      // indistinguishable on the wire.
      return _error(request, ApplicationErrorCode.rejected);
    } on Object {
      return _error(request, ApplicationErrorCode.unavailable);
    }
  }

  Future<Uint8List> _run(Object decoded) => switch (decoded) {
    wire.VaultFetchRequest request => _fetch(request),
    wire.VaultCreateRequest request => _create(request),
    wire.VaultUpdateRequest request => _update(request),
    wire.VaultDeleteRequest request => _delete(request),
    _ => throw ArgumentError.value(decoded),
  };

  /// Builds the sentence the user reads before deciding.
  ///
  /// The item's name comes from the store rather than from the frame: for a
  /// fetch, a delete or an update the desktop sends only an id, and a desktop
  /// that could name the item on the sheet itself could name it whatever made
  /// approval likeliest. Only `create` describes an item that does not exist
  /// yet, so only there is the frame the source.
  Future<VaultApprovalRequest> _describe(String id, Object decoded) async {
    if (decoded is wire.VaultCreateRequest) {
      return VaultApprovalRequest(
        id: id,
        verifierName: decoded.verifierName,
        operation: VaultOperation.create,
        itemName: decoded.name,
        username: decoded.username,
        uri: decoded.uri,
      );
    }

    final (verifierName, itemId, operation) = switch (decoded) {
      wire.VaultFetchRequest request => (
        request.verifierName,
        request.itemId,
        VaultOperation.read,
      ),
      wire.VaultUpdateRequest request => (
        request.verifierName,
        request.itemId,
        VaultOperation.update,
      ),
      wire.VaultDeleteRequest request => (
        request.verifierName,
        request.itemId,
        VaultOperation.delete,
      ),
      _ => throw ArgumentError.value(decoded),
    };

    // An id nothing matches still gets a sheet. Skipping straight to a refusal
    // would answer faster for a missing item than for a present one, and that
    // difference is exactly what lets a paired desktop enumerate the vault.
    final item = await _store.summary(itemId);
    return VaultApprovalRequest(
      id: id,
      verifierName: verifierName,
      operation: operation,
      itemName: item?.name ?? 'Item desconhecido',
      username: item?.username ?? '',
      uri: item?.uri ?? '',
    );
  }

  /// Serves one page of a walk, from the snapshot the walk started with.
  ///
  /// The cursor is this service's own: an offset into that snapshot, opaque to
  /// the desktop, which only ever hands back what it was given. An empty one
  /// starts a walk and is the only thing that reads the vault again.
  Future<Uint8List> _list(wire.VaultListRequest request) async {
    final restart = request.cursor.isEmpty;
    final offset = restart ? 0 : int.tryParse(request.cursor) ?? -1;
    final all = await _listing.items(restart: restart);
    if (offset < 0 || offset > all.length) {
      throw const FormatException('Cursor de listagem inválido');
    }
    final page = all.skip(offset).take(_pageSize).toList(growable: false);
    final next = offset + page.length;
    return wire.VaultListResponse(
      items: [
        for (final item in page)
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
      nextCursor: next < all.length ? '$next' : '',
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
