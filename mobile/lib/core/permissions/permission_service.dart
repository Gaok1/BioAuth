import 'dart:typed_data';

import '../protocol/application_frame.dart';
import '../protocol/permission_payloads.dart';
import 'permission_store.dart';

/// Atende `permissions.sync`: o único lugar onde os dois lados acertam o que um
/// pareamento pode autorizar.
///
/// Este lado é quem decide. O computador manda o que acredita, aqui roda a
/// regra de [reconcile], e a resposta é o conjunto inteiro que vale — nunca um
/// diff e nunca "sem mudança". O computador guarda o que voltar literalmente,
/// então uma resposta que ele não entenda vira uma chamada recusada e não um
/// pareamento atualizado pela metade.
///
/// **Sem digital, de propósito.** Este handler não levanta prompt, e a razão é
/// que ele não concede nada: ou repete o que o computador acabou de mandar, ou
/// devolve o que uma pessoa já editou nesta tela — atrás do desbloqueio do
/// aparelho, com biometria, no momento em que editou. Pedir de novo aqui
/// significaria uma digital por sessão para dizer "continua igual", que é o
/// caminho mais curto para o usuário aprovar sem ler.
///
/// A credencial da sessão é quem delimita o alcance. Uma sessão aberta com a
/// credencial do SSH só acerta as permissões dela; não há como nomear outra.
class PermissionService {
  PermissionService({
    required PermissionStore store,
    required String verifierId,
    required String credentialId,
    DateTime Function()? clock,
  }) : _store = store,
       _verifierId = verifierId,
       _credentialId = credentialId,
       _clock = clock ?? DateTime.now;

  final PermissionStore _store;
  final String _verifierId;
  final String _credentialId;
  final DateTime Function() _clock;

  /// Se este frame é para cá.
  ///
  /// Recebe os bytes e não um frame já decodificado, porque decidir isto não
  /// pode ser o lugar onde um frame ilegível estoura. A regra da sessão é que
  /// um frame que ela não consegue ler fica com o handler, que responde com um
  /// erro — e não com uma exceção subindo pelo despacho. Um frame que não
  /// decodifica aqui simplesmente não é nosso, e segue para quem já sabe
  /// recusá-lo direito.
  static bool serves(Uint8List frame) {
    try {
      return ApplicationFrame.decode(frame).operation ==
          permissionsSyncOperation;
    } on Object {
      return false;
    }
  }

  Future<Uint8List> handle(
    Uint8List frame, {
    required Uint8List sessionBinding,
  }) async {
    final request = ApplicationFrame.decode(frame);
    if (request.kind != ApplicationFrameKind.request ||
        !_sameBytes(request.sessionBinding, sessionBinding) ||
        request.isExpiredAt(_clock().toUtc())) {
      throw const FormatException('permission frame from another session');
    }

    final PermissionSyncRequest decoded;
    try {
      decoded = PermissionSyncRequest.decode(request.payload);
    } on FormatException {
      return _error(request, ApplicationErrorCode.invalidRequest);
    }

    try {
      final mine = await _store.read(_verifierId, _credentialId);
      final winner = reconcile(
        mine.revision,
        decoded.revision,
        phoneWinsTies: true,
      );

      final settled = switch (winner) {
        PermissionWinner.mine => mine,
        PermissionWinner.theirs => PermissionSet(
          revision: decoded.revision,
          permissions: List.unmodifiable(decoded.permissions),
        ),
      };

      // Escrito mesmo quando este lado venceu? Não. Quando este lado vence,
      // o que está no disco já é o que vai na resposta, e reescrever seria
      // uma gravação por sessão ociosa. Só a adoção grava.
      if (winner == PermissionWinner.theirs) {
        await _store.write(_verifierId, _credentialId, settled);
      }

      return _reply(
        request,
        PermissionSyncResponse(
          revision: settled.revision,
          permissions: settled.permissions,
        ).encode(),
      );
    } on FormatException {
      // O conjunto guardado não cabe no formato — grande demais, ou com um
      // campo que não deveria ter passado. Indisponível, não recusado: não é
      // uma decisão sobre este pedido.
      return _error(request, ApplicationErrorCode.unavailable);
    } on Object {
      return _error(request, ApplicationErrorCode.unavailable);
    }
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

  static bool _sameBytes(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var same = 0;
    for (var index = 0; index < a.length; index++) {
      same |= a[index] ^ b[index];
    }
    return same == 0;
  }
}
