import 'dart:typed_data';

import 'package:phone_auth_native/phone_auth_native.dart';

import '../protocol/application_frame.dart';
import '../protocol/locker_payloads.dart';

/// Quem guarda a chave que embrulha as chaves de container.
///
/// Existe como interface para que o serviço seja testável sem Keystore: a
/// implementação real é [NativeLockerKeyGuardian], que passa por biometria
/// forte a cada uso.
abstract class LockerKeyGuardian {
  Future<Uint8List> wrap({
    required Uint8List binding,
    required String credentialId,
    required Uint8List dataKey,
    required String fileName,
    required String verifierName,
  });

  Future<Uint8List> unwrap({
    required Uint8List binding,
    required String credentialId,
    required Uint8List wrapper,
    required String fileName,
    required String verifierName,
    bool rekeying,
  });
}

class NativeLockerKeyGuardian implements LockerKeyGuardian {
  const NativeLockerKeyGuardian();

  static const _key = PhoneAuthLockerKey();

  @override
  Future<Uint8List> wrap({
    required Uint8List binding,
    required String credentialId,
    required Uint8List dataKey,
    required String fileName,
    required String verifierName,
  }) => _key.wrap(
    binding: binding,
    credentialId: credentialId,
    dataKey: dataKey,
    fileName: fileName,
    verifierName: verifierName,
  );

  @override
  Future<Uint8List> unwrap({
    required Uint8List binding,
    required String credentialId,
    required Uint8List wrapper,
    required String fileName,
    required String verifierName,
    bool rekeying = false,
  }) => _key.unwrap(
    binding: binding,
    credentialId: credentialId,
    wrapper: wrapper,
    fileName: fileName,
    verifierName: verifierName,
    rekeying: rekeying,
  );
}

/// O lado do telefone das operações `locker.*`.
///
/// Recebe um frame de aplicação já decifrado pelo canal seguro, confere que ele
/// pertence a esta sessão, pede o gesto biométrico e devolve o frame de
/// resposta. Nada aqui grava chave, binding ou nome de arquivo em log.
class LockerService {
  LockerService({
    required LockerKeyGuardian guardian,
    required String credentialId,
  }) : _guardian = guardian,
       _credentialId = credentialId;

  final LockerKeyGuardian _guardian;
  final String _credentialId;

  /// Processa um frame e devolve a resposta a enviar de volta.
  ///
  /// [sessionBinding] é o binding da sessão viva, não o que veio no frame:
  /// comparar os dois é o que impede uma resposta capturada em outra sessão de
  /// ser aceita nesta.
  Future<Uint8List> handle(
    Uint8List frame, {
    required Uint8List sessionBinding,
    DateTime? now,
  }) async {
    final moment = (now ?? DateTime.now()).toUtc();
    final request = ApplicationFrame.decode(frame);

    if (request.kind != ApplicationFrameKind.request ||
        !_sameBytes(request.sessionBinding, sessionBinding) ||
        request.isExpiredAt(moment)) {
      throw const FormatException('Frame de locker fora desta sessão');
    }

    try {
      final payload = switch (request.operation) {
        lockerCreateOperation => await _wrap(request),
        lockerUnlockOperation => await _unwrap(request, rekeying: false),
        lockerRekeyOperation => await _unwrap(request, rekeying: true),
        _ => throw const FormatException('Operação de locker desconhecida'),
      };
      return _reply(request, ApplicationFrameKind.response, payload);
    } on Object {
      // Recusa, cancelamento e payload inválido saem iguais na rede: qual dos
      // três foi não é informação que o computador precisa, e é informação que
      // um atacante usaria.
      return _reply(request, ApplicationFrameKind.error, Uint8List(0));
    }
  }

  Future<Uint8List> _wrap(ApplicationFrame request) async {
    final asked = LockerWrapRequest.decode(request.payload);
    final wrapper = await _guardian.wrap(
      binding: asked.containerBinding,
      credentialId: _credentialId,
      dataKey: asked.dataKey,
      fileName: asked.fileName,
      verifierName: asked.verifierName,
    );
    return LockerWrapResponse(
      credentialId: _credentialId,
      wrapper: wrapper,
    ).encode();
  }

  Future<Uint8List> _unwrap(
    ApplicationFrame request, {
    required bool rekeying,
  }) async {
    final asked = LockerUnwrapRequest.decode(request.payload);
    // O telefone usa a credencial que ele mesmo guarda. Se o container aponta
    // para outra, o AAD não bate e a tag falha — que é o resultado certo.
    final dataKey = await _guardian.unwrap(
      binding: asked.containerBinding,
      credentialId: _credentialId,
      wrapper: asked.wrapper,
      fileName: asked.fileName,
      verifierName: asked.verifierName,
      rekeying: rekeying,
    );
    return LockerUnwrapResponse(dataKey: dataKey).encode();
  }

  Uint8List _reply(
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

  static bool _sameBytes(Uint8List left, Uint8List right) {
    if (left.length != right.length) return false;
    for (var index = 0; index < left.length; index++) {
      if (left[index] != right[index]) return false;
    }
    return true;
  }
}
