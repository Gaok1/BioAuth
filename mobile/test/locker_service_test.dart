import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/locker/locker_service.dart';
import 'package:phone_auth/core/protocol/application_frame.dart';
import 'package:phone_auth/core/protocol/locker_payloads.dart';

/// Um Keystore de mentira: embrulha com um XOR e registra o que foi perguntado.
///
/// O que interessa testar aqui não é a criptografia — essa é do Keystore — e
/// sim quem o serviço deixa entrar e o que ele devolve.
class FakeGuardian implements LockerKeyGuardian {
  bool refuse = false;
  int wraps = 0;
  String? lastCredentialId;
  String? lastFileName;
  bool? lastRekeying;

  @override
  Future<Uint8List> wrap({
    required Uint8List binding,
    required String credentialId,
    required Uint8List dataKey,
    required String fileName,
    required String verifierName,
  }) async {
    if (refuse) throw StateError('usuário cancelou');
    wraps++;
    lastCredentialId = credentialId;
    lastFileName = fileName;
    return Uint8List.fromList([
      for (var index = 0; index < dataKey.length; index++)
        dataKey[index] ^ binding[index],
    ]);
  }

  @override
  Future<Uint8List> unwrap({
    required Uint8List binding,
    required String credentialId,
    required Uint8List wrapper,
    required String fileName,
    required String verifierName,
    bool rekeying = false,
  }) async {
    if (refuse) throw StateError('usuário cancelou');
    lastCredentialId = credentialId;
    lastFileName = fileName;
    lastRekeying = rekeying;
    return Uint8List.fromList([
      for (var index = 0; index < 32; index++)
        wrapper[index % wrapper.length] ^ binding[index],
    ]);
  }
}

final _sessionBinding = Uint8List.fromList(List<int>.filled(32, 3));
final _containerBinding = Uint8List.fromList(
  List<int>.generate(32, (index) => index),
);
final _now = DateTime.fromMillisecondsSinceEpoch(1787745600000, isUtc: true);

Uint8List _request(
  String operation,
  Uint8List payload, {
  Uint8List? binding,
  String requestId = 'request-1',
}) => ApplicationFrame(
  protocolVersion: 1,
  kind: ApplicationFrameKind.request,
  requestId: requestId,
  sessionBinding: binding ?? _sessionBinding,
  operation: operation,
  issuedAt: _now,
  expiresAt: _now.add(const Duration(seconds: 60)),
  payload: payload,
).encode();

Uint8List _wrapPayload() => LockerWrapRequest(
  verifierName: 'Workstation',
  fileName: 'tax return.pdf',
  plaintextLength: 100000,
  containerBinding: _containerBinding,
  dataKey: List<int>.filled(32, 7),
).encode();

Uint8List _unwrapPayload() => LockerUnwrapRequest(
  verifierName: 'Workstation',
  fileName: 'tax return.pdf.balock',
  plaintextLength: 100000,
  containerBinding: _containerBinding,
  credentialId: 'locker-cred-1',
  wrapper: List<int>.filled(60, 9),
).encode();

void main() {
  late FakeGuardian guardian;
  late LockerService service;

  setUp(() {
    guardian = FakeGuardian();
    service = LockerService(guardian: guardian, credentialId: 'locker-cred-1');
  });

  test(
    'locker.create devolve um wrapper amarrado à credencial do telefone',
    () async {
      final answer = await service.handle(
        _request(lockerCreateOperation, _wrapPayload()),
        sessionBinding: _sessionBinding,
        now: _now,
      );

      final frame = ApplicationFrame.decode(answer);
      expect(frame.kind, ApplicationFrameKind.response);
      expect(frame.operation, lockerCreateOperation);
      expect(frame.requestId, 'request-1');

      final response = LockerWrapResponse.decode(frame.payload);
      expect(response.credentialId, 'locker-cred-1');
      expect(guardian.lastFileName, 'tax return.pdf');
    },
  );

  test('locker.unlock e locker.rekey pedem gestos diferentes', () async {
    await service.handle(
      _request(lockerUnlockOperation, _unwrapPayload()),
      sessionBinding: _sessionBinding,
      now: _now,
    );
    expect(guardian.lastRekeying, isFalse);

    await service.handle(
      _request(lockerRekeyOperation, _unwrapPayload()),
      sessionBinding: _sessionBinding,
      now: _now,
    );
    expect(guardian.lastRekeying, isTrue);
  });

  test(
    'um retry de locker.create reutiliza o wrapper sem novo gesto',
    () async {
      final first = ApplicationFrame.decode(
        await service.handle(
          _request(lockerCreateOperation, _wrapPayload()),
          sessionBinding: _sessionBinding,
          now: _now,
        ),
      );
      final nextBinding = Uint8List.fromList(List<int>.filled(32, 4));
      final retry = ApplicationFrame.decode(
        await service.handle(
          _request(lockerCreateOperation, _wrapPayload(), binding: nextBinding),
          sessionBinding: nextBinding,
          now: _now,
        ),
      );

      expect(retry.payload, first.payload);
      expect(retry.sessionBinding, nextBinding);
      expect(guardian.wraps, 1);
    },
  );

  test('o mesmo requestId não aceita outro locker.create', () async {
    await service.handle(
      _request(lockerCreateOperation, _wrapPayload()),
      sessionBinding: _sessionBinding,
      now: _now,
    );
    final changed = LockerWrapRequest(
      verifierName: 'Workstation',
      fileName: 'other.pdf',
      plaintextLength: 100000,
      containerBinding: _containerBinding,
      dataKey: List<int>.filled(32, 7),
    ).encode();
    final answer = ApplicationFrame.decode(
      await service.handle(
        _request(lockerCreateOperation, changed),
        sessionBinding: _sessionBinding,
        now: _now,
      ),
    );

    expect(answer.kind, ApplicationFrameKind.error);
    expect(guardian.wraps, 1);
  });

  test(
    'o telefone usa a credencial que ele guarda, não a que veio no frame',
    () async {
      final other = LockerService(
        guardian: guardian,
        credentialId: 'outra-cred',
      );
      await other.handle(
        _request(lockerUnlockOperation, _unwrapPayload()),
        sessionBinding: _sessionBinding,
        now: _now,
      );
      expect(guardian.lastCredentialId, 'outra-cred');
    },
  );

  test('um frame de outra sessão não é respondido', () async {
    final foreign = _request(
      lockerUnlockOperation,
      _unwrapPayload(),
      binding: Uint8List.fromList(List<int>.filled(32, 9)),
    );
    expect(
      () => service.handle(foreign, sessionBinding: _sessionBinding, now: _now),
      throwsFormatException,
    );
  });

  test('um frame expirado não é respondido', () async {
    expect(
      () => service.handle(
        _request(lockerUnlockOperation, _unwrapPayload()),
        sessionBinding: _sessionBinding,
        now: _now.add(const Duration(seconds: 61)),
      ),
      throwsFormatException,
    );
  });

  test('uma recusa vira frame de erro sem payload', () async {
    guardian.refuse = true;
    final answer = await service.handle(
      _request(lockerCreateOperation, _wrapPayload()),
      sessionBinding: _sessionBinding,
      now: _now,
    );

    final frame = ApplicationFrame.decode(answer);
    expect(frame.kind, ApplicationFrameKind.error);
    expect(frame.payload, isEmpty);
    expect(frame.requestId, 'request-1');
  });

  test('uma operação de outro produto não é atendida', () async {
    final answer = await service.handle(
      _request('vault.list', _wrapPayload()),
      sessionBinding: _sessionBinding,
      now: _now,
    );
    expect(ApplicationFrame.decode(answer).kind, ApplicationFrameKind.error);
  });

  test('um payload que não é do locker vira erro, não chave', () async {
    final answer = await service.handle(
      _request(lockerCreateOperation, _unwrapPayload()),
      sessionBinding: _sessionBinding,
      now: _now,
    );
    expect(ApplicationFrame.decode(answer).kind, ApplicationFrameKind.error);
  });
}
