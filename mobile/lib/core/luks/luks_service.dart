import 'dart:typed_data';

import 'package:phone_auth_native/phone_auth_native.dart';

import '../protocol/application_frame.dart';
import '../protocol/application_idempotency.dart';
import '../protocol/luks_payloads.dart';

abstract class LuksKeyGuardian {
  Future<Uint8List> wrap({
    required Uint8List binding,
    required String credentialId,
    required Uint8List diskKey,
    required String volumeName,
    required String verifierName,
  });

  Future<Uint8List> unwrap({
    required Uint8List binding,
    required String credentialId,
    required Uint8List wrapper,
    required String volumeName,
    required String verifierName,
  });
}

class NativeLuksKeyGuardian implements LuksKeyGuardian {
  const NativeLuksKeyGuardian();

  static const _key = PhoneAuthLuksKey();

  @override
  Future<Uint8List> wrap({
    required Uint8List binding,
    required String credentialId,
    required Uint8List diskKey,
    required String volumeName,
    required String verifierName,
  }) => _key.wrap(
    binding: binding,
    credentialId: credentialId,
    diskKey: diskKey,
    volumeName: volumeName,
    verifierName: verifierName,
  );

  @override
  Future<Uint8List> unwrap({
    required Uint8List binding,
    required String credentialId,
    required Uint8List wrapper,
    required String volumeName,
    required String verifierName,
  }) => _key.unwrap(
    binding: binding,
    credentialId: credentialId,
    wrapper: wrapper,
    volumeName: volumeName,
    verifierName: verifierName,
  );
}

/// Handles the phone half of LUKS enrollment and boot unlock.
class LuksService {
  LuksService({required LuksKeyGuardian guardian, required String credentialId})
    : _guardian = guardian,
      _credentialId = credentialId;

  final LuksKeyGuardian _guardian;
  final String _credentialId;
  final ApplicationIdempotency _idempotency = ApplicationIdempotency();

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
      throw const FormatException('Frame LUKS outside this session');
    }

    Future<ApplicationOutcome> execute() async {
      try {
        final payload = switch (request.operation) {
          luksEnrollOperation => await _enroll(request),
          luksUnlockOperation => await _unlock(request),
          _ => throw const FormatException('Unknown LUKS operation'),
        };
        return ApplicationOutcome(ApplicationFrameKind.response, payload);
      } on Object {
        // Malformed data, refusal and cancellation are deliberately identical.
        return ApplicationOutcome(ApplicationFrameKind.error, Uint8List(0));
      }
    }

    try {
      final outcome = request.operation == luksEnrollOperation
          ? await _idempotency.run(
              scope: _credentialId,
              request: request,
              operation: execute,
            )
          : await execute();
      return _reply(request, outcome.kind, outcome.payload);
    } on Object {
      return _reply(request, ApplicationFrameKind.error, Uint8List(0));
    }
  }

  Future<Uint8List> _enroll(ApplicationFrame request) async {
    final asked = LuksEnrollRequest.decode(request.payload);
    final wrapper = await _guardian.wrap(
      binding: asked.volumeBinding,
      credentialId: _credentialId,
      diskKey: asked.diskKey,
      volumeName: asked.volumeName,
      verifierName: asked.verifierName,
    );
    return LuksEnrollResponse(
      credentialId: _credentialId,
      wrapper: wrapper,
    ).encode();
  }

  Future<Uint8List> _unlock(ApplicationFrame request) async {
    final asked = LuksUnlockRequest.decode(request.payload);
    if (asked.credentialId != _credentialId) {
      throw const FormatException('LUKS credential mismatch');
    }
    final diskKey = await _guardian.unwrap(
      binding: asked.volumeBinding,
      credentialId: _credentialId,
      wrapper: asked.wrapper,
      volumeName: asked.volumeName,
      verifierName: asked.verifierName,
    );
    return LuksUnlockResponse(diskKey: diskKey).encode();
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
