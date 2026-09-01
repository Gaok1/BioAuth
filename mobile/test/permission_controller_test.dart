import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/pairing/pairing_record.dart';
import 'package:phone_auth/core/pairing/pairing_store.dart';
import 'package:phone_auth/core/permissions/permission_store.dart';
import 'package:phone_auth/core/protocol/enrolment.dart';
import 'package:phone_auth/core/protocol/permission_payloads.dart';
import 'package:phone_auth/features/permissions/permission_controller.dart';

class _Pairings implements PairingStore {
  _Pairings(this._records);

  final List<PairingRecord> _records;

  @override
  Future<List<PairingRecord>> load() async => _records;

  @override
  Future<void> save(PairingRecord record) async => _records.add(record);

  @override
  Future<void> remove(String verifierId) async =>
      _records.removeWhere((record) => record.verifierId == verifierId);

  @override
  Future<String> deviceId() async => 'phone-1';
}

class _Permissions implements PermissionStore {
  final Map<String, PermissionSet> entries = {};
  Object? failWith;

  @override
  Future<PermissionSet> read(String verifierId, String credentialId) async =>
      entries['$verifierId $credentialId'] ?? PermissionSet.never;

  @override
  Future<void> write(
    String verifierId,
    String credentialId,
    PermissionSet set,
  ) async {
    if (failWith case final error?) throw error;
    entries['$verifierId $credentialId'] = set;
  }

  @override
  Future<Map<String, PermissionSet>> readAll(String verifierId) async => {};

  @override
  Future<void> forget(String verifierId) async {}
}

PairingRecord record(String credentialId, CredentialPurpose purpose) =>
    PairingRecord(
      verifierId: 'desk-1',
      verifierIdentitySpki: Uint8List.fromList(List<int>.filled(91, 1)),
      endpoint: '127.0.0.1:1',
      credentialId: credentialId,
      keyKind: KeyKind.strongBox,
      purpose: purpose,
      pairedAt: DateTime.utc(2026, 9, 1),
    );

void main() {
  PermissionController controllerFor(_Permissions permissions) =>
      PermissionController(
        pairings: _Pairings([
          record('cred-login', CredentialPurpose.authorization),
          record('cred-vault', CredentialPurpose.vault),
        ]),
        permissions: permissions,
        verifierId: 'desk-1',
      );

  test('lista uma linha por credencial deste computador', () async {
    final controller = controllerFor(_Permissions());
    await controller.load();

    expect(controller.loading, isFalse);
    expect(controller.credentials.map((entry) => entry.credentialId), [
      'cred-login',
      'cred-vault',
    ]);
    expect(controller.credentials.first.services, isEmpty);
  });

  test('conceder grava o conjunto inteiro daquela credencial', () async {
    final permissions = _Permissions();
    final controller = controllerFor(permissions);
    await controller.load();

    await controller.toggle('cred-login', 'sudo', true);
    await controller.toggle('cred-login', 'login', true);

    final stored = permissions.entries['desk-1 cred-login']!;
    expect(stored.permissions.map((permission) => permission.service).toSet(), {
      'sudo',
      'login',
    });
    // O outro conjunto não foi tocado: a chave é verificador + credencial.
    expect(permissions.entries['desk-1 cred-vault'], isNull);
  });

  /// O mesmo motivo do lado do computador, e o que faz esta tela ser segura:
  /// tirar uma concessão deixa um conjunto *menor*. Se a revisão ficasse
  /// parada, a próxima reconciliação perderia para a cópia mais antiga e mais
  /// ampla do computador — e o poder recém-tirado voltaria sozinho, vindo do
  /// aparelho de onde acabou de ser removido.
  test('tirar uma concessão sobe a revisão como qualquer edição', () async {
    final permissions = _Permissions();
    final controller = controllerFor(permissions);
    await controller.load();

    await controller.toggle('cred-login', 'sudo', true);
    expect(permissions.entries['desk-1 cred-login']!.revision, 1);

    await controller.toggle('cred-login', 'sudo', false);
    final after = permissions.entries['desk-1 cred-login']!;
    expect(after.permissions, isEmpty);
    expect(
      after.revision,
      2,
      reason: 'a revogação ficou numa revisão que o conjunto antigo vence',
    );
  });

  /// Todo campo além de `service` sai como `*`. Vazio ali não é coringa do
  /// lado que aplica, é um valor que nada casa — e o payload recusaria.
  test('os campos que não são serviço saem como coringa', () async {
    final permissions = _Permissions();
    final controller = controllerFor(permissions);
    await controller.load();

    await controller.toggle('cred-vault', 'vault', true);

    final grant = permissions.entries['desk-1 cred-vault']!.permissions.single;
    expect(grant.action, permissionWildcard);
    expect(grant.resource, permissionWildcard);
    expect(grant.user, permissionWildcard);
    expect(grant.isValid, isTrue);
  });

  test('uma gravação que falha aparece na tela e não muda a lista', () async {
    final permissions = _Permissions()..failWith = StateError('disco cheio');
    final controller = controllerFor(permissions);
    await controller.load();

    await controller.toggle('cred-login', 'sudo', true);

    expect(controller.failure, contains('disco cheio'));
    expect(controller.credentials.first.services, isEmpty);
  });
}
