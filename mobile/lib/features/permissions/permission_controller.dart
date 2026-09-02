import 'package:flutter/foundation.dart';

import '../../core/protocol/enrolment.dart';
import '../../core/pairing/pairing_store.dart';
import '../../core/permissions/permission_store.dart';
import '../../core/protocol/permission_payloads.dart';

/// Uma credencial de um computador pareado e o que ela pode autorizar.
class CredentialPermissions {
  const CredentialPermissions({
    required this.credentialId,
    required this.purpose,
    required this.set,
  });

  final String credentialId;
  final CredentialPurpose purpose;
  final PermissionSet set;

  Set<String> get services => {
    for (final permission in set.permissions) permission.service,
  };
}

/// A tela de permissões de um computador pareado.
///
/// Edita só o que está neste celular. Não há como empurrar para o computador
/// daqui — este lado nunca inicia sessão — e não precisa: a edição sobe a
/// revisão, e a próxima vez que o computador conectar, a reconciliação entrega
/// o conjunto novo. É por isso que a tela fala em "vale a partir da próxima
/// conexão" em vez de fingir que já aplicou.
class PermissionController extends ChangeNotifier {
  PermissionController({
    required PairingStore pairings,
    required PermissionStore permissions,
    required this.verifierId,
  }) : _pairings = pairings,
       _permissions = permissions;

  /// Os serviços que uma concessão pode nomear, e como aparecem na tela.
  ///
  /// Lista fechada porque o lado que aplica compara `service` exatamente
  /// contra um vocabulário pequeno — não há coringa para ele, de propósito,
  /// já que um serviço coringa é conceder tudo.
  /// The services a person can hand out from here, in the order they are
  /// listed. The words for them live in the language packs.
  static const grantable = <String>[
    'sudo',
    'login',
    'vault',
    'locker',
    'ssh',
    'luks',
    'webauthn',
  ];

  final PairingStore _pairings;
  final PermissionStore _permissions;
  final String verifierId;

  List<CredentialPermissions> _credentials = const [];
  bool _loading = true;
  bool _disposed = false;
  bool _saveFailed = false;

  List<CredentialPermissions> get credentials => _credentials;
  bool get loading => _loading;
  bool get saveFailed => _saveFailed;

  Future<void> load() async {
    final records = await _pairings.load();
    final mine = records.where((record) => record.verifierId == verifierId);
    final loaded = <CredentialPermissions>[];
    for (final record in mine) {
      loaded.add(
        CredentialPermissions(
          credentialId: record.credentialId,
          purpose: record.purpose,
          set: await _permissions.read(verifierId, record.credentialId),
        ),
      );
    }
    if (_disposed) return;
    _credentials = List.unmodifiable(loaded);
    _loading = false;
    notifyListeners();
  }

  /// Concede ou tira um serviço de uma credencial.
  ///
  /// Grava o conjunto inteiro, como a reconciliação transmite: um conjunto é
  /// substituído, nunca mesclado, então mandar só o que mudou seria revogar o
  /// resto.
  Future<void> toggle(String credentialId, String service, bool granted) async {
    final index = _credentials.indexWhere(
      (credential) => credential.credentialId == credentialId,
    );
    if (index == -1) return;

    final current = _credentials[index];
    final services = {...current.services};
    if (granted) {
      services.add(service);
    } else {
      services.remove(service);
    }

    // A revisão sobe inclusive ao tirar. Uma revogação parada perderia a
    // próxima reconciliação para a cópia mais antiga e mais ampla do
    // computador, e o poder recém-tirado voltaria sozinho.
    final next = current.set.edited([
      for (final name in services)
        Permission(
          service: name,
          action: permissionWildcard,
          resource: permissionWildcard,
          user: permissionWildcard,
        ),
    ]);

    try {
      await _permissions.write(verifierId, credentialId, next);
    } on Object {
      if (_disposed) return;
      _saveFailed = true;
      notifyListeners();
      return;
    }
    if (_disposed) return;
    _saveFailed = false;
    _credentials = List.unmodifiable([
      for (var position = 0; position < _credentials.length; position++)
        if (position == index)
          CredentialPermissions(
            credentialId: current.credentialId,
            purpose: current.purpose,
            set: next,
          )
        else
          _credentials[position],
    ]);
    notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    super.dispose();
  }
}
