/// Os payloads de `permissions.sync` e a regra que decide quem vence.
///
/// O que um pareamento pode autorizar sempre foi do computador, porque é ele
/// que aplica. Mudar isso exigia ir até o computador, e dar a um celular um
/// segundo conjunto de poderes exigia parear de novo. É isso que sai daqui.
///
/// O formato é decidido por algo que o transporte já resolveu: **o celular
/// nunca inicia**. Toda operação deste protocolo é o computador perguntando e
/// o celular respondendo. Um celular que editasse as próprias permissões não
/// teria por onde avisar.
///
/// Então não são duas escritas, é uma reconciliação: o computador manda o que
/// acredita, este lado responde o que vale, e os dois desligam concordando.
///
/// A regra tem duas linhas de propósito. Ela existe duas vezes — aqui e em
/// `phone_auth_protocol::permissions` — e regra que precisa de parágrafo é
/// regra que as duas cópias acabam divergindo:
///
///   1. Revisão maior vence.
///   2. No empate, vale a do celular.
///
/// A regra 2 não é cara-ou-coroa. Empate significa que os dois lados editaram
/// sem ver o outro, e das duas telas envolvidas só uma pediu digital antes de
/// deixar alguém mudar o que um aparelho pode autorizar.
///
/// Zero contra zero é a exceção, e é o caso que **todo pareamento existente
/// hoje** encontra na primeira sincronização. Os dois zeros não querem dizer a
/// mesma coisa: o do computador é "concedido pela bandeja e nunca mexido desde
/// então", o do celular é "nunca teve armazenamento de permissão nenhum".
/// Mandado ao desempate, o celular venceria com nada e sincronizar um
/// pareamento em uso o revogaria. Zero duplo vai para o computador.
library;

import 'dart:typed_data';

import 'cbor.dart';

const String permissionsSyncOperation = 'permissions.sync';

/// Versionado à parte dos outros: eles mudam por razões diferentes e prender
/// os dois juntos faria um esperar pelo outro.
const int permissionsSchema = 1;

/// Como todo campo exceto `service` escreve "qualquer valor".
const String permissionWildcard = '*';

/// Quantas concessões uma credencial pode carregar.
///
/// Quem concede sessenta e quatro poderes distintos a um celular parou de
/// descrever um pareamento e começou a descrever uma conta. E o limite é o que
/// impede uma resposta malformada de virar uma alocação.
const int maxPermissions = 64;

const int _maxFieldUnits = 255;
const int _maxNameUnits = 255;
const int _maxPayloadBytes = 64 * 1024;

/// Uma concessão: quem pode fazer o quê, em quê, como quem.
class Permission {
  const Permission({
    required this.service,
    required this.action,
    required this.resource,
    required this.user,
  });

  final String service;
  final String action;
  final String resource;
  final String user;

  /// Os quatro campos são obrigatórios e nenhum pode ser vazio.
  ///
  /// "Qualquer recurso" se escreve `*` do lado que aplica. Vazio ali não é
  /// coringa, é um valor que nada casa — uma concessão que o usuário escreveu,
  /// acredita valer, e que silenciosamente nunca se aplica.
  bool get isValid =>
      _fits(service) && _fits(action) && _fits(resource) && _fits(user);

  static bool _fits(String value) =>
      value.isNotEmpty && value.length <= _maxFieldUnits;

  void _write(CborWriter writer) {
    writer
      ..array(4)
      ..text(service)
      ..text(action)
      ..text(resource)
      ..text(user);
  }

  static Permission _read(CborReader reader) {
    if (reader.array() != 4) {
      throw const FormatException('unexpected permission structure');
    }
    return Permission(
      service: reader.text(),
      action: reader.text(),
      resource: reader.text(),
      user: reader.text(),
    );
  }

  @override
  bool operator ==(Object other) =>
      other is Permission &&
      other.service == service &&
      other.action == action &&
      other.resource == resource &&
      other.user == user;

  @override
  int get hashCode => Object.hash(service, action, resource, user);

  @override
  String toString() => '$service/$action/$resource/$user';
}

/// De quem é o conjunto que vale.
enum PermissionWinner {
  /// O conjunto de quem perguntou.
  mine,

  /// O do outro lado.
  theirs,
}

/// A regra inteira, num lugar só.
///
/// [phoneWinsTies] é o que faz disto a mesma função nos dois lados: o celular
/// chama com `true` a respeito do próprio conjunto, o computador chama com
/// `false` a respeito do dele. Nenhum dos dois tem uma segunda regra própria
/// da qual divergir.
PermissionWinner reconcile(
  int mine,
  int theirs, {
  required bool phoneWinsTies,
}) {
  // Nenhum dos lados foi editado. Primeira sincronização de um pareamento
  // anterior a esta feature — os dois zeros não significam a mesma coisa, e
  // mandar isto ao desempate revogaria um pareamento em uso.
  if (mine == 0 && theirs == 0) {
    return phoneWinsTies ? PermissionWinner.theirs : PermissionWinner.mine;
  }
  if (mine > theirs) return PermissionWinner.mine;
  if (theirs > mine) return PermissionWinner.theirs;
  return phoneWinsTies ? PermissionWinner.mine : PermissionWinner.theirs;
}

/// `permissions.sync`: o computador oferece o que acredita e pergunta o que vale.
class PermissionSyncRequest {
  const PermissionSyncRequest({
    required this.verifierName,
    required this.revision,
    required this.permissions,
  });

  /// Mostrado na tela ao lado do conjunto, para quem aprova saber de qual
  /// computador são os poderes que está olhando.
  final String verifierName;

  /// A revisão do computador. Zero significa que nunca foi editada.
  final int revision;

  final List<Permission> permissions;

  Uint8List encode() {
    if (verifierName.isEmpty || verifierName.length > _maxNameUnits) {
      throw const FormatException('invalid verifierName');
    }
    _checkSet(permissions);
    if (revision < 0) {
      throw const FormatException('invalid revision');
    }
    final writer = CborWriter()
      ..array(4)
      ..uint(permissionsSchema)
      ..text(verifierName)
      ..uint(revision)
      ..array(permissions.length);
    for (final permission in permissions) {
      permission._write(writer);
    }
    return writer.takeBytes();
  }

  static PermissionSyncRequest decode(Uint8List payload) =>
      _decode(payload, () {
        final reader = CborReader(payload);
        if (reader.array() != 4) {
          throw const FormatException('Estrutura de payload inesperada');
        }
        if (reader.uint() != permissionsSchema) {
          throw const FormatException('unsupported permission schema version');
        }
        final decoded = PermissionSyncRequest(
          verifierName: reader.text(),
          revision: reader.uint(),
          permissions: _readSet(reader),
        );
        reader.finish();
        _checkCanonical(decoded.encode(), payload);
        return decoded;
      });
}

/// A resposta do celular: o conjunto que vale, e em que revisão ele vale.
///
/// Sempre o conjunto inteiro, nunca um diff e nunca "sem mudança". O
/// computador guarda o que volta literalmente, então uma resposta que ele não
/// entenda só pode virar uma chamada recusada — e não um pareamento
/// atualizado pela metade.
class PermissionSyncResponse {
  const PermissionSyncResponse({
    required this.revision,
    required this.permissions,
  });

  final int revision;
  final List<Permission> permissions;

  Uint8List encode() {
    _checkSet(permissions);
    if (revision < 0) {
      throw const FormatException('invalid revision');
    }
    final writer = CborWriter()
      ..array(3)
      ..uint(permissionsSchema)
      ..uint(revision)
      ..array(permissions.length);
    for (final permission in permissions) {
      permission._write(writer);
    }
    return writer.takeBytes();
  }

  static PermissionSyncResponse decode(Uint8List payload) =>
      _decode(payload, () {
        final reader = CborReader(payload);
        if (reader.array() != 3) {
          throw const FormatException('Estrutura de payload inesperada');
        }
        if (reader.uint() != permissionsSchema) {
          throw const FormatException('unsupported permission schema version');
        }
        final decoded = PermissionSyncResponse(
          revision: reader.uint(),
          permissions: _readSet(reader),
        );
        reader.finish();
        _checkCanonical(decoded.encode(), payload);
        return decoded;
      });
}

List<Permission> _readSet(CborReader reader) {
  final count = reader.array();
  // Conferido antes de alocar: o comprimento é escolhido pelo outro lado, e
  // reservar espaço por ele é a negação de serviço inteira.
  if (count > maxPermissions) {
    throw const FormatException('permission set too large');
  }
  final permissions = <Permission>[];
  for (var index = 0; index < count; index++) {
    permissions.add(Permission._read(reader));
  }
  return permissions;
}

void _checkSet(List<Permission> permissions) {
  if (permissions.length > maxPermissions) {
    throw const FormatException('permission set too large');
  }
  for (final permission in permissions) {
    if (!permission.isValid) {
      throw FormatException('invalid permission: $permission');
    }
  }
}

void _checkCanonical(Uint8List reencoded, Uint8List payload) {
  // Recodificar e comparar é o que todo payload aqui faz: duas cadeias de
  // bytes com o mesmo significado seriam duas requisições que uma aprovação
  // cobre.
  if (reencoded.length != payload.length) {
    throw const FormatException('non-canonical payload');
  }
  for (var index = 0; index < reencoded.length; index++) {
    if (reencoded[index] != payload[index]) {
      throw const FormatException('non-canonical payload');
    }
  }
}

T _decode<T>(Uint8List payload, T Function() read) {
  if (payload.isEmpty || payload.length > _maxPayloadBytes) {
    throw const FormatException('invalid permission payload length');
  }
  try {
    return read();
  } on CborException catch (error) {
    throw FormatException(error.message);
  }
}
