/// Payloads das cinco operações do cofre pessoal, transportadas dentro de um
/// [ApplicationFrame] no canal seguro.
///
/// O formato é espelho exato de `desktop/crates/phone-auth-protocol/src/vault.rs`
/// e o vetor compartilhado vive em `mobile/test/vault_payloads_test.dart`.
/// Mudar um lado sem o outro quebra o vetor, que é exatamente o objetivo.
///
/// Duas regras moldam tudo aqui.
///
/// A primeira é que listar e ler são operações diferentes. A lista é metadado
/// que o usuário já concordou em mostrar no computador; o fetch é um segredo,
/// liberado uma vez. Juntar as duas faria o computador guardar o cofre inteiro
/// em memória só para desenhar uma busca, que é justamente o que o desenho
/// "telefone é o cofre" existe para evitar.
///
/// A segunda é revisão otimista. Todo item carrega uma revisão, e update ou
/// delete precisam dizer qual revisão acreditam estar substituindo. Dois
/// computadores pareados no mesmo telefone não é hipótese, e um cofre
/// last-writer-wins engole uma troca de senha em silêncio.
///
/// Nenhuma classe que carrega segredo tem `toString`.
library;

import 'dart:typed_data';

import 'cbor.dart';

/// Pedir ao telefone uma página de metadados. Nenhum segredo atravessa.
const String vaultListOperation = 'vault.list';

/// Pedir ao telefone o segredo de exatamente um item. Exige biometria.
const String vaultFetchOperation = 'vault.fetch';

/// Guardar um item novo.
const String vaultCreateOperation = 'vault.create';

/// Substituir um item, dizendo qual revisão está sendo substituída.
const String vaultUpdateOperation = 'vault.update';

/// Remover um item, dizendo qual revisão está sendo removida.
const String vaultDeleteOperation = 'vault.delete';

/// Único schema que esta versão fala. Schema desconhecido falha fechado.
const int vaultSchema = 1;

/// Espelha o limite do envelope de aplicação.
const int maxVaultPayloadBytes = 6 * 1024;

/// Máximo de resumos que uma página de `vault.list` pode carregar.
///
/// O limite real é [maxVaultPayloadBytes], conferido depois de codificar. Esta
/// contagem existe para o telefone parar de montar a página antes de gastar
/// trabalho com resumos que teria de descartar, e para que uma resposta hostil
/// não faça o computador alocar uma lista enorme antes da checagem de tamanho.
const int vaultMaxPageItems = 32;

const int _maxIdLength = 64;
const int _maxNameLength = 255;
const int _maxUsernameLength = 255;
const int _maxUriLength = 1024;
const int _maxCursorLength = 128;

/// Limita a senha de um login ou o corpo de uma nota segura.
const int _maxSecretLength = 4096;

/// O que um item é.
///
/// Duas variantes, conforme `DEC-05`: logins e notas seguras. Cartões,
/// identidades e anexos ficam de fora até a threat model ser revisitada, e
/// acrescentar variante é mudança de schema nos dois lados.
enum VaultItemKind {
  login(0),
  note(1),

  /// A TOTP seed. The stored secret is the base32 key; the digits are derived
  /// on the phone and never stored.
  totp(2);

  const VaultItemKind(this.wire);

  final int wire;

  static VaultItemKind fromWire(int value) {
    for (final kind in VaultItemKind.values) {
      if (kind.wire == value) return kind;
    }
    throw FormatException('Tipo de item desconhecido: $value');
  }
}

/// Uma linha da lista do computador. Não carrega segredo.
///
/// `username` e `uri` são vazios numa nota, e vazio também é legítimo num
/// login: muito login não tem URL que valha registrar. Por isso usam
/// [_checkOptional] e não a regra de não-vazio.
class VaultItemSummary {
  VaultItemSummary({
    required this.id,
    required this.revision,
    required this.kind,
    required this.name,
    required this.username,
    required this.uri,
    required this.updatedAtMs,
  });

  static const fields = 7;

  /// Opaco e estável. O computador nunca deriva significado dele.
  final String id;
  final int revision;
  final VaultItemKind kind;
  final String name;
  final String username;
  final String uri;
  final int updatedAtMs;

  void validate() {
    _checkId('itemId', id);
    _checkName('name', name);
    _checkOptional('username', username, _maxUsernameLength);
    _checkOptional('uri', uri, _maxUriLength);
    _checkRevision(revision);
  }

  void write(CborWriter writer) {
    writer
      ..array(fields)
      ..text(id)
      ..uint(revision)
      ..uint(kind.wire)
      ..text(name)
      ..text(username)
      ..text(uri)
      ..int64(updatedAtMs);
  }

  static VaultItemSummary read(CborReader reader) {
    if (reader.array() != fields) {
      throw const FormatException('Estrutura de resumo inesperada');
    }
    return VaultItemSummary(
      id: reader.text(),
      revision: reader.uint(),
      kind: VaultItemKind.fromWire(reader.uint()),
      name: reader.text(),
      username: reader.text(),
      uri: reader.text(),
      updatedAtMs: reader.int64(),
    );
  }

  @override
  bool operator ==(Object other) =>
      other is VaultItemSummary &&
      other.id == id &&
      other.revision == revision &&
      other.kind == kind &&
      other.name == name &&
      other.username == username &&
      other.uri == uri &&
      other.updatedAtMs == updatedAtMs;

  @override
  int get hashCode =>
      Object.hash(id, revision, kind, name, username, uri, updatedAtMs);
}

/// `vault.list`: o computador pede uma página de metadados.
class VaultListRequest {
  VaultListRequest({required this.verifierName, this.cursor = ''});

  static const _fields = 3;

  final String verifierName;

  /// Vazio começa na primeira página; qualquer outra coisa é o cursor que uma
  /// [VaultListResponse] anterior devolveu.
  final String cursor;

  void validate() {
    _checkName('verifierName', verifierName);
    _checkOptional('cursor', cursor, _maxCursorLength);
  }

  Uint8List encode() {
    validate();
    final writer = CborWriter()
      ..array(_fields)
      ..uint(vaultSchema)
      ..text(verifierName)
      ..text(cursor);
    return _sized(writer.takeBytes());
  }

  static VaultListRequest decode(Uint8List payload) {
    return _decode(
      payload,
      _fields,
      (reader) =>
          VaultListRequest(verifierName: reader.text(), cursor: reader.text()),
      (value) => value.encode(),
    );
  }
}

/// Resposta do telefone ao `vault.list`.
class VaultListResponse {
  VaultListResponse({required this.items, this.nextCursor = ''});

  static const _fields = 3;

  final List<VaultItemSummary> items;

  /// Vazio quer dizer última página. Qualquer outra coisa é opaca para o
  /// computador e precisa voltar igual.
  final String nextCursor;

  void validate() {
    if (items.length > vaultMaxPageItems) {
      throw const FormatException('vault page too large');
    }
    for (final item in items) {
      item.validate();
    }
    _checkOptional('nextCursor', nextCursor, _maxCursorLength);
  }

  Uint8List encode() {
    validate();
    final writer = CborWriter()
      ..array(_fields)
      ..uint(vaultSchema)
      ..array(items.length);
    for (final item in items) {
      item.write(writer);
    }
    writer.text(nextCursor);
    // A checagem de tamanho mora aqui e não em [validate] porque ela precisa
    // dos bytes: chamar `encode` de dentro de `validate` seria recursão.
    return _sized(writer.takeBytes());
  }

  static VaultListResponse decode(Uint8List payload) {
    return _decode(payload, _fields, (reader) {
      final count = reader.array();
      // Conferido antes de alocar: o prefixo de tamanho vem de fora e confiar
      // nele seria a negação de serviço inteira.
      if (count > vaultMaxPageItems) {
        throw const FormatException('vault page too large');
      }
      final items = <VaultItemSummary>[
        for (var index = 0; index < count; index++)
          VaultItemSummary.read(reader),
      ];
      return VaultListResponse(items: items, nextCursor: reader.text());
    }, (value) => value.encode());
  }
}

/// `vault.fetch`: o computador pede o segredo de exatamente um item.
class VaultFetchRequest {
  VaultFetchRequest({required this.verifierName, required this.itemId});

  static const _fields = 3;

  final String verifierName;
  final String itemId;

  void validate() {
    _checkName('verifierName', verifierName);
    _checkId('itemId', itemId);
  }

  Uint8List encode() {
    validate();
    final writer = CborWriter()
      ..array(_fields)
      ..uint(vaultSchema)
      ..text(verifierName)
      ..text(itemId);
    return _sized(writer.takeBytes());
  }

  static VaultFetchRequest decode(Uint8List payload) {
    return _decode(
      payload,
      _fields,
      (reader) =>
          VaultFetchRequest(verifierName: reader.text(), itemId: reader.text()),
      (value) => value.encode(),
    );
  }
}

/// Resposta do telefone ao `vault.fetch`: o único segredo aprovado.
///
/// A revisão viaja junto para o computador saber que o valor que vai para a
/// área de transferência é o da linha que o usuário clicou, e não o de uma
/// versão editada em outro aparelho no meio do caminho.
class VaultFetchResponse {
  VaultFetchResponse({
    required this.itemId,
    required this.revision,
    required this.secret,
  });

  static const _fields = 4;

  final String itemId;
  final int revision;

  /// A senha de um login ou o corpo de uma nota.
  final String secret;

  void validate() {
    _checkId('itemId', itemId);
    _checkRevision(revision);
    _checkSecret(secret);
  }

  Uint8List encode() {
    validate();
    final writer = CborWriter()
      ..array(_fields)
      ..uint(vaultSchema)
      ..text(itemId)
      ..uint(revision)
      ..text(secret);
    return _sized(writer.takeBytes());
  }

  static VaultFetchResponse decode(Uint8List payload) {
    return _decode(
      payload,
      _fields,
      (reader) => VaultFetchResponse(
        itemId: reader.text(),
        revision: reader.uint(),
        secret: reader.text(),
      ),
      (value) => value.encode(),
    );
  }
}

/// `vault.create`: o computador pede para o telefone guardar um item novo.
class VaultCreateRequest {
  VaultCreateRequest({
    required this.verifierName,
    required this.kind,
    required this.name,
    this.username = '',
    this.uri = '',
    required this.secret,
  });

  static const _fields = 7;

  final String verifierName;
  final VaultItemKind kind;

  /// Mostrado no telefone antes do prompt biométrico, para o usuário aprovar
  /// algo com nome e não uma escrita opaca.
  final String name;
  final String username;
  final String uri;
  final String secret;

  void validate() {
    _checkName('verifierName', verifierName);
    _checkName('name', name);
    _checkOptional('username', username, _maxUsernameLength);
    _checkOptional('uri', uri, _maxUriLength);
    _checkSecret(secret);
  }

  Uint8List encode() {
    validate();
    final writer = CborWriter()
      ..array(_fields)
      ..uint(vaultSchema)
      ..text(verifierName)
      ..uint(kind.wire)
      ..text(name)
      ..text(username)
      ..text(uri)
      ..text(secret);
    return _sized(writer.takeBytes());
  }

  static VaultCreateRequest decode(Uint8List payload) {
    return _decode(
      payload,
      _fields,
      (reader) => VaultCreateRequest(
        verifierName: reader.text(),
        kind: VaultItemKind.fromWire(reader.uint()),
        name: reader.text(),
        username: reader.text(),
        uri: reader.text(),
        secret: reader.text(),
      ),
      (value) => value.encode(),
    );
  }
}

/// `vault.update`: substitui um item, dizendo qual revisão está substituindo.
///
/// Carrega o item inteiro e não um patch. Um patch exigiria que o computador
/// guardasse o segredo anterior para saber o que não está mudando, e o ponto do
/// desenho é que ele não guarda segredo entre operações.
class VaultUpdateRequest {
  VaultUpdateRequest({
    required this.verifierName,
    required this.itemId,
    required this.expectedRevision,
    required this.kind,
    required this.name,
    this.username = '',
    this.uri = '',
    required this.secret,
  });

  static const _fields = 9;

  final String verifierName;
  final String itemId;

  /// A revisão que o computador acredita estar substituindo. Um telefone que
  /// guarda outra recusa, e o computador relê em vez de sobrescrever uma edição
  /// que nunca viu.
  final int expectedRevision;
  final VaultItemKind kind;
  final String name;
  final String username;
  final String uri;
  final String secret;

  void validate() {
    _checkName('verifierName', verifierName);
    _checkId('itemId', itemId);
    _checkRevision(expectedRevision);
    _checkName('name', name);
    _checkOptional('username', username, _maxUsernameLength);
    _checkOptional('uri', uri, _maxUriLength);
    _checkSecret(secret);
  }

  Uint8List encode() {
    validate();
    final writer = CborWriter()
      ..array(_fields)
      ..uint(vaultSchema)
      ..text(verifierName)
      ..text(itemId)
      ..uint(expectedRevision)
      ..uint(kind.wire)
      ..text(name)
      ..text(username)
      ..text(uri)
      ..text(secret);
    return _sized(writer.takeBytes());
  }

  static VaultUpdateRequest decode(Uint8List payload) {
    return _decode(
      payload,
      _fields,
      (reader) => VaultUpdateRequest(
        verifierName: reader.text(),
        itemId: reader.text(),
        expectedRevision: reader.uint(),
        kind: VaultItemKind.fromWire(reader.uint()),
        name: reader.text(),
        username: reader.text(),
        uri: reader.text(),
        secret: reader.text(),
      ),
      (value) => value.encode(),
    );
  }
}

/// Resposta do telefone ao `vault.create` e ao `vault.update`.
class VaultWriteResponse {
  VaultWriteResponse({required this.itemId, required this.revision});

  static const _fields = 3;

  final String itemId;

  /// A revisão agora guardada. Sempre maior que a substituída.
  final int revision;

  void validate() {
    _checkId('itemId', itemId);
    _checkRevision(revision);
  }

  Uint8List encode() {
    validate();
    final writer = CborWriter()
      ..array(_fields)
      ..uint(vaultSchema)
      ..text(itemId)
      ..uint(revision);
    return _sized(writer.takeBytes());
  }

  static VaultWriteResponse decode(Uint8List payload) {
    return _decode(
      payload,
      _fields,
      (reader) =>
          VaultWriteResponse(itemId: reader.text(), revision: reader.uint()),
      (value) => value.encode(),
    );
  }

  @override
  bool operator ==(Object other) =>
      other is VaultWriteResponse &&
      other.itemId == itemId &&
      other.revision == revision;

  @override
  int get hashCode => Object.hash(itemId, revision);
}

/// `vault.delete`: remove um item, dizendo qual revisão está removendo.
class VaultDeleteRequest {
  VaultDeleteRequest({
    required this.verifierName,
    required this.itemId,
    required this.expectedRevision,
  });

  static const _fields = 4;

  final String verifierName;
  final String itemId;
  final int expectedRevision;

  void validate() {
    _checkName('verifierName', verifierName);
    _checkId('itemId', itemId);
    _checkRevision(expectedRevision);
  }

  Uint8List encode() {
    validate();
    final writer = CborWriter()
      ..array(_fields)
      ..uint(vaultSchema)
      ..text(verifierName)
      ..text(itemId)
      ..uint(expectedRevision);
    return _sized(writer.takeBytes());
  }

  static VaultDeleteRequest decode(Uint8List payload) {
    return _decode(
      payload,
      _fields,
      (reader) => VaultDeleteRequest(
        verifierName: reader.text(),
        itemId: reader.text(),
        expectedRevision: reader.uint(),
      ),
      (value) => value.encode(),
    );
  }
}

/// Resposta do telefone ao `vault.delete`.
class VaultDeleteResponse {
  VaultDeleteResponse({required this.itemId});

  static const _fields = 2;

  final String itemId;

  void validate() => _checkId('itemId', itemId);

  Uint8List encode() {
    validate();
    final writer = CborWriter()
      ..array(_fields)
      ..uint(vaultSchema)
      ..text(itemId);
    return _sized(writer.takeBytes());
  }

  static VaultDeleteResponse decode(Uint8List payload) {
    return _decode(
      payload,
      _fields,
      (reader) => VaultDeleteResponse(itemId: reader.text()),
      (value) => value.encode(),
    );
  }
}

T _decode<T>(
  Uint8List payload,
  int fields,
  T Function(CborReader reader) read,
  Uint8List Function(T value) encode,
) {
  if (payload.isEmpty || payload.length > maxVaultPayloadBytes) {
    throw const FormatException('invalid vault payload length');
  }
  try {
    final reader = CborReader(payload);
    if (reader.array() != fields) {
      throw const FormatException('Estrutura de payload inesperada');
    }
    if (reader.uint() != vaultSchema) {
      throw const FormatException('unsupported vault schema');
    }
    final decoded = read(reader);
    reader.finish();
    final reencoded = encode(decoded);
    if (reencoded.length != payload.length) {
      throw const FormatException('non-canonical vault payload');
    }
    for (var index = 0; index < payload.length; index++) {
      if (reencoded[index] != payload[index]) {
        throw const FormatException('non-canonical vault payload');
      }
    }
    return decoded;
  } on CborException catch (error) {
    throw FormatException(error.message);
  }
}

/// Uma página que não cabe é bug do telefone, e pegar aqui faz o erro aparecer
/// como recusa em vez de um frame que a camada de sessão descarta por tamanho.
Uint8List _sized(Uint8List payload) {
  if (payload.length > maxVaultPayloadBytes) {
    throw const FormatException('Payload de cofre grande demais');
  }
  return payload;
}

void _checkName(String field, String value) {
  if (value.trim().isEmpty || value.length > _maxNameLength) {
    throw FormatException('invalid $field');
  }
}

void _checkId(String field, String value) {
  if (value.trim().isEmpty || value.length > _maxIdLength) {
    throw FormatException('invalid $field');
  }
}

/// Limitado, mas pode ser vazio.
void _checkOptional(String field, String value, int max) {
  if (value.length > max) {
    throw FormatException('invalid $field');
  }
}

void _checkSecret(String value) {
  if (value.isEmpty || value.length > _maxSecretLength) {
    throw const FormatException('invalid secret');
  }
}

/// Revisão começa em um, então zero é sempre quem esqueceu de preencher.
void _checkRevision(int revision) {
  if (revision < 1) {
    throw const FormatException('invalid revision');
  }
}
