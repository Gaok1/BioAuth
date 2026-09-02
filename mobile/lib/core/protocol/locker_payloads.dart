/// Payloads das três operações do File Locker, transportadas dentro de um
/// [ApplicationFrame] no canal seguro.
///
/// O formato é espelho exato de `desktop/crates/phone-auth-protocol/src/locker.rs`
/// e o vetor compartilhado vive em `mobile/test/locker_payloads_test.dart`.
/// Mudar um lado sem o outro quebra o vetor, que é exatamente o objetivo.
///
/// Nenhuma classe aqui tem `toString`: duas delas carregam a chave de dados de
/// um container.
library;

import 'dart:typed_data';

import 'cbor.dart';

/// Pedir ao telefone para embrulhar a chave de um locker novo.
const String lockerCreateOperation = 'locker.create';

/// Pedir ao telefone para desembrulhar a chave de um locker existente.
const String lockerUnlockOperation = 'locker.unlock';

/// Desembrulhar para trocar a chave do container. É uma operação separada do
/// unlock para que o telefone diga ao usuário o que realmente vai acontecer.
const String lockerRekeyOperation = 'locker.rekey';

/// Único schema que esta versão fala. Schema desconhecido falha fechado.
const int lockerSchema = 1;

/// Tamanho da chave de dados de um locker.
const int lockerDataKeyLength = 32;

/// Maior blob embrulhado que o telefone pode devolver.
const int lockerMaxWrapperBytes = 512;

const int _maxNameLength = 255;
const int _maxIdLength = 64;
const int _bindingLength = 32;

/// `locker.create`: o computador entrega uma chave nova para ser embrulhada.
class LockerWrapRequest {
  LockerWrapRequest({
    required this.verifierName,
    required this.fileName,
    required this.plaintextLength,
    required List<int> containerBinding,
    required List<int> dataKey,
  }) : containerBinding = Uint8List.fromList(containerBinding),
       dataKey = Uint8List.fromList(dataKey);

  static const _fields = 6;

  final String verifierName;

  /// Mostrado no telefone antes do prompt biométrico.
  final String fileName;
  final int plaintextLength;

  /// Binding do container. A tag do próprio telefone cobre este valor, então
  /// uma aprovação para um container não vale para outro.
  final Uint8List containerBinding;
  final Uint8List dataKey;

  void validate() {
    _checkName('verifierName', verifierName);
    _checkName('fileName', fileName);
    if (containerBinding.length != _bindingLength) {
      throw const FormatException('invalid containerBinding');
    }
    if (dataKey.length != lockerDataKeyLength) {
      throw const FormatException('invalid dataKey');
    }
    if (plaintextLength < 0) {
      throw const FormatException('invalid plaintextLength');
    }
  }

  Uint8List encode() {
    validate();
    final writer = CborWriter()
      ..array(_fields)
      ..uint(lockerSchema)
      ..text(verifierName)
      ..text(fileName)
      ..uint(plaintextLength)
      ..bytes(containerBinding)
      ..bytes(dataKey);
    return writer.takeBytes();
  }

  static LockerWrapRequest decode(Uint8List payload) {
    return _decode(payload, _fields, (reader) {
      return LockerWrapRequest(
        verifierName: reader.text(),
        fileName: reader.text(),
        plaintextLength: reader.uint(),
        containerBinding: reader.bytes(),
        dataKey: reader.bytes(),
      );
    }, (value) => value.encode());
  }
}

/// Resposta do telefone ao `locker.create`.
class LockerWrapResponse {
  LockerWrapResponse({required this.credentialId, required List<int> wrapper})
    : wrapper = Uint8List.fromList(wrapper);

  static const _fields = 3;

  final String credentialId;

  /// Opaco para o computador, que só guarda e devolve.
  final Uint8List wrapper;

  void validate() {
    _checkId('credentialId', credentialId);
    _checkWrapper(wrapper);
  }

  Uint8List encode() {
    validate();
    final writer = CborWriter()
      ..array(_fields)
      ..uint(lockerSchema)
      ..text(credentialId)
      ..bytes(wrapper);
    return writer.takeBytes();
  }

  static LockerWrapResponse decode(Uint8List payload) {
    return _decode(payload, _fields, (reader) {
      return LockerWrapResponse(
        credentialId: reader.text(),
        wrapper: reader.bytes(),
      );
    }, (value) => value.encode());
  }
}

/// `locker.unlock` e `locker.rekey`: o computador devolve a chave embrulhada.
class LockerUnwrapRequest {
  LockerUnwrapRequest({
    required this.verifierName,
    required this.fileName,
    required this.plaintextLength,
    required List<int> containerBinding,
    required this.credentialId,
    required List<int> wrapper,
  }) : containerBinding = Uint8List.fromList(containerBinding),
       wrapper = Uint8List.fromList(wrapper);

  static const _fields = 7;

  final String verifierName;

  /// Nome do container, não o nome cifrado lá dentro: o computador só descobre
  /// esse depois que este pedido der certo.
  final String fileName;
  final int plaintextLength;
  final Uint8List containerBinding;
  final String credentialId;
  final Uint8List wrapper;

  void validate() {
    _checkName('verifierName', verifierName);
    _checkName('fileName', fileName);
    _checkId('credentialId', credentialId);
    if (containerBinding.length != _bindingLength) {
      throw const FormatException('invalid containerBinding');
    }
    _checkWrapper(wrapper);
    if (plaintextLength < 0) {
      throw const FormatException('invalid plaintextLength');
    }
  }

  Uint8List encode() {
    validate();
    final writer = CborWriter()
      ..array(_fields)
      ..uint(lockerSchema)
      ..text(verifierName)
      ..text(fileName)
      ..uint(plaintextLength)
      ..bytes(containerBinding)
      ..text(credentialId)
      ..bytes(wrapper);
    return writer.takeBytes();
  }

  static LockerUnwrapRequest decode(Uint8List payload) {
    return _decode(payload, _fields, (reader) {
      return LockerUnwrapRequest(
        verifierName: reader.text(),
        fileName: reader.text(),
        plaintextLength: reader.uint(),
        containerBinding: reader.bytes(),
        credentialId: reader.text(),
        wrapper: reader.bytes(),
      );
    }, (value) => value.encode());
  }
}

/// Resposta do telefone ao `locker.unlock` ou `locker.rekey`.
class LockerUnwrapResponse {
  LockerUnwrapResponse({required List<int> dataKey})
    : dataKey = Uint8List.fromList(dataKey);

  static const _fields = 2;

  final Uint8List dataKey;

  void validate() {
    if (dataKey.length != lockerDataKeyLength) {
      throw const FormatException('invalid dataKey');
    }
  }

  Uint8List encode() {
    validate();
    final writer = CborWriter()
      ..array(_fields)
      ..uint(lockerSchema)
      ..bytes(dataKey);
    return writer.takeBytes();
  }

  static LockerUnwrapResponse decode(Uint8List payload) {
    return _decode(payload, _fields, (reader) {
      return LockerUnwrapResponse(dataKey: reader.bytes());
    }, (value) => value.encode());
  }
}

/// Frente e verso compartilhados de todo decode: limites, forma, schema,
/// nada sobrando e uma única grafia por valor.
T _decode<T>(
  Uint8List payload,
  int fields,
  T Function(CborReader reader) read,
  Uint8List Function(T value) encode,
) {
  if (payload.isEmpty || payload.length > maxLockerPayloadBytes) {
    throw const FormatException('invalid locker payload length');
  }
  try {
    final reader = CborReader(payload);
    if (reader.array() != fields) {
      throw const FormatException('Estrutura de payload inesperada');
    }
    if (reader.uint() != lockerSchema) {
      throw const FormatException('unsupported locker schema');
    }
    final decoded = read(reader);
    reader.finish();
    final reencoded = encode(decoded);
    if (reencoded.length != payload.length) {
      throw const FormatException('non-canonical locker payload');
    }
    for (var index = 0; index < payload.length; index++) {
      if (reencoded[index] != payload[index]) {
        throw const FormatException('non-canonical locker payload');
      }
    }
    return decoded;
  } on CborException catch (error) {
    throw FormatException(error.message);
  }
}

/// Espelha o limite do envelope de aplicação.
const int maxLockerPayloadBytes = 6 * 1024;

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

void _checkWrapper(Uint8List wrapper) {
  if (wrapper.isEmpty || wrapper.length > lockerMaxWrapperBytes) {
    throw const FormatException('invalid wrapper');
  }
}
