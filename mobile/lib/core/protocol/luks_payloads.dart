/// Payloads do esquema dedicado de wrapping LUKS.
library;

import 'dart:typed_data';

import 'cbor.dart';

const String luksEnrollOperation = 'luks.enroll';
const String luksUnlockOperation = 'luks.unlock';
const int luksSchema = 1;
const int luksDiskKeyLength = 32;
const int luksVolumeBindingLength = 32;
const int luksMaxWrapperBytes = 512;
const int _maxNameLength = 255;
const int _maxIdLength = 64;
const int _maxPayloadBytes = 6 * 1024;

class LuksEnrollRequest {
  LuksEnrollRequest({
    required this.verifierName,
    required this.volumeName,
    required List<int> volumeBinding,
    required List<int> diskKey,
  }) : volumeBinding = Uint8List.fromList(volumeBinding),
       diskKey = Uint8List.fromList(diskKey);
  final String verifierName;
  final String volumeName;
  final Uint8List volumeBinding;
  final Uint8List diskKey;
  void validate() {
    _names(verifierName, volumeName);
    _binding(volumeBinding);
    _key(diskKey);
  }

  Uint8List encode() {
    validate();
    return (CborWriter()
          ..array(5)
          ..uint(luksSchema)
          ..text(verifierName)
          ..text(volumeName)
          ..bytes(volumeBinding)
          ..bytes(diskKey))
        .takeBytes();
  }

  static LuksEnrollRequest decode(Uint8List payload) => _decode(
    payload,
    5,
    (r) => LuksEnrollRequest(
      verifierName: r.text(),
      volumeName: r.text(),
      volumeBinding: r.bytes(),
      diskKey: r.bytes(),
    ),
    (v) => v.encode(),
  );
}

class LuksEnrollResponse {
  LuksEnrollResponse({required this.credentialId, required List<int> wrapper})
    : wrapper = Uint8List.fromList(wrapper);
  final String credentialId;
  final Uint8List wrapper;
  void validate() {
    _id(credentialId);
    _wrapper(wrapper);
  }

  Uint8List encode() {
    validate();
    return (CborWriter()
          ..array(3)
          ..uint(luksSchema)
          ..text(credentialId)
          ..bytes(wrapper))
        .takeBytes();
  }

  static LuksEnrollResponse decode(Uint8List payload) => _decode(
    payload,
    3,
    (r) => LuksEnrollResponse(credentialId: r.text(), wrapper: r.bytes()),
    (v) => v.encode(),
  );
}

class LuksUnlockRequest {
  LuksUnlockRequest({
    required this.verifierName,
    required this.volumeName,
    required List<int> volumeBinding,
    required this.credentialId,
    required List<int> wrapper,
  }) : volumeBinding = Uint8List.fromList(volumeBinding),
       wrapper = Uint8List.fromList(wrapper);
  final String verifierName;
  final String volumeName;
  final Uint8List volumeBinding;
  final String credentialId;
  final Uint8List wrapper;
  void validate() {
    _names(verifierName, volumeName);
    _binding(volumeBinding);
    _id(credentialId);
    _wrapper(wrapper);
  }

  Uint8List encode() {
    validate();
    return (CborWriter()
          ..array(6)
          ..uint(luksSchema)
          ..text(verifierName)
          ..text(volumeName)
          ..bytes(volumeBinding)
          ..text(credentialId)
          ..bytes(wrapper))
        .takeBytes();
  }

  static LuksUnlockRequest decode(Uint8List payload) => _decode(
    payload,
    6,
    (r) => LuksUnlockRequest(
      verifierName: r.text(),
      volumeName: r.text(),
      volumeBinding: r.bytes(),
      credentialId: r.text(),
      wrapper: r.bytes(),
    ),
    (v) => v.encode(),
  );
}

class LuksUnlockResponse {
  LuksUnlockResponse({required List<int> diskKey})
    : diskKey = Uint8List.fromList(diskKey);
  final Uint8List diskKey;
  void validate() => _key(diskKey);
  Uint8List encode() {
    validate();
    return (CborWriter()
          ..array(2)
          ..uint(luksSchema)
          ..bytes(diskKey))
        .takeBytes();
  }

  static LuksUnlockResponse decode(Uint8List payload) => _decode(
    payload,
    2,
    (r) => LuksUnlockResponse(diskKey: r.bytes()),
    (v) => v.encode(),
  );
}

T _decode<T>(
  Uint8List payload,
  int fields,
  T Function(CborReader) read,
  Uint8List Function(T) encode,
) {
  if (payload.isEmpty || payload.length > _maxPayloadBytes) {
    throw const FormatException('invalid LUKS payload');
  }
  try {
    final reader = CborReader(payload);
    if (reader.array() != fields) {
      throw const FormatException('Estrutura LUKS inesperada');
    }
    if (reader.uint() != luksSchema) {
      throw const FormatException('unsupported LUKS schema');
    }
    final value = read(reader);
    reader.finish();
    final canonical = encode(value);
    if (canonical.length != payload.length) {
      throw const FormatException('non-canonical LUKS payload');
    }
    for (var i = 0; i < payload.length; i++) {
      if (canonical[i] != payload[i]) {
        throw const FormatException('non-canonical LUKS payload');
      }
    }
    return value;
  } on CborException catch (error) {
    throw FormatException(error.message);
  }
}

void _names(String verifier, String volume) {
  if (verifier.trim().isEmpty ||
      verifier.length > _maxNameLength ||
      volume.trim().isEmpty ||
      volume.length > _maxNameLength) {
    throw const FormatException('invalid LUKS name');
  }
}

void _binding(Uint8List value) {
  if (value.length != luksVolumeBindingLength) {
    throw const FormatException('invalid LUKS binding');
  }
}

void _key(Uint8List value) {
  if (value.length != luksDiskKeyLength) {
    throw const FormatException('invalid LUKS key');
  }
}

void _id(String value) {
  if (value.trim().isEmpty || value.length > _maxIdLength) {
    throw const FormatException('invalid LUKS credential');
  }
}

void _wrapper(Uint8List value) {
  if (value.isEmpty || value.length > luksMaxWrapperBytes) {
    throw const FormatException('invalid LUKS wrapper');
  }
}
