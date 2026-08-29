/// The `ssh.sign` payloads, and the check that keeps them safe.
///
/// `SYS-02`. The desktop asks the phone to sign bytes the desktop chose, with
/// a key the desktop cannot otherwise reach. That is the most powerful request
/// in this protocol, and what stops it being a blind signing oracle is
/// [accountInRequest]: the phone reads the blob itself and signs nothing it
/// cannot name an account for.
///
/// The desktop's own reading is used only to draw a prompt. This one decides.
/// It is the same rule as the vault's approval sheet, for the same reason — a
/// caller that could describe its own request would describe it favourably.
library;

import 'dart:typed_data';

import 'cbor.dart';

const String sshSignOperation = 'ssh.sign';

/// Versioned separately from the vault's schema: the two change for different
/// reasons and pinning them together would make one wait for the other.
const int sshSchema = 1;

/// A P-256 signature, `r || s`.
const int sshSignatureLength = 64;

/// The largest blob worth signing. A userauth request is a few hundred bytes.
const int maxSshSignDataBytes = 2048;

/// SSH_MSG_USERAUTH_REQUEST, RFC 4252.
const int _userauthRequest = 50;

class SshSignRequest {
  const SshSignRequest({
    required this.verifierName,
    required this.destination,
    required this.data,
  });

  /// The computer asking, as it calls itself.
  final String verifierName;

  /// Where the computer says the connection is going.
  ///
  /// Advisory. The phone cannot check it, so the screen presents it as the
  /// computer's claim rather than as a fact — the same treatment
  /// `verifierName` gets on the vault sheet.
  final String destination;

  final Uint8List data;

  Uint8List encode() {
    if (verifierName.isEmpty || verifierName.length > 64) {
      throw const FormatException('verifierName inválido');
    }
    if (destination.length > 128) {
      throw const FormatException('destination inválido');
    }
    if (data.isEmpty || data.length > maxSshSignDataBytes) {
      throw const FormatException('data inválido');
    }
    return (CborWriter()
          ..array(4)
          ..uint(sshSchema)
          ..text(verifierName)
          ..text(destination)
          ..bytes(data))
        .takeBytes();
  }

  static SshSignRequest decode(Uint8List payload) => _decode(payload, () {
    final reader = CborReader(payload);
    if (reader.array() != 4) {
      throw const FormatException('Estrutura de payload inesperada');
    }
    if (reader.uint() != sshSchema) {
      throw const FormatException('Versão de schema ssh não suportada');
    }
    final decoded = SshSignRequest(
      verifierName: reader.text(),
      destination: reader.text(),
      data: reader.bytes(),
    );
    reader.finish();
    // Re-encoding and comparing is what every payload here does: two byte
    // strings that mean the same thing would be two requests one approval
    // covers.
    final reencoded = decoded.encode();
    if (reencoded.length != payload.length) {
      throw const FormatException('Payload não canônico');
    }
    for (var index = 0; index < reencoded.length; index++) {
      if (reencoded[index] != payload[index]) {
        throw const FormatException('Payload não canônico');
      }
    }
    return decoded;
  });
}

class SshSignResponse {
  const SshSignResponse({required this.signature});

  final Uint8List signature;

  Uint8List encode() {
    if (signature.length != sshSignatureLength) {
      throw const FormatException('Assinatura de tamanho inválido');
    }
    return (CborWriter()
          ..array(2)
          ..uint(sshSchema)
          ..bytes(signature))
        .takeBytes();
  }

  static SshSignResponse decode(Uint8List payload) => _decode(payload, () {
    final reader = CborReader(payload);
    if (reader.array() != 2) {
      throw const FormatException('Estrutura de payload inesperada');
    }
    if (reader.uint() != sshSchema) {
      throw const FormatException('Versão de schema ssh não suportada');
    }
    final decoded = SshSignResponse(signature: reader.bytes());
    reader.finish();
    if (decoded.signature.length != sshSignatureLength) {
      throw const FormatException('Assinatura de tamanho inválido');
    }
    return decoded;
  });
}

/// Turns a CBOR failure into the `FormatException` every decoder in this
/// project raises.
///
/// Two exception types for the same class of malformed input would mean a
/// caller catching one and being surprised by the other, which is how a
/// malformed frame becomes a crash instead of a refusal.
T _decode<T>(Uint8List payload, T Function() read) {
  if (payload.isEmpty || payload.length > maxSshSignDataBytes * 2) {
    throw const FormatException('Payload ssh com tamanho inválido');
  }
  try {
    return read();
  } on CborException catch (error) {
    throw FormatException(error.message);
  }
}

/// The account and service an SSH authentication request is for.
///
/// Returns null when the bytes are not a `publickey` userauth request, and
/// that null is the whole security property: the phone signs nothing it cannot
/// name an account for, so `ssh.sign` cannot be pointed at arbitrary bytes.
///
/// Reads SSH's own framing rather than CBOR — this is a blob OpenSSH built.
({String user, String service})? accountInRequest(Uint8List data) {
  var position = 0;

  Uint8List? string() {
    if (position + 4 > data.length) return null;
    final length =
        (data[position] << 24) |
        (data[position + 1] << 16) |
        (data[position + 2] << 8) |
        data[position + 3];
    position += 4;
    // A length is a number whoever built this blob chose. Checked against what
    // is actually here before any slice.
    if (length < 0 || position + length > data.length) return null;
    final slice = Uint8List.sublistView(data, position, position + length);
    position += length;
    return slice;
  }

  String? text() {
    final bytes = string();
    if (bytes == null) return null;
    try {
      return String.fromCharCodes(bytes);
    } on Object {
      return null;
    }
  }

  if (string() == null) return null; // session identifier
  if (position >= data.length || data[position] != _userauthRequest) {
    return null;
  }
  position += 1;

  final user = text();
  final service = text();
  final method = text();
  if (user == null || service == null || method != 'publickey') return null;
  if (user.isEmpty) return null;
  return (user: user, service: service);
}
