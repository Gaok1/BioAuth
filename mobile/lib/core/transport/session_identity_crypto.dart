import 'dart:typed_data';

import 'package:phone_auth_native/phone_auth_native.dart';

abstract interface class SessionIdentityCrypto {
  Future<Uint8List> publicKey();

  Future<Uint8List> sign(Uint8List transcript);

  Future<bool> verify({
    required Uint8List publicKey,
    required Uint8List transcript,
    required Uint8List signature,
  });
}

class NativeSessionIdentityCrypto implements SessionIdentityCrypto {
  NativeSessionIdentityCrypto({SessionIdentity? identity})
    : _identity = identity ?? const PhoneAuthNative();

  final SessionIdentity _identity;

  @override
  Future<Uint8List> publicKey() async {
    try {
      return (await _identity.getSessionIdentityPublicKey()).bytes;
    } on Object {
      return (await _identity.generateSessionIdentityKey()).bytes;
    }
  }

  @override
  Future<Uint8List> sign(Uint8List transcript) async =>
      (await _identity.signSessionIdentity(transcript)).signature;

  @override
  Future<bool> verify({
    required Uint8List publicKey,
    required Uint8List transcript,
    required Uint8List signature,
  }) => _identity.verifySessionIdentity(
    publicKey: publicKey,
    transcript: transcript,
    signature: signature,
  );
}
