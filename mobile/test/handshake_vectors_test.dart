// Cross-language handshake lock, Dart side.
//
// Every constant below comes from `docs/protocol-handshake.md`, which derived
// them from the specification with an implementation independent of both the
// Rust verifier and this codec. `phone-auth-session/tests/handshake_vectors.rs`
// asserts the same values on the other side.
//
// Each of these fails on the wire with the same undiagnosable symptom — a
// decryption error with no explanation — so checking them in isolation is what
// turns a long hunt into a five-minute fix. A change to any constant is a
// protocol version bump, not a fix.

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/session/key_schedule.dart';
import 'package:phone_auth/core/session/session_binding.dart';
import 'package:phone_auth/core/transport/pairing_bootstrap.dart';

import 'support/handshake_fixtures.dart';

void main() {
  test('the transcript hash matches the shared vector', () async {
    // Covers both hello encodings at once: a single byte out of place in
    // either one changes this hash, and with it every derived key.
    expect(
      toHex(await transcriptHash(serverHelloBody(), clientHelloBody())),
      '76b72c40a881574d332adada02a0960e39c3236f4a14b6bd53c42c565e01860d',
    );
  });

  test('the key schedule matches the shared vector', () async {
    final schedule = await KeySchedule.derive(
      sharedSecret: SecretKeyData(ascendingBytes(32)),
      transcriptHash: fromHex(
        '76b72c40a881574d332adada02a0960e39c3236f4a14b6bd53c42c565e01860d',
      ),
    );

    expect(
      toHex(schedule.clientToServer),
      '8dfa481719332738c6ba26756da8c2b30fa5dde7fb300c343aee6553cf655539',
    );
    expect(
      toHex(schedule.serverToClient),
      '7ebbd0e4c9f0c0b1129ecb14324eeadafcf53483e85752ee6205a139f865b43c',
    );
    expect(
      toHex(schedule.exporter),
      'eb2501574690d2f829f0f625cf1789e5c3203b8d402d2e6fe6fee9d911cc5522',
    );
  });

  test('splitting the schedule in the other order would not interoperate', () {
    // Two implementations that both reversed the split would agree with each
    // other and with nothing else. Naming the halves is what prevents it.
    expect(vectorExporter, isNot(equals(vectorClientToServer)));
    expect(vectorClientToServer, isNot(equals(vectorServerToClient)));
  });

  test('the session binding matches the shared vector', () async {
    expect(
      toHex(
        await deriveSessionBinding(
          SessionBindingInputs(
            transportName: 'QrNetworkTransport',
            sessionId: vectorSessionId,
            serverEphemeral: repeated(0x11, 32),
            clientEphemeral: repeated(0x22, 32),
            exporter: vectorExporter,
          ),
        ),
      ),
      'e8435f560ac83635c296802cfb1b07c01aba8c47efead3b880dcc3bbed024017',
    );
  });

  test('the verification code matches the shared vector', () async {
    expect(await verificationCode(vectorExporter), '420017');
  });

  test('verification codes keep their leading zeroes', () async {
    // "42" on one screen and "000042" on the other is a failed comparison.
    for (var seed = 0; seed < 64; seed++) {
      final code = await verificationCode(repeated(seed, 32));
      expect(code, hasLength(verificationCodeDigits));
      expect(RegExp(r'^\d{6}$').hasMatch(code), isTrue, reason: code);
    }
  });

  test('the identity hash matches the shared vector', () async {
    expect(
      toHex(await hashIdentity(vectorServerSpki)),
      '713920868af55094ba143c90dfadc9f532ce00dd11e7ffece6a3b3a71f51ab90',
    );
  });

  test('a bootstrap round-trips through its URI', () {
    final bootstrap = PairingBootstrap(
      sessionId: vectorSessionId,
      nonce: ascendingBytes(32),
      verifierId: vectorVerifierId,
      verifierIdentityHash: repeated(0xcd, 32),
      endpoint: '192.168.1.10:8765',
      expiresAtMs: vectorExpiresAtMs,
    );
    final parsed = PairingBootstrap.parse(bootstrap.toUri());

    expect(parsed.sessionId, bootstrap.sessionId);
    expect(parsed.verifierId, bootstrap.verifierId);
    expect(parsed.nonce, bootstrap.nonce);
    expect(parsed.verifierIdentityHash, bootstrap.verifierIdentityHash);
    expect(parsed.endpoint, bootstrap.endpoint);
    expect(parsed.expiresAtMs, bootstrap.expiresAtMs);
  });
}
