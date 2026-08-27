import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/transport/pairing_bootstrap.dart';

void main() {
  const now = 1787745600000;
  final nonce = Uint8List.fromList(List<int>.generate(32, (i) => i));
  final hash = Uint8List.fromList(List<int>.generate(32, (i) => 255 - i));

  String uri({
    String vid = 'desktop-1',
    String sid = 'session-1',
    String? n,
    String? k,
    String ep = '192.168.1.10:8765',
    String exp = '$now',
  }) =>
      '${bootstrapPrefix}vid=$vid&sid=$sid'
      '&n=${n ?? toBase64Url(nonce)}'
      '&k=${k ?? toBase64Url(hash)}'
      '&ep=$ep&exp=$exp';

  test('parses a well-formed code', () {
    final bootstrap = PairingBootstrap.parse(uri());

    expect(bootstrap.verifierId, 'desktop-1');
    expect(bootstrap.sessionId, 'session-1');
    expect(bootstrap.nonce, nonce);
    expect(bootstrap.verifierIdentityHash, hash);
    expect(bootstrap.endpoint, '192.168.1.10:8765');
    expect(bootstrap.expiresAtMs, now);
  });

  test('a foreign scheme is refused', () {
    for (final candidate in [
      'https://example.com/pair?vid=a',
      'phoneauth://pair/v2?vid=a',
      '',
      'random text a user scanned off a poster',
    ]) {
      expect(
        () => PairingBootstrap.parse(candidate),
        throwsA(isA<BootstrapException>()),
        reason: '`$candidate` must be refused',
      );
    }
  });

  test('a missing field is refused rather than defaulted', () {
    // A bootstrap without `k` would leave the phone with nothing to
    // authenticate the desktop against.
    final full = uri().substring(bootstrapPrefix.length);
    for (final key in ['vid', 'sid', 'n', 'k', 'ep', 'exp']) {
      final query = full
          .split('&')
          .where((pair) => !pair.startsWith('$key='))
          .join('&');
      expect(
        () => PairingBootstrap.parse('$bootstrapPrefix$query'),
        throwsA(isA<BootstrapException>()),
        reason: 'a bootstrap without `$key` must be refused',
      );
    }
  });

  test('an unknown field is refused', () {
    // A future version that adds a meaningful field must not be silently
    // half-understood.
    expect(
      () => PairingBootstrap.parse('${uri()}&surprise=1'),
      throwsA(isA<BootstrapException>()),
    );
  });

  test('wrong-length nonces and hashes are refused', () {
    // A 32-byte field decoded from a shorter string would leave the rest of
    // the buffer as zeroes — exactly the quiet truncation a fixed-size field
    // exists to prevent.
    expect(
      () => PairingBootstrap.parse(uri(n: toBase64Url(Uint8List(16)))),
      throwsA(isA<BootstrapException>()),
    );
    expect(
      () => PairingBootstrap.parse(uri(k: toBase64Url(Uint8List(31)))),
      throwsA(isA<BootstrapException>()),
    );
    expect(
      () => PairingBootstrap.parse(uri(n: 'not base64url!')),
      throwsA(isA<BootstrapException>()),
    );
  });

  test('a non-numeric expiry is refused', () {
    expect(
      () => PairingBootstrap.parse(uri(exp: 'soon')),
      throwsA(isA<BootstrapException>()),
    );
  });

  test('separators may not appear inside a field', () {
    // Otherwise the two ends disagree about where a value ends.
    expect(
      () => PairingBootstrap(
        sessionId: 'session-1',
        nonce: nonce,
        verifierId: 'desktop-1',
        verifierIdentityHash: hash,
        endpoint: 'host:1&vid=attacker',
        expiresAtMs: now,
      ),
      throwsA(isA<BootstrapException>()),
    );
  });

  test('an empty endpoint is allowed for transports without addresses', () {
    expect(PairingBootstrap.parse(uri(ep: '')).endpoint, isEmpty);
  });

  test('expiry is enforced at the boundary', () {
    final bootstrap = PairingBootstrap.parse(uri());
    expect(bootstrap.isExpiredAt(now - 1), isFalse);
    expect(bootstrap.isExpiredAt(now), isTrue);
    expect(bootstrap.isExpiredAt(now + 1), isTrue);
  });

  test('a bind address is refused with the real reason', () {
    // The desktop shipped a code carrying `0.0.0.0`, its bind address. A phone
    // dialling that dials itself, and the connection error it produced was
    // reported to the user as the two devices being on different networks.
    expect(
      () => PairingBootstrap.parse(uri(ep: '0.0.0.0:8765')),
      throwsA(
        isA<BootstrapException>().having(
          (e) => e.toString(),
          'message',
          contains('no phone can reach'),
        ),
      ),
    );
    expect(
      () => PairingBootstrap.parse(uri(ep: '[::]:8765')),
      throwsA(isA<BootstrapException>()),
    );
  });

  test('an ordinary address still parses', () {
    expect(
      PairingBootstrap.parse(uri(ep: '192.168.100.80:8765')).endpoint,
      '192.168.100.80:8765',
    );
    expect(
      PairingBootstrap.parse(uri(ep: '[fe80::1]:8765')).endpoint,
      '[fe80::1]:8765',
    );
  });
}
