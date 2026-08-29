/// TOTP against the RFC's own numbers.
///
/// A generator that is subtly wrong produces codes that look right and are
/// rejected, and the user blames their phone's clock. The published vectors
/// are the only thing that settles it, so they are the first test here.
library;

import 'dart:async';
import 'dart:typed_data';

import 'package:fake_async/fake_async.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/vault/totp.dart';
import 'package:phone_auth/features/vault/vault_controller.dart';
import 'package:phone_auth/features/vault/vault_store.dart';

void main() {
  /// RFC 6238 Appendix B: the seed is the ASCII "12345678901234567890",
  /// SHA-1, eight digits. Written as bytes rather than base32 so the vector
  /// is recognisably the one in the document.
  final rfcSecret = TotpSecret(
    Uint8List.fromList('12345678901234567890'.codeUnits),
    digits: 8,
  );

  DateTime atSeconds(int seconds) =>
      DateTime.fromMillisecondsSinceEpoch(seconds * 1000, isUtc: true);

  group('RFC 6238 Appendix B', () {
    // Only the SHA-1 rows: SHA-256 and SHA-512 use different seeds in the
    // document, and this generator is SHA-1 by design because that is what
    // every issuer emits.
    const vectors = {
      59: '94287082',
      1111111109: '07081804',
      1111111111: '14050471',
      1234567890: '89005924',
      2000000000: '69279037',
      20000000000: '65353130',
    };

    for (final entry in vectors.entries) {
      test('t=${entry.key} gives ${entry.value}', () async {
        final code = await generateTotp(rfcSecret, at: atSeconds(entry.key));

        expect(code.digits, entry.value);
      });
    }
  });

  test('a code lasts to the end of its window and no longer', () async {
    // 59 seconds in: the window began at 30 and ends at 60.
    final code = await generateTotp(rfcSecret, at: atSeconds(59));

    expect(code.expiresAt, atSeconds(60));
    expect(code.secondsRemaining(atSeconds(59)), 1);
    expect(code.secondsRemaining(atSeconds(45)), 15);
    // Never negative: a code read after it expired has zero left, not -4.
    expect(code.secondsRemaining(atSeconds(90)), 0);
  });

  test('the code changes exactly on the window boundary', () async {
    final before = await generateTotp(rfcSecret, at: atSeconds(29));
    final after = await generateTotp(rfcSecret, at: atSeconds(30));
    final later = await generateTotp(rfcSecret, at: atSeconds(59));

    expect(before.digits, isNot(after.digits));
    expect(after.digits, later.digits, reason: 'same window, same code');
  });

  group('reading a seed', () {
    /// A person copying a seed off a screen gets spaces, case and padding
    /// wrong. A seed that works in another authenticator and not here would
    /// read as this app being broken.
    test('survives the way a person copies it', () {
      final canonical = TotpSecret.parse('JBSWY3DPEHPK3PXP');

      for (final typed in [
        'jbswy3dpehpk3pxp',
        'JBSW Y3DP EHPK 3PXP',
        'JBSW-Y3DP-EHPK-3PXP',
        '  JBSWY3DPEHPK3PXP  ',
        'JBSWY3DPEHPK3PXP======',
      ]) {
        expect(
          TotpSecret.parse(typed).bytes,
          canonical.bytes,
          reason: '`$typed` did not read back',
        );
      }
    });

    test('rejects what is not base32', () {
      for (final bad in ['', '  ', '!!!!', 'JBSW0Y3D', 'JBSW1Y3D']) {
        expect(
          () => TotpSecret.parse(bad),
          throwsA(isA<TotpException>()),
          reason: bad,
        );
      }
    });

    test('rejects digit and period settings outside what issuers use', () {
      expect(
        () => TotpSecret.parse('JBSWY3DPEHPK3PXP', digits: 5),
        throwsA(isA<TotpException>()),
      );
      expect(
        () => TotpSecret.parse('JBSWY3DPEHPK3PXP', digits: 9),
        throwsA(isA<TotpException>()),
      );
      expect(
        () => TotpSecret.parse('JBSWY3DPEHPK3PXP', period: Duration.zero),
        throwsA(isA<TotpException>()),
      );
    });
  });

  group('otpauth URIs', () {
    test('a QR code from an issuer is read', () {
      final secret = TotpSecret.fromUri(
        'otpauth://totp/Banco:alice@example.com'
        '?secret=JBSWY3DPEHPK3PXP&issuer=Banco&digits=8&period=60',
      );

      expect(secret.bytes, TotpSecret.parse('JBSWY3DPEHPK3PXP').bytes);
      expect(secret.digits, 8);
      expect(secret.period, const Duration(seconds: 60));
    });

    test('defaults are the ones every authenticator assumes', () {
      final secret = TotpSecret.fromUri(
        'otpauth://totp/Banco?secret=JBSWY3DPEHPK3PXP',
      );

      expect(secret.digits, totpDigits);
      expect(secret.period, totpPeriod);
    });

    /// Generating wrong codes silently is the worst outcome here: the user
    /// would blame the site, the clock, and eventually this app.
    test('an algorithm this does not implement is refused, not ignored', () {
      expect(
        () => TotpSecret.fromUri(
          'otpauth://totp/Banco?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256',
        ),
        throwsA(isA<TotpException>()),
      );
    });

    test('anything that is not an otpauth totp is refused', () {
      for (final bad in [
        'https://example.com',
        'otpauth://hotp/Banco?secret=JBSWY3DPEHPK3PXP',
        'otpauth://totp/Banco',
        'not a uri at all %%%',
      ]) {
        expect(
          () => TotpSecret.fromUri(bad),
          throwsA(isA<TotpException>()),
          reason: bad,
        );
      }
    });

    /// The encoder exists so the parser has an inverse to be checked against.
    /// A round-trip bug here stops somebody's second factor working.
    test('a seed survives being written out and read back', () {
      for (final original in [
        'JBSWY3DPEHPK3PXP',
        'GEZDGNBVGY3TQOJQ',
        'AA',
        'MFRGGZDFMZTWQ2LK',
      ]) {
        final secret = TotpSecret.parse(original);

        final round = TotpSecret.fromUri(
          encodeTotpSecret(secret, label: 'Banco:alice'),
        );

        expect(round.bytes, secret.bytes, reason: original);
      }
    });
  });

  test('a form can tell a seed from a password before the field is left', () {
    expect(looksLikeTotpSecret('JBSWY3DPEHPK3PXP'), isTrue);
    expect(looksLikeTotpSecret('jbsw y3dp ehpk 3pxp'), isTrue);
    expect(looksLikeTotpSecret('hunter2!'), isFalse);
    expect(looksLikeTotpSecret(''), isFalse);
  });

  group('a TOTP item in the vault', () {
    /// The stored secret of a TOTP item is the seed. Showing that where the
    /// user expects six digits would put the one value that must never be
    /// screenshotted on screen.
    test('reveals its digits and never its seed', () async {
      final controller = VaultController(
        store: _SeedStore(),
        copy: (_) async {},
      );
      addTearDown(controller.dispose);
      await controller.unlock();

      await controller.reveal(_totpItem());

      expect(controller.secretFor('one'), isNull, reason: 'the seed leaked');
      final code = controller.totpFor('one');
      expect(code, isNotNull);
      expect(code!.digits, hasLength(6));
      expect(int.tryParse(code.digits), isNotNull);
    });

    /// Copying the seed would paste something no login field accepts, and
    /// leave the second factor itself on the clipboard.
    test('copies its digits, not its seed', () async {
      String? copied;
      final controller = VaultController(
        store: _SeedStore(),
        copy: (value) async => copied = value,
      );
      addTearDown(controller.dispose);
      await controller.unlock();

      await controller.copy(_totpItem());

      expect(copied, hasLength(6));
      expect(copied, isNot(_seed));
    });

    /// A seed that will not parse is a stored item that is wrong. Saying so
    /// beats the generic vault message: the user can fix it by editing.
    test('a seed that will not parse says why', () async {
      final controller = VaultController(
        store: _SeedStore(seed: 'not base32 !!'),
        copy: (_) async {},
      );
      addTearDown(controller.dispose);
      await controller.unlock();

      await controller.reveal(_totpItem());

      expect(controller.totpFor('one'), isNull);
      expect(controller.error, contains('TOTP'));
    });

    /// There is one revealed code for the whole vault, and whichever item is
    /// revealed is the one that reads it. A ticker left running from the item
    /// before therefore writes into the row that replaced it.
    test('revealing a password stops the authenticator it replaced', () {
      fakeAsync((async) {
        final controller = VaultController(
          store: _SeedStore(),
          copy: (_) async {},
        );
        addTearDown(controller.dispose);
        unawaited(controller.unlock());
        async.flushMicrotasks();
        unawaited(controller.reveal(_totpItem()));
        async.flushMicrotasks();
        expect(controller.totpFor('one'), isNotNull);

        unawaited(controller.reveal(_loginItem()));
        async.flushMicrotasks();

        expect(controller.secretFor('two'), _password);
        expect(
          controller.totpFor('two'),
          isNull,
          reason: 'the password row showed six digits it never had',
        );
        // And it stays gone. A ticker still running would put them back a
        // second later, and go on deriving from a seed nobody is looking at.
        async.elapse(const Duration(seconds: 3));
        expect(controller.totpFor('two'), isNull);
        expect(controller.secretFor('two'), _password);
      });
    });

    /// Locking has to stop the ticker as well as clear the code, or a locked
    /// vault keeps deriving codes from a seed it still holds.
    test('locking clears the code', () async {
      final controller = VaultController(
        store: _SeedStore(),
        copy: (_) async {},
      );
      addTearDown(controller.dispose);
      await controller.unlock();
      await controller.reveal(_totpItem());
      expect(controller.totpFor('one'), isNotNull);

      controller.lock();

      expect(controller.totpFor('one'), isNull);
    });
  });
}

const _seed = 'JBSWY3DPEHPK3PXP';
const _password = 'hunter2';

VaultItemSummary _totpItem() => VaultItemSummary(
  id: 'one',
  revision: 1,
  kind: VaultItemKind.totp,
  name: 'Banco',
  username: 'alice',
  uri: 'https://banco.example.com',
  updatedAt: DateTime.utc(2026),
);

VaultItemSummary _loginItem() => VaultItemSummary(
  id: 'two',
  revision: 1,
  kind: VaultItemKind.login,
  name: 'Correio',
  username: 'alice',
  uri: 'https://correio.example.com',
  updatedAt: DateTime.utc(2026),
);

class _SeedStore extends VaultStore {
  _SeedStore({this.seed = _seed});

  final String seed;

  @override
  Future<VaultPage> listPage([String? cursor]) async =>
      VaultPage(items: [_totpItem(), _loginItem()]);

  @override
  Future<VaultSecret> fetch(String id) async =>
      VaultSecret(id: id, revision: 1, secret: id == 'one' ? seed : _password);

  @override
  Future<VaultWrite> create(VaultItemInput item) async =>
      const VaultWrite(id: 'two', revision: 1);

  @override
  Future<VaultWrite> update(
    VaultItemSummary current,
    VaultItemInput item,
  ) async => VaultWrite(id: current.id, revision: current.revision + 1);

  @override
  Future<void> delete(VaultItemSummary item) async {}
}
