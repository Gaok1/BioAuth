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

    /// The other two rows of the same table.
    ///
    /// Each uses its own seed: the document repeats "1234567890" to the
    /// digest's block size, so these are not the SHA-1 seed under a different
    /// hash. Refusing `algorithm=` used to mean an account on either of them
    /// could not be added at all.
    final byAlgorithm = {
      TotpAlgorithm.sha256: (
        seed: '12345678901234567890123456789012',
        codes: {
          59: '46119246',
          1111111109: '68084774',
          1111111111: '67062674',
          1234567890: '91819424',
          2000000000: '90698825',
          20000000000: '77737706',
        },
      ),
      TotpAlgorithm.sha512: (
        seed:
            '1234567890123456789012345678901234567890'
            '123456789012345678901234',
        codes: {
          59: '90693936',
          1111111109: '25091201',
          1111111111: '99943326',
          1234567890: '93441116',
          2000000000: '38618901',
          20000000000: '47863826',
        },
      ),
    };

    for (final entry in byAlgorithm.entries) {
      final secret = TotpSecret(
        Uint8List.fromList(entry.value.seed.codeUnits),
        digits: 8,
        algorithm: entry.key,
      );
      for (final vector in entry.value.codes.entries) {
        test(
          '${entry.key.label} t=${vector.key} gives ${vector.value}',
          () async {
            final code = await generateTotp(secret, at: atSeconds(vector.key));

            expect(code.digits, vector.value);
          },
        );
      }
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
      for (final named in ['SHA3-256', 'MD5', 'sha', '']) {
        expect(
          () => TotpSecret.fromUri(
            'otpauth://totp/Banco?secret=JBSWY3DPEHPK3PXP&algorithm=$named',
          ),
          named.isEmpty ? returnsNormally : throwsA(isA<TotpException>()),
          reason: named,
        );
      }
    });

    test('the algorithms RFC 6238 defines are read from the uri', () {
      for (final written in ['SHA256', 'sha256', 'SHA-256']) {
        expect(
          TotpSecret.fromUri(
            'otpauth://totp/Banco?secret=JBSWY3DPEHPK3PXP&algorithm=$written',
          ).algorithm,
          TotpAlgorithm.sha256,
          reason: written,
        );
      }
      expect(
        TotpSecret.fromUri(
          'otpauth://totp/Banco?secret=JBSWY3DPEHPK3PXP&algorithm=SHA512',
        ).algorithm,
        TotpAlgorithm.sha512,
      );
    });

    /// The seed alone does not say which hash it is for, so an item on
    /// anything but SHA-1 has to store the whole URI -- exactly as it already
    /// does for digits and window. Storing the bare seed would read back as
    /// SHA-1 and produce a code no issuer accepts, which is the failure this
    /// file exists to avoid.
    test('a seed on another hash is stored whole, and reads back the same', () {
      final secret = TotpSecret.parse(
        'JBSWY3DPEHPK3PXP',
        algorithm: TotpAlgorithm.sha512,
      );

      final stored = storedTotpSecret(secret);
      expect(stored, startsWith('otpauth://'));
      expect(readTotpSecret(stored).algorithm, TotpAlgorithm.sha512);

      // And SHA-1 still stores bare, so nothing already in a vault moves.
      expect(
        storedTotpSecret(TotpSecret.parse('JBSWY3DPEHPK3PXP')),
        'JBSWY3DPEHPK3PXP',
      );
      expect(
        encodeTotpSecret(TotpSecret.parse('JBSWY3DPEHPK3PXP', digits: 8)),
        isNot(contains('algorithm')),
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

  group('the form a seed is stored in', () {
    /// The overwhelmingly common case, and the one a restore depends on: an
    /// ordinary seed stays bare base32, so an item added from a QR link and
    /// one typed by hand are the same bytes.
    test('an ordinary seed stays bare base32', () {
      final stored = storedTotpSecret(TotpSecret.parse('JBSWY3DPEHPK3PXP'));

      expect(stored, 'JBSWY3DPEHPK3PXP');
      expect(readTotpSecret(stored).digits, totpDigits);
      expect(readTotpSecret(stored).period, totpPeriod);
    });

    /// The bug this covers is silent. The digits and the window were parsed
    /// off the pasted `otpauth://` and then dropped, so an eight-digit or
    /// sixty-second issuer became an item that generated a perfectly plausible
    /// six-digit code that nothing would ever accept -- with no error, and
    /// nothing on screen to suggest the app was the reason.
    test('digits and window that are not the defaults survive storage', () {
      final pasted = readTotpSecret(
        'otpauth://totp/Banco:alice?secret=JBSWY3DPEHPK3PXP&digits=8&period=60',
      );
      expect(pasted.digits, 8);
      expect(pasted.period, const Duration(seconds: 60));

      final reread = readTotpSecret(storedTotpSecret(pasted));

      expect(reread.digits, 8);
      expect(reread.period, const Duration(seconds: 60));
      expect(reread.bytes, pasted.bytes);
    });

    test(
      'a stored non-default seed still generates its own shape of code',
      () async {
        final stored = storedTotpSecret(
          readTotpSecret(
            'otpauth://totp/Banco?secret=JBSWY3DPEHPK3PXP&digits=8&period=60',
          ),
        );

        final code = await generateTotp(
          readTotpSecret(stored),
          at: DateTime.utc(2026, 1, 1),
        );

        expect(code.digits.length, 8);
        // The window is sixty seconds, so a code minted on the boundary lasts
        // sixty -- not the thirty a dropped `period=` would have given it.
        expect(code.secondsRemaining(DateTime.utc(2026, 1, 1)), 60);
      },
    );
  });

  test('a form can tell a seed from a password before the field is left', () {
    expect(looksLikeTotpSecret('JBSWY3DPEHPK3PXP'), isTrue);
    expect(looksLikeTotpSecret('jbsw y3dp ehpk 3pxp'), isTrue);
    // What a site shows next to the QR code, which is the other half of what
    // people paste into that field.
    expect(
      looksLikeTotpSecret('otpauth://totp/Banco?secret=JBSWY3DPEHPK3PXP'),
      isTrue,
    );
    expect(looksLikeTotpSecret('hunter2!'), isFalse);
    expect(looksLikeTotpSecret(''), isFalse);
    // An otpauth naming a hash this cannot generate is not a seed this form
    // should say yes to: the item would be refused a moment later on save.
    expect(
      looksLikeTotpSecret(
        'otpauth://totp/Banco?secret=JBSWY3DPEHPK3PXP&algorithm=MD5',
      ),
      isFalse,
    );
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
      // The one item whose stored value and copied value are different things,
      // so it is the one the confirmation has to be explicit about.
      expect(controller.notice, contains('Código'));
      expect(controller.notice, contains('não a semente'));
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
  Future<List<VaultItemSummary>?> delete(VaultItemSummary item) async => null;
}
