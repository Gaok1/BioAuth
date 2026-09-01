/// Property tests over the importers.
///
/// The last open corner of `REL-05`. These parsers read a file the user picked
/// from somewhere else entirely — another manager's export, possibly truncated,
/// possibly not what they thought it was — so the input is as unconstrained as
/// anything arriving on a socket.
///
/// Three properties:
///
/// 1. **Nothing but a `VaultImportException` ever escapes.** A `RangeError` or
///    a `TypeError` reaching the screen is a crash on a file the user picked,
///    and the message they get is a Dart stack trace.
/// 2. **Every item produced is one the store will accept.** The store enforces
///    its own bounds and fails the write; a parser that emitted an over-long
///    field would turn one bad row into an import that dies half-written.
/// 3. **A rejection is never silent.** Every input row is either imported or
///    reported. Rows that vanish are the failure mode an import report exists
///    to prevent.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/vault/vault_import.dart';

import 'support/property_config.dart';

/// The store's own limits, restated here on purpose. If they drift apart this
/// file fails, which is the point: the parser promises what the store demands.
const _maxName = 255;
const _maxUsername = 255;
const _maxUri = 1024;
const _maxSecret = 4096;

Uint8List bytes(String text) => Uint8List.fromList(utf8.encode(text));

/// Fixed seed: a property test that fails only sometimes is a property test
/// nobody trusts. A counterexample found here is reproducible from the seed.
///
/// Fixed, not immovable. One seed walks one sequence of inputs, and walked
/// only that one on every run since this file was written; see
/// `support/property_config.dart` for how to sweep others without changing
/// what an ordinary `flutter test` does.
final _random = propertyRandom(0x5eed);

String _fuzzText(int maxLength) {
  // Quotes, separators, backslashes, newlines, accented letters and a NUL:
  // everything a CSV parser or a JSON reader is entitled to be confused by.
  //
  // The NUL is written as an escape and has to stay one. It was a raw 0x00
  // byte in this file -- the same string at run time, and a different file to
  // every tool that reads it. Git called the file binary and printed
  // `Bin 7539 -> 7540 bytes` where a diff belongs, so every change to the
  // suite that proves the importers cannot emit an unstorable item was
  // unreviewable, and grep skipped it in every search across the tests.
  const alphabet = 'abc,;"\'\\\n\r\t {}[]:0123456789áé—\u0000 ';
  final length = _random.nextInt(maxLength);
  return String.fromCharCodes(
    List.generate(
      length,
      (_) => alphabet.codeUnitAt(_random.nextInt(alphabet.length)),
    ),
  );
}

void main() {
  test(
    'arbitrary bytes never escape as anything but an import failure',
    () async {
      for (var attempt = 0; attempt < propertyRounds(400); attempt++) {
        final input = Uint8List.fromList(
          List.generate(_random.nextInt(256), (_) => _random.nextInt(256)),
        );
        try {
          await parseVaultImport(input);
        } on VaultImportException {
          // The one acceptable outcome besides success.
        } catch (error) {
          fail('input #$attempt escaped as ${error.runtimeType}: $error');
        }
      }
    },
  );

  test(
    'arbitrary text never escapes as anything but an import failure',
    () async {
      for (var attempt = 0; attempt < propertyRounds(400); attempt++) {
        try {
          await parseVaultImport(bytes(_fuzzText(300)));
        } on VaultImportException {
          // Expected for most of these.
        } catch (error) {
          fail('input #$attempt escaped as ${error.runtimeType}: $error');
        }
      }
    },
  );

  /// The shapes most likely to reach the field decoders rather than dying on
  /// the first byte: something that already looks like a header row.
  test(
    'plausible CSV never escapes, and never emits an unstorable item',
    () async {
      for (var attempt = 0; attempt < propertyRounds(400); attempt++) {
        final rows = StringBuffer('name,username,password,url,notes\n');
        for (var row = 0; row < _random.nextInt(6); row++) {
          rows.writeln(
            [
              _fuzzText(40),
              _fuzzText(40),
              _fuzzText(40),
              _fuzzText(40),
              _fuzzText(40),
            ].join(','),
          );
        }

        try {
          final preview = await parseVaultImport(bytes(rows.toString()));
          for (final item in preview.items) {
            expect(
              item.name,
              isNotEmpty,
              reason: 'a nameless item was emitted',
            );
            expect(item.secret, isNotEmpty);
            expect(item.name.length, lessThanOrEqualTo(_maxName));
            expect(item.username.length, lessThanOrEqualTo(_maxUsername));
            expect(item.uri.length, lessThanOrEqualTo(_maxUri));
            expect(item.secret.length, lessThanOrEqualTo(_maxSecret));
          }
        } on VaultImportException {
          // A file that is not readable at all is a fine outcome.
        } catch (error) {
          fail('input #$attempt escaped as ${error.runtimeType}: $error');
        }
      }
    },
  );

  test(
    'plausible Bitwarden JSON never escapes, and never emits an unstorable item',
    () async {
      for (var attempt = 0; attempt < propertyRounds(300); attempt++) {
        final items = List.generate(_random.nextInt(5), (_) {
          // Types outside 1 and 2 exercise the rejection path; a missing
          // `login` object on a type 1 exercises the other one.
          final type = _random.nextInt(5);
          return <String, Object?>{
            'type': type,
            'name': _fuzzText(40),
            'notes': _fuzzText(40),
            if (_random.nextBool())
              'login': {
                'username': _fuzzText(40),
                'password': _fuzzText(40),
                if (_random.nextBool())
                  'uris': [
                    {'uri': _fuzzText(40)},
                  ],
              },
          };
        });

        try {
          final preview = await parseVaultImport(
            bytes(jsonEncode({'encrypted': false, 'items': items})),
          );
          for (final item in preview.items) {
            expect(item.name, isNotEmpty);
            expect(item.secret, isNotEmpty);
            expect(item.name.length, lessThanOrEqualTo(_maxName));
            expect(item.secret.length, lessThanOrEqualTo(_maxSecret));
          }
          // Nothing may vanish. A row that is neither imported nor reported is
          // exactly what an import report exists to prevent.
          expect(
            preview.items.length + preview.rejections.length,
            items.length,
            reason: 'rows went missing between the file and the report',
          );
        } on VaultImportException {
          // Fine.
        } catch (error) {
          fail('input #$attempt escaped as ${error.runtimeType}: $error');
        }
      }
    },
  );

  /// Truncation at any point must be a refusal or a partial read, never a
  /// crash — a half-copied file is an ordinary thing to be handed.
  test('a truncated export is refused rather than crashing', () async {
    final whole = bytes(
      jsonEncode({
        'encrypted': false,
        'items': [
          {
            'type': 1,
            'name': 'Banco',
            'login': {'username': 'alice', 'password': 'hunter2'},
          },
        ],
      }),
    );

    for (var cut = 0; cut < whole.length; cut++) {
      try {
        await parseVaultImport(Uint8List.sublistView(whole, 0, cut));
      } on VaultImportException {
        // Expected for nearly all of them.
      } catch (error) {
        fail('truncating to $cut escaped as ${error.runtimeType}: $error');
      }
    }
  });

  /// A file far past the cap must be refused on the count rather than parsed
  /// into memory first.
  test('a file past the row cap is refused', () async {
    final rows = StringBuffer('name,password\n');
    for (var row = 0; row <= maxImportRows; row++) {
      rows.writeln('item$row,secret$row');
    }

    expect(
      () => parseVaultImport(bytes(rows.toString())),
      throwsA(isA<VaultImportException>()),
    );
  });
}
