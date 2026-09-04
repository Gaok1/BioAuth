import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Characters that only a Portuguese sentence has.
///
/// The pack cannot be checked by asking whether a string is English -- most
/// short ones are the same word in both. What it can be checked by is the
/// accents, which is enough: a screen holding a Portuguese sentence almost
/// always holds one of these.
final RegExp _accented = RegExp('[çãõáéíóúâêôàü]', caseSensitive: false);

void main() {
  /// Every user-facing string belongs to a pack, and a literal that never went
  /// through one is invisible to the compiler: it type-checks, it analyses
  /// clean, and it shows up in the wrong language on somebody's phone.
  ///
  /// This is the shape that got through -- `XTypeGroup(label: 'Exportação de
  /// gerenciador')` sat inside a `const` list, which is exactly where a string
  /// hides from a pack, and the platform's own file dialog drew it in
  /// Portuguese on an English phone.
  ///
  /// Multi-line strings are not scanned. Nothing user-facing is written as one
  /// today, and a scanner that tracked them would be a Dart parser.
  test('no string outside the packs is written in one language', () {
    final offenders = <String>[];

    for (final entity in Directory('lib').listSync(recursive: true)) {
      if (entity is! File || !entity.path.endsWith('.dart')) continue;
      final path = entity.path.replaceAll(r'\', '/');
      // Where the packs live, and where the sentences are supposed to be.
      if (path.contains('/l10n/')) continue;

      final lines = entity.readAsLinesSync();
      for (var index = 0; index < lines.length; index++) {
        for (final literal in _literalsIn(lines[index])) {
          if (_accented.hasMatch(literal)) {
            offenders.add('$path:${index + 1}  $literal');
          }
        }
      }
    }

    expect(
      offenders,
      isEmpty,
      reason:
          'These strings are drawn in one language whatever the phone is set '
          'to. Move each into AppStrings and read it from there:\n'
          '${offenders.join('\n')}',
    );
  });
}

/// The quoted spans of one line, with comments dropped.
///
/// Written as a scan rather than a regular expression because a comment may
/// contain quotes -- most of the ones in this repository do -- and a pattern
/// that matched quotes first would read half a sentence as a string literal.
List<String> _literalsIn(String line) {
  final literals = <String>[];
  String? quote;
  var start = 0;

  for (var index = 0; index < line.length; index++) {
    final character = line[index];
    if (quote == null) {
      // A comment ends the code on this line. Checked before quotes so that a
      // `//` outside a string wins, and after them so that a `//` inside one
      // -- every URL in the repository -- does not.
      if (character == '/' &&
          index + 1 < line.length &&
          line[index + 1] == '/') {
        break;
      }
      if (character == "'" || character == '"') {
        quote = character;
        start = index + 1;
      }
      continue;
    }
    if (character == r'\') {
      index++;
      continue;
    }
    if (character == quote) {
      literals.add(line.substring(start, index));
      quote = null;
    }
  }

  return literals;
}
