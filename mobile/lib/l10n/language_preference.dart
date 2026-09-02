/// Which language pack the interface uses, and where that choice is kept.
///
/// Absent means the phone decides. That is the default, and it is the only
/// value that keeps working when the user changes the phone's language later
/// -- a stored `en` would outlive the reason it was chosen.
library;

import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'app_strings.dart';

const String _key = 'app.language.v1';

/// Reads the stored choice, or null for "follow the phone".
///
/// A preference store that will not answer means the phone decides, never a
/// launch that fails: the language is a preference and the app is the feature.
Future<Locale?> loadLanguageChoice() async {
  try {
    final preferences = await SharedPreferences.getInstance();
    return _decode(preferences.getString(_key));
  } on Object {
    return null;
  }
}

/// What [loadLanguageChoice] found at boot.
///
/// Overridden in `runPhoneAuth` with the value read from disk, so the first
/// frame is already in the right language. Without that the app would paint
/// once in the phone's language and then switch, in front of the user.
final bootLanguageProvider = Provider<Locale?>((ref) => null);

/// The pack for code with no `BuildContext`.
///
/// A background session raises the platform's own biometric prompt while none
/// of this app's screens are up, so there is no `Localizations` to read from
/// and the words still have to match what the user picked.
final appStringsProvider = Provider<AppStrings>((ref) {
  final chosen = ref.watch(languageProvider);
  return AppStrings.forLocale(
    chosen ?? WidgetsBinding.instance.platformDispatcher.locale,
  );
});

final languageProvider = NotifierProvider<LanguageController, Locale?>(
  LanguageController.new,
);

class LanguageController extends Notifier<Locale?> {
  @override
  Locale? build() => ref.watch(bootLanguageProvider);

  /// Switches the interface. Null follows the phone.
  Future<void> select(Locale? locale) async {
    state = locale;
    try {
      final preferences = await SharedPreferences.getInstance();
      if (locale == null) {
        await preferences.remove(_key);
      } else {
        await preferences.setString(_key, _encode(locale));
      }
    } on Object {
      // Applied for this session; the next launch follows the phone again.
    }
  }
}

String _encode(Locale locale) => locale.countryCode == null
    ? locale.languageCode
    : '${locale.languageCode}_${locale.countryCode}';

/// Maps a stored tag back onto a language the app still ships.
///
/// Anything else -- a tag from a version that shipped a language this one
/// dropped, or a value someone put there by hand -- reads as "follow the
/// phone" rather than as a language nothing can render.
Locale? _decode(String? tag) {
  if (tag == null || tag.isEmpty) return null;
  final parts = tag.split('_');
  final candidate = parts.length == 2
      ? Locale(parts.first, parts.last)
      : Locale(parts.first);
  return AppStrings.supportedLocales.contains(candidate) ? candidate : null;
}
