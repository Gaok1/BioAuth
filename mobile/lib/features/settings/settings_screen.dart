import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../l10n/app_strings.dart';
import '../../l10n/language_preference.dart';
import '../../shared/page_heading.dart';
import '../recovery/recovery_screen.dart';
import '../passkeys/passkeys_screen.dart';
import '../security/security_screen.dart';

class SettingsScreen extends ConsumerWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final strings = AppStrings.of(context);
    return ListView(
      children: [
        PageHeading(title: strings.settingsTitle),
        ListTile(
          leading: const Icon(Icons.security),
          title: Text(strings.settingsSecurity),
          subtitle: Text(strings.settingsSecuritySubtitle),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => Navigator.of(context).push(
            MaterialPageRoute<void>(builder: (_) => const SecurityScreen()),
          ),
        ),
        ListTile(
          leading: const Icon(Icons.key),
          title: Text(strings.settingsPasskeys),
          subtitle: Text(strings.settingsPasskeysSubtitle),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => Navigator.of(context).push(
            MaterialPageRoute<void>(builder: (_) => const PasskeysScreen()),
          ),
        ),
        ListTile(
          leading: const Icon(Icons.restore),
          title: Text(strings.settingsRecovery),
          subtitle: Text(strings.settingsRecoverySubtitle),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => Navigator.of(context).push(
            MaterialPageRoute<void>(builder: (_) => const RecoveryScreen()),
          ),
        ),
        const _LanguageTile(),
        AboutListTile(
          icon: const Icon(Icons.info_outline),
          applicationName: strings.appTitle,
          applicationVersion: _version,
        ),
      ],
    );
  }
}

/// Bumped with `pubspec.yaml` at each release.
const String _version = '0.3.0';

class _LanguageTile extends ConsumerWidget {
  const _LanguageTile();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final strings = AppStrings.of(context);
    final chosen = ref.watch(languageProvider);
    return ListTile(
      leading: const Icon(Icons.translate),
      title: Text(strings.settingsLanguage),
      subtitle: Text(
        chosen == null
            ? strings.settingsLanguageSystem
            : AppStrings.forLocale(chosen).languageName,
      ),
      trailing: const Icon(Icons.chevron_right),
      onTap: () => _pick(context, ref, chosen),
    );
  }

  Future<void> _pick(
    BuildContext context,
    WidgetRef ref,
    Locale? chosen,
  ) async {
    final strings = AppStrings.of(context);
    // A sentinel for "follow the phone", because null is a legitimate answer
    // and `showDialog` cannot tell it from a dismissed dialog.
    const system = Locale('und');
    final picked = await showDialog<Locale>(
      context: context,
      builder: (context) => SimpleDialog(
        title: Text(strings.settingsLanguage),
        children: [
          _LanguageOption(
            label: strings.settingsLanguageSystem,
            selected: chosen == null,
            onTap: () => Navigator.pop(context, system),
          ),
          for (final locale in AppStrings.supportedLocales)
            _LanguageOption(
              // Each language names itself. A picker that renamed every entry
              // into the language currently showing is one a person cannot use
              // to get out of a language they do not read.
              label: AppStrings.forLocale(locale).languageName,
              selected: chosen == locale,
              onTap: () => Navigator.pop(context, locale),
            ),
        ],
      ),
    );
    if (picked == null) return;
    await ref
        .read(languageProvider.notifier)
        .select(picked == system ? null : picked);
  }
}

class _LanguageOption extends StatelessWidget {
  const _LanguageOption({
    required this.label,
    required this.selected,
    required this.onTap,
  });

  final String label;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) => ListTile(
    title: Text(label),
    trailing: selected ? const Icon(Icons.check) : null,
    onTap: onTap,
  );
}
