import 'package:flutter/material.dart';

import '../../shared/page_heading.dart';
import '../recovery/recovery_screen.dart';
import '../passkeys/passkeys_screen.dart';
import '../security/security_screen.dart';

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return ListView(
      children: [
        const PageHeading(title: 'Ajustes'),
        ListTile(
          leading: const Icon(Icons.security),
          title: const Text('Segurança'),
          subtitle: const Text('Biometria e proteção de chaves'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => Navigator.of(context).push(
            MaterialPageRoute<void>(builder: (_) => const SecurityScreen()),
          ),
        ),
        ListTile(
          leading: const Icon(Icons.key),
          title: const Text('Passkeys'),
          subtitle: const Text('Contas, chaves inválidas e exclusão'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => Navigator.of(context).push(
            MaterialPageRoute<void>(builder: (_) => const PasskeysScreen()),
          ),
        ),
        ListTile(
          leading: const Icon(Icons.restore),
          title: const Text('Recuperação'),
          subtitle: const Text('Revogação e novo pareamento'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => Navigator.of(context).push(
            MaterialPageRoute<void>(builder: (_) => const RecoveryScreen()),
          ),
        ),
        const AboutListTile(
          icon: Icon(Icons.info_outline),
          applicationName: 'Phone Auth',
          applicationVersion: '0.1.5',
        ),
      ],
    );
  }
}
