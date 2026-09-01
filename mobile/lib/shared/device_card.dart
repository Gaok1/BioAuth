import 'package:flutter/material.dart';

import '../core/protocol/enrolment.dart';
import '../domain/desktop_device.dart';
import 'connection_status.dart';

class DeviceCard extends StatelessWidget {
  const DeviceCard({
    required this.device,
    required this.onRevoke,
    this.onPermissions,
    super.key,
  });

  final DesktopDevice device;
  final VoidCallback onRevoke;

  /// Abre o que este computador pode autorizar. Ausente onde o card é só
  /// leitura.
  final VoidCallback? onPermissions;

  @override
  Widget build(BuildContext context) {
    final blocked = device.isBlockedAt(DateTime.now().toUtc());
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          children: [
            CircleAvatar(child: Icon(blocked ? Icons.block : Icons.computer)),
            const SizedBox(width: 14),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    device.name,
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                  const SizedBox(height: 4),
                  if (blocked)
                    const Text('Bloqueado temporariamente')
                  else
                    ConnectionStatus(phase: device.phase),
                  const SizedBox(height: 4),
                  Text(
                    'Visto ${_relativeTime(device.lastSeen)}',
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                  if (device.purposes.isNotEmpty) ...[
                    const SizedBox(height: 8),
                    // What this computer was actually given. Two pairings with
                    // the same desktop look identical otherwise, and the
                    // difference between them is which key it can ask for.
                    Wrap(
                      spacing: 6,
                      runSpacing: 6,
                      children: [
                        for (final purpose in device.purposes)
                          _PurposeChip(purpose: purpose),
                      ],
                    ),
                  ],
                ],
              ),
            ),
            PopupMenuButton<void>(
              tooltip: 'Opções do dispositivo',
              itemBuilder: (context) => [
                if (onPermissions case final open?)
                  PopupMenuItem<void>(
                    onTap: open,
                    child: const Text('Permissões'),
                  ),
                PopupMenuItem<void>(
                  onTap: () => _confirmRevoke(context),
                  child: const Text('Revogar dispositivo'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _confirmRevoke(BuildContext context) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        // Scrollable, because a dialog is not exempt from the system font: the
        // box is capped at the screen and its content is not, so past a certain
        // size the text is cut off mid-sentence -- and here it is the sentence
        // explaining what the button below it destroys.
        scrollable: true,
        title: const Text('Revogar este computador?'),
        content: Text(
          'O telefone removerá ${device.name} e encerrará a sessão. '
          'O computador ainda pode guardar sua chave pública até você remover '
          'o pareamento também nele. Para reconectar, faça um novo pareamento '
          'e confira os dois códigos.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancelar'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Revogar'),
          ),
        ],
      ),
    );
    if (confirmed == true) onRevoke();
  }

  String _relativeTime(DateTime at) {
    final elapsed = DateTime.now().toUtc().difference(at);
    if (elapsed.inMinutes < 1) return 'agora';
    if (elapsed.inHours < 1) return 'há ${elapsed.inMinutes} min';
    if (elapsed.inDays < 1) return 'há ${elapsed.inHours} h';
    return 'há ${elapsed.inDays} d';
  }
}

/// One credential this desktop holds, named for what it can ask for.
class _PurposeChip extends StatelessWidget {
  const _PurposeChip({required this.purpose});

  final CredentialPurpose purpose;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final (icon, label) = switch (purpose) {
      CredentialPurpose.authorization => (Icons.lock_outline, 'Login'),
      CredentialPurpose.diskUnlock => (Icons.storage, 'Disco'),
      CredentialPurpose.webAuthn => (Icons.password, 'Sites'),
      CredentialPurpose.vault => (Icons.vpn_key_outlined, 'Cofre'),
      CredentialPurpose.fileLocker => (Icons.folder_outlined, 'Arquivos'),
      CredentialPurpose.ssh => (Icons.terminal, 'SSH'),
    };

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(20),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 13, color: theme.colorScheme.onSurfaceVariant),
          const SizedBox(width: 5),
          Text(label, style: theme.textTheme.labelSmall),
        ],
      ),
    );
  }
}
