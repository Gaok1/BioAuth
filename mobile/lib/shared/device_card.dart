import 'package:flutter/material.dart';

import '../domain/desktop_device.dart';
import 'connection_status.dart';

class DeviceCard extends StatelessWidget {
  const DeviceCard({required this.device, required this.onRevoke, super.key});

  final DesktopDevice device;
  final VoidCallback onRevoke;

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
                ],
              ),
            ),
            PopupMenuButton<void>(
              tooltip: 'Opções do dispositivo',
              itemBuilder: (context) => [
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
