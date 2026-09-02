import 'package:flutter/material.dart';

import '../core/protocol/enrolment.dart';
import '../domain/desktop_device.dart';
import '../l10n/app_strings.dart';
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

  /// Opens what this computer may authorize. Absent where the card is read
  /// only.
  final VoidCallback? onPermissions;

  @override
  Widget build(BuildContext context) {
    final strings = AppStrings.of(context);
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
                    Text(strings.deviceBlocked)
                  else
                    ConnectionStatus(phase: device.phase),
                  const SizedBox(height: 4),
                  Text(
                    strings.deviceLastSeen(
                      _relativeTime(strings, device.lastSeen),
                    ),
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
              tooltip: strings.deviceMenu,
              itemBuilder: (context) => [
                if (onPermissions case final open?)
                  PopupMenuItem<void>(
                    onTap: open,
                    child: Text(strings.devicePermissions),
                  ),
                PopupMenuItem<void>(
                  onTap: () => _confirmRevoke(context),
                  child: Text(strings.deviceRevoke),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _confirmRevoke(BuildContext context) async {
    final strings = AppStrings.of(context);
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        // Scrollable, because a dialog is not exempt from the system font: the
        // box is capped at the screen and its content is not, so past a certain
        // size the text is cut off mid-sentence -- and here it is the sentence
        // explaining what the button below it destroys.
        scrollable: true,
        title: Text(strings.deviceRevokeTitle),
        content: Text(strings.deviceRevokeBody(device.name)),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: Text(strings.cancel),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: Text(strings.revoke),
          ),
        ],
      ),
    );
    if (confirmed == true) onRevoke();
  }

  String _relativeTime(AppStrings strings, DateTime at) {
    final elapsed = DateTime.now().toUtc().difference(at);
    if (elapsed.inMinutes < 1) return strings.deviceJustNow;
    if (elapsed.inHours < 1) return strings.deviceMinutesAgo(elapsed.inMinutes);
    if (elapsed.inDays < 1) return strings.deviceHoursAgo(elapsed.inHours);
    return strings.deviceDaysAgo(elapsed.inDays);
  }
}

/// One credential this desktop holds, named for what it can ask for.
class _PurposeChip extends StatelessWidget {
  const _PurposeChip({required this.purpose});

  final CredentialPurpose purpose;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final icon = switch (purpose) {
      CredentialPurpose.authorization => Icons.lock_outline,
      CredentialPurpose.diskUnlock => Icons.storage,
      CredentialPurpose.webAuthn => Icons.password,
      CredentialPurpose.vault => Icons.vpn_key_outlined,
      CredentialPurpose.fileLocker => Icons.folder_outlined,
      CredentialPurpose.ssh => Icons.terminal,
    };
    final label = AppStrings.of(context).credentialPurpose(purpose);

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
