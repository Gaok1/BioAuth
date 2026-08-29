/// The screen an SSH login has to pass before the key is used.
///
/// `SYS-02`. This one is not like the vault's, and the difference is worth
/// stating: a copied password is spent when it is pasted, and an SSH signature
/// opens a session that lasts as long as the terminal stays open. Approving
/// here is approving everything that happens in that session.
///
/// So it names the account and the destination, and it says plainly when it
/// does not know the destination — an `ssh` older than 8.9 sends no
/// `session-bind`, and a blank where a hostname belongs reads as "no host
/// involved" rather than as "nobody told me".
library;

import 'package:flutter/material.dart';

import '../../core/ssh/ssh_service.dart';

/// Shows the sheet and resolves to what the user chose.
///
/// Dismissing resolves false. No path returns true without a tap on the button
/// that says so.
/// [withdrawn] is the answer to this request from anywhere -- the session that
/// raised it dying, the app leaving the foreground. It resolves the moment the
/// request stops being answerable, and the sheet takes itself down: buttons
/// that no longer reach a session must not look live, because tapping them
/// looks to the user exactly like approving.
Future<bool> showSshApprovalSheet(
  BuildContext context,
  SshApprovalRequest request, {
  Future<bool>? withdrawn,
}) async {
  final approved = await showModalBottomSheet<bool>(
    context: context,
    isScrollControlled: true,
    useSafeArea: true,
    isDismissible: true,
    builder: (context) =>
        _SshApprovalSheet(request: request, withdrawn: withdrawn),
  );
  return approved ?? false;
}

class _SshApprovalSheet extends StatefulWidget {
  const _SshApprovalSheet({required this.request, this.withdrawn});

  final SshApprovalRequest request;
  final Future<bool>? withdrawn;

  @override
  State<_SshApprovalSheet> createState() => _SshApprovalSheetState();
}

class _SshApprovalSheetState extends State<_SshApprovalSheet> {
  @override
  void initState() {
    super.initState();
    // Answered elsewhere. When the user is the one answering, the sheet is
    // already gone by the time this resolves, so `mounted` is the whole guard.
    widget.withdrawn?.then((_) {
      if (mounted) Navigator.of(context).pop(false);
    });
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = theme.colorScheme;
    final named = widget.request.destination.isNotEmpty;

    // Scrolls, because the sheet is sized by its contents and its contents are
    // sized by the system font and by names the computer chose. Past a certain
    // height a `Column` does not shrink -- it puts its last children below the
    // bottom edge, and here those are "Aprovar" and "Recusar". A request that
    // can be neither approved nor refused looks, from the computer, like a
    // phone that stopped answering.
    return SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(20, 12, 20, 20),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Center(
            child: Container(
              width: 36,
              height: 4,
              margin: const EdgeInsets.only(bottom: 20),
              decoration: BoxDecoration(
                color: colors.outlineVariant,
                borderRadius: BorderRadius.circular(2),
              ),
            ),
          ),
          Row(
            children: [
              Icon(Icons.terminal, color: colors.primary),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  'Entrar por SSH',
                  style: theme.textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 18),

          _Field(label: 'Computador', value: widget.request.verifierName),
          _Field(
            label: 'Entrar como',
            value: widget.request.user,
            emphasis: true,
          ),
          _Field(
            label: 'Servidor',
            // The fingerprint, not a hostname: it is what the client can prove
            // and what `ssh` itself prints when it asks about an unknown host,
            // so the two can be compared.
            value: named
                ? widget.request.destination
                : 'não informado por este computador',
            emphasis: named,
          ),

          const SizedBox(height: 16),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: named
                  ? colors.surfaceContainerHighest
                  : colors.errorContainer,
              borderRadius: BorderRadius.circular(10),
            ),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Icon(
                  named ? Icons.info_outline : Icons.warning_amber_outlined,
                  size: 18,
                  color: named ? colors.onSurface : colors.onErrorContainer,
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    named
                        ? 'Aprovar abre uma sessão nesse servidor. Ela continua '
                              'aberta enquanto o terminal estiver aberto — não é '
                              'uma permissão que acaba agora.'
                        : 'Este computador não disse para qual servidor está '
                              'entrando. Só aprove se você acabou de rodar um '
                              '`ssh` e sabe para onde.',
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: named ? null : colors.onErrorContainer,
                    ),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 20),

          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Aprovar login'),
          ),
          const SizedBox(height: 8),
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Recusar'),
          ),
        ],
      ),
    );
  }
}

class _Field extends StatelessWidget {
  const _Field({
    required this.label,
    required this.value,
    this.emphasis = false,
  });

  final String label;
  final String value;
  final bool emphasis;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 104,
            child: Text(
              label,
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: emphasis
                  ? theme.textTheme.bodyLarge?.copyWith(
                      fontWeight: FontWeight.w700,
                    )
                  : theme.textTheme.bodyMedium,
            ),
          ),
        ],
      ),
    );
  }
}
