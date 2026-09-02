/// The screen a desktop's vault request has to pass before the Keystore is
/// asked for anything.
///
/// Everything on it is there to make one question answerable: *is this the
/// thing I just did on my computer?* The computer's name, the operation and
/// the item are all shown before the biometric, because after the biometric
/// there is nothing left to decide.
library;

import 'package:flutter/material.dart';

import '../../l10n/app_strings.dart';
import '../../core/vault/vault_approval.dart';

/// Shows the sheet and resolves to what the user chose.
///
/// Dismissing it — back gesture, tap outside — resolves false. There is no
/// path through this function that returns true without a tap on the button
/// that says so.
/// [withdrawn] is the answer to this request from anywhere -- the session that
/// raised it dying, the app leaving the foreground. It resolves the moment the
/// request stops being answerable, and the sheet takes itself down: buttons
/// that no longer reach a session must not look live, because tapping them
/// looks to the user exactly like approving.
Future<bool> showVaultApprovalSheet(
  BuildContext context,
  VaultApprovalRequest request, {
  Future<bool>? withdrawn,
}) async {
  final approved = await showModalBottomSheet<bool>(
    context: context,
    isScrollControlled: true,
    useSafeArea: true,
    // Not dismissible by accident, but still dismissible: a sheet the user
    // cannot get rid of is a sheet they will approve to make it go away.
    isDismissible: true,
    builder: (context) =>
        _VaultApprovalSheet(request: request, withdrawn: withdrawn),
  );
  return approved ?? false;
}

class _VaultApprovalSheet extends StatefulWidget {
  const _VaultApprovalSheet({required this.request, this.withdrawn});

  final VaultApprovalRequest request;
  final Future<bool>? withdrawn;

  @override
  State<_VaultApprovalSheet> createState() => _VaultApprovalSheetState();
}

class _VaultApprovalSheetState extends State<_VaultApprovalSheet> {
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
    final strings = AppStrings.of(context);
    final domain = widget.request.domain;

    // Scrolls, because the sheet is sized by its contents and its contents are
    // sized by the system font and by names the computer chose. Past a certain
    // height a `Column` does not shrink -- it puts its last children below the
    // bottom edge, and here those are approve and refuse. A request that
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
              Icon(
                widget.request.operation.releasesSecret
                    ? Icons.content_paste_go
                    : Icons.edit_outlined,
                color: colors.primary,
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  strings.vaultRequestTitle,
                  style: theme.textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 18),

          // The computer's own claim about its name, framed as a claim. The
          // phone verified the *pairing*, not that the name is honest, and the
          // wording must not promise more than that.
          _Field(
            label: strings.sshComputer,
            value: widget.request.verifierName,
          ),
          _Field(
            label: strings.vaultOperationLabel,
            value: strings.vaultOperation(widget.request.operation),
          ),
          _Field(
            label: strings.vaultItemLabel,
            value: widget.request.itemName,
            emphasis: true,
          ),
          if (widget.request.username.isNotEmpty)
            _Field(label: strings.requestUser, value: widget.request.username),
          if (domain.isNotEmpty)
            _Field(label: strings.vaultDomainLabel, value: domain),

          const SizedBox(height: 16),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: colors.surfaceContainerHighest,
              borderRadius: BorderRadius.circular(10),
            ),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Icon(Icons.info_outline, size: 18, color: colors.onSurface),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    widget.request.operation.releasesSecret
                        ? strings.vaultApprovalCopyNote
                        : strings.vaultApprovalWriteNote,
                    style: theme.textTheme.bodySmall,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 20),

          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: Text(
              widget.request.operation.releasesSecret
                  ? strings.vaultApproveCopy
                  : strings.approve,
            ),
          ),
          const SizedBox(height: 8),
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: Text(strings.refuse),
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
