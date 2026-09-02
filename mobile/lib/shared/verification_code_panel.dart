import 'package:flutter/material.dart';

import '../core/protocol/enrolment.dart';
import '../l10n/app_strings.dart';

/// The six digits the user compares against the desktop's screen.
///
/// Both ends derive this from the same handshake exporter, which never went on
/// the wire. A relay sitting between the two produces a different transcript on
/// each side, so the codes differ — which is the whole point of showing them.
class VerificationCodePanel extends StatelessWidget {
  const VerificationCodePanel({
    super.key,
    required this.code,
    required this.verifierId,
    required this.onConfirm,
    required this.onReject,
    this.purpose = CredentialPurpose.authorization,
  });

  final String code;
  final String verifierId;

  /// What this credential will be able to do once confirmed.
  final CredentialPurpose purpose;
  final Future<void> Function() onConfirm;
  final Future<void> Function() onReject;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final strings = AppStrings.of(context);
    return Card(
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 28, horizontal: 20),
        child: Column(
          // Hugs its content. Without this the card stretches to whatever
          // height it is given, which is the full screen anywhere outside a
          // scroll view.
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              strings.verificationCheckOn(verifierId),
              textAlign: TextAlign.center,
              style: theme.textTheme.titleMedium,
            ),
            const SizedBox(height: 20),
            Semantics(
              label: strings.verificationCodeSpoken(code.split('').join(' ')),
              child: Text(
                // Grouped for reading aloud; the code itself is six digits.
                '${code.substring(0, 3)} ${code.substring(3)}',
                style: theme.textTheme.displaySmall?.copyWith(
                  fontFeatures: const [FontFeature.tabularFigures()],
                  letterSpacing: 6,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
            const SizedBox(height: 20),
            _PurposeNote(purpose: purpose),
            const SizedBox(height: 16),
            Text(
              strings.verificationWarning,
              textAlign: TextAlign.center,
              style: theme.textTheme.bodyMedium,
            ),
            const SizedBox(height: 24),
            Row(
              children: [
                Expanded(
                  child: OutlinedButton(
                    onPressed: onReject,
                    child: Text(strings.verificationDiffer),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: FilledButton(
                    onPressed: onConfirm,
                    child: Text(strings.verificationMatch),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

/// Says what the key being enrolled is for, in the words of what it will do.
///
/// The six digits answer "which computer". This answers "to do what", which is
/// the half that decides whether confirming is a good idea: an SSH credential
/// signs logins to servers, and someone who thought they were pairing for
/// `sudo` has no way to tell the difference afterwards — the list shows one
/// entry either way.
class _PurposeNote extends StatelessWidget {
  const _PurposeNote({required this.purpose});

  final CredentialPurpose purpose;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = theme.colorScheme;
    final icon = switch (purpose) {
      CredentialPurpose.authorization => Icons.lock_outline,
      CredentialPurpose.diskUnlock => Icons.storage,
      CredentialPurpose.webAuthn => Icons.password,
      CredentialPurpose.vault => Icons.vpn_key_outlined,
      CredentialPurpose.fileLocker => Icons.folder_outlined,
      CredentialPurpose.ssh => Icons.terminal,
    };
    final text = AppStrings.of(context).credentialPurposeNote(purpose);

    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: colors.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(10),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, size: 18, color: colors.onSurface),
          const SizedBox(width: 10),
          Expanded(child: Text(text, style: theme.textTheme.bodySmall)),
        ],
      ),
    );
  }
}
