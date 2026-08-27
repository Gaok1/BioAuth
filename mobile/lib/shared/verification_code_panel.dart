import 'package:flutter/material.dart';

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
  });

  final String code;
  final String verifierId;
  final Future<void> Function() onConfirm;
  final Future<void> Function() onReject;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Card(
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 28, horizontal: 20),
        child: Column(
          children: [
            Text(
              'Confira o código em $verifierId',
              textAlign: TextAlign.center,
              style: theme.textTheme.titleMedium,
            ),
            const SizedBox(height: 20),
            Semantics(
              label: 'Código de verificação ${code.split('').join(' ')}',
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
            Text(
              'Só confirme se o computador mostrar exatamente estes seis '
              'dígitos. Se forem diferentes, alguém está no meio da conexão.',
              textAlign: TextAlign.center,
              style: theme.textTheme.bodyMedium,
            ),
            const SizedBox(height: 24),
            Row(
              children: [
                Expanded(
                  child: OutlinedButton(
                    onPressed: onReject,
                    child: const Text('São diferentes'),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: FilledButton(
                    onPressed: onConfirm,
                    child: const Text('Conferem'),
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
