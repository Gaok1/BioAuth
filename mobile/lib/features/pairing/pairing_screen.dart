import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/protocol/enrolment.dart';
import '../../shared/page_heading.dart';
import '../../shared/pairing_qr_scanner.dart';
import '../../shared/verification_code_panel.dart';
import 'pairing_controller.dart';

class PairingScreen extends ConsumerWidget {
  const PairingScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(pairingControllerProvider);
    final controller = ref.read(pairingControllerProvider.notifier);

    return ListView(
      padding: const EdgeInsets.only(bottom: 32),
      children: [
        const PageHeading(
          title: 'Parear dispositivo',
          subtitle: 'Escaneie o QR exibido pelo computador',
        ),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 24),
          child: switch (state.stage) {
            PairingStage.idle => PairingQRScanner(
              onDetect: controller.submitScan,
            ),
            PairingStage.connecting => const _Busy(
              label: 'Conectando ao computador…',
            ),
            PairingStage.awaitingCode => VerificationCodePanel(
              code: state.verificationCode!,
              verifierId: state.verifierId!,
              purpose: state.purpose ?? CredentialPurpose.authorization,
              onConfirm: controller.confirm,
              onReject: controller.reject,
            ),
            PairingStage.paired => _Result(
              icon: Icons.verified_user,
              title: state.message ?? 'Pareado.',
              detail:
                  'Conclua a autorização no computador para liberar as '
                  'permissões desta credencial.',
              onDismiss: controller.reset,
            ),
            PairingStage.failed => _Result(
              icon: Icons.error_outline,
              title: 'Pareamento não concluído',
              detail: state.message ?? 'Tente novamente.',
              onDismiss: controller.reset,
            ),
          },
        ),
        const SizedBox(height: 24),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 28),
          child: Text(
            'O QR autentica o computador para o telefone. O código de seis '
            'dígitos fecha o outro sentido: sem ele, quem fotografar a tela '
            'poderia parear no seu lugar.',
            textAlign: TextAlign.center,
            style: Theme.of(context).textTheme.bodyMedium,
          ),
        ),
      ],
    );
  }
}

class _Busy extends StatelessWidget {
  const _Busy({required this.label});

  final String label;

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 48),
    child: Column(
      children: [
        const CircularProgressIndicator(),
        const SizedBox(height: 20),
        Text(label, style: Theme.of(context).textTheme.bodyLarge),
      ],
    ),
  );
}

class _Result extends StatelessWidget {
  const _Result({
    required this.icon,
    required this.title,
    required this.detail,
    required this.onDismiss,
  });

  final IconData icon;
  final String title;
  final String detail;
  final VoidCallback onDismiss;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          children: [
            Icon(icon, size: 48, color: theme.colorScheme.primary),
            const SizedBox(height: 16),
            Text(
              title,
              textAlign: TextAlign.center,
              style: theme.textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text(
              detail,
              textAlign: TextAlign.center,
              style: theme.textTheme.bodyMedium,
            ),
            const SizedBox(height: 20),
            FilledButton(onPressed: onDismiss, child: const Text('Concluir')),
          ],
        ),
      ),
    );
  }
}
