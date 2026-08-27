import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../app/app_controller.dart';
import '../../domain/authentication_request.dart';
import '../../domain/connection_phase.dart';
import '../../shared/connection_status.dart';

class AuthenticationRequestScreen extends ConsumerWidget {
  const AuthenticationRequestScreen({required this.requestId, super.key});

  final String requestId;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(appControllerProvider);
    final request = state.requests
        .where((candidate) => candidate.id == requestId)
        .firstOrNull;
    final phase = state.requestPhases[requestId];

    if (request == null) {
      return Scaffold(
        appBar: AppBar(title: const Text('Solicitação de acesso')),
        body: Center(
          child: phase == null
              ? const Text('Solicitação indisponível')
              : ConnectionStatus(phase: phase),
        ),
      );
    }

    final busy =
        phase == ConnectionPhase.awaitingBiometric ||
        phase == ConnectionPhase.signing;
    return Scaffold(
      appBar: AppBar(title: const Text('Solicitação de acesso')),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(20),
          children: [
            _RequestHeader(request: request),
            const SizedBox(height: 18),
            _ContextRow(label: 'Origem', value: request.origin),
            _ContextRow(label: 'Serviço', value: request.service),
            _ContextRow(label: 'Ação', value: request.action),
            _ContextRow(label: 'Destino', value: request.resource),
            _ContextRow(label: 'Usuário', value: request.user),
            _ContextRow(
              label: 'Horário',
              value: _formatTimestamp(request.requestedAt),
            ),
            if (request.duplicateCount > 1) ...[
              const SizedBox(height: 12),
              Text(
                '${request.duplicateCount} solicitações idênticas foram agrupadas.',
                style: TextStyle(
                  color: Theme.of(context).colorScheme.error,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
            if (busy && phase != null) ...[
              const SizedBox(height: 24),
              Center(child: ConnectionStatus(phase: phase)),
              const SizedBox(height: 12),
              const LinearProgressIndicator(),
            ],
            const SizedBox(height: 32),
            Row(
              children: [
                Expanded(
                  child: OutlinedButton(
                    onPressed: busy
                        ? null
                        : () {
                            ref
                                .read(appControllerProvider.notifier)
                                .deny(requestId);
                            Navigator.of(context).pop();
                          },
                    child: const Text('Negar'),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: FilledButton(
                    onPressed: busy
                        ? null
                        : () async {
                            await ref
                                .read(appControllerProvider.notifier)
                                .approve(requestId);
                            if (context.mounted) Navigator.of(context).pop();
                          },
                    child: const Text('Autorizar'),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  String _formatTimestamp(DateTime at) {
    final local = at.toLocal();
    return '${local.day.toString().padLeft(2, '0')}/'
        '${local.month.toString().padLeft(2, '0')} '
        '${local.hour.toString().padLeft(2, '0')}:'
        '${local.minute.toString().padLeft(2, '0')}';
  }
}

class _RequestHeader extends StatelessWidget {
  const _RequestHeader({required this.request});

  final AuthenticationRequest request;

  @override
  Widget build(BuildContext context) => Card(
    child: Padding(
      padding: const EdgeInsets.all(18),
      child: Row(
        children: [
          const CircleAvatar(child: Icon(Icons.computer)),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  request.deviceName,
                  style: Theme.of(context).textTheme.titleLarge,
                ),
                const Text('Confira os detalhes antes de autorizar'),
              ],
            ),
          ),
        ],
      ),
    ),
  );
}

class _ContextRow extends StatelessWidget {
  const _ContextRow({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 9),
    child: Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 90,
          child: Text(label, style: Theme.of(context).textTheme.labelLarge),
        ),
        Expanded(child: SelectableText(value)),
      ],
    ),
  );
}
