import 'package:flutter/material.dart';

import '../domain/connection_phase.dart';
import '../l10n/app_strings.dart';

class ConnectionStatus extends StatelessWidget {
  const ConnectionStatus({required this.phase, super.key});

  final ConnectionPhase phase;

  @override
  Widget build(BuildContext context) {
    final color = switch (phase) {
      ConnectionPhase.connected || ConnectionPhase.approved => Colors.green,
      ConnectionPhase.scanning ||
      ConnectionPhase.connecting ||
      ConnectionPhase.secureHandshake ||
      ConnectionPhase.authenticationPending ||
      ConnectionPhase.awaitingBiometric ||
      ConnectionPhase.signing => Colors.orange,
      ConnectionPhase.error => Theme.of(context).colorScheme.error,
      _ => Colors.grey,
    };

    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Container(
          width: 9,
          height: 9,
          decoration: BoxDecoration(color: color, shape: BoxShape.circle),
        ),
        const SizedBox(width: 7),
        Text(AppStrings.of(context).connectionPhase(phase)),
      ],
    );
  }
}
