import 'package:flutter/material.dart';

import '../domain/audit_entry.dart';

class AuditEntryTile extends StatelessWidget {
  const AuditEntryTile({required this.entry, super.key});

  final AuditEntry entry;

  @override
  Widget build(BuildContext context) {
    final (label, icon, color) = switch (entry.outcome) {
      AuditOutcome.approved => ('Aprovado', Icons.check_circle, Colors.green),
      AuditOutcome.denied => ('Negado', Icons.cancel, Colors.orange),
      AuditOutcome.expired => ('Expirado', Icons.timer_off, Colors.grey),
      AuditOutcome.blocked => (
        'Bloqueado',
        Icons.block,
        Theme.of(context).colorScheme.error,
      ),
    };

    return ListTile(
      leading: Icon(icon, color: color),
      title: Text('${entry.service} • ${entry.resource}'),
      subtitle: Text('${entry.deviceName} • $label'),
      trailing: Text(_time(entry.timestamp)),
    );
  }

  String _time(DateTime at) =>
      '${at.hour.toString().padLeft(2, '0')}:${at.minute.toString().padLeft(2, '0')}';
}
