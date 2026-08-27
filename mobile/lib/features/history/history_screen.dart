import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../app/app_controller.dart';
import '../../shared/audit_entry_tile.dart';
import '../../shared/page_heading.dart';

class HistoryScreen extends ConsumerWidget {
  const HistoryScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final entries = ref.watch(
      appControllerProvider.select((state) => state.auditEntries),
    );
    return ListView(
      children: [
        const PageHeading(
          title: 'Histórico',
          subtitle: 'Decisões registradas somente neste aparelho',
        ),
        if (entries.isEmpty)
          const Padding(
            padding: EdgeInsets.all(24),
            child: Center(child: Text('Nenhuma atividade registrada.')),
          )
        else
          ...entries.map((entry) => AuditEntryTile(entry: entry)),
      ],
    );
  }
}
