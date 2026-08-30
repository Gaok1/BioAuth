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
    // Built lazily, not spread into a `ListView`'s children. This screen is a
    // tab of an `IndexedStack`, so it is in the tree whichever tab is showing
    // -- an eager list rebuilt every tile on every change to the log, off
    // screen, while the user was somewhere else. That was affordable while
    // only a person's taps could add a row.
    return ListView.builder(
      itemCount: entries.isEmpty ? 2 : entries.length + 1,
      itemBuilder: (context, index) {
        if (index == 0) {
          return const PageHeading(
            title: 'Histórico',
            subtitle: 'Decisões registradas somente neste aparelho',
          );
        }
        if (entries.isEmpty) {
          return const Padding(
            padding: EdgeInsets.all(24),
            child: Center(child: Text('Nenhuma atividade registrada.')),
          );
        }
        return AuditEntryTile(entry: entries[index - 1]);
      },
    );
  }
}
