import 'package:flutter/material.dart';
import 'package:phone_auth_native/phone_auth_native.dart';

import '../../l10n/app_strings.dart';

class PasskeysScreen extends StatefulWidget {
  const PasskeysScreen({super.key});

  @override
  State<PasskeysScreen> createState() => _PasskeysScreenState();
}

class _PasskeysScreenState extends State<PasskeysScreen> {
  final _passkeys = const PhoneAuthPasskeys();
  late Future<List<ManagedPasskey>> _items = _passkeys.list();

  void _reload() => setState(() {
    _items = _passkeys.list();
  });

  Future<void> _delete(ManagedPasskey passkey) async {
    final strings = AppStrings.of(context);
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        // Scrollable, because a dialog is not exempt from the system font: the
        // box is capped at the screen and its content is not, so past a certain
        // size the text is cut off mid-sentence -- and here it is the sentence
        // explaining what the button below it destroys.
        scrollable: true,
        title: Text(strings.passkeysDeleteTitle),
        content: Text(
          passkey.kind == 'orphan'
              ? strings.passkeysDeleteOrphanBody
              : strings.passkeysDeleteBody(passkey.userName, passkey.rpId),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: Text(strings.cancel),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: Text(strings.continueLabel),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;
    try {
      await _passkeys.delete(passkey);
    } catch (_) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text(strings.passkeysDeleteFailed)));
      }
      return;
    }
    if (!mounted) return;
    _reload();
  }

  @override
  Widget build(BuildContext context) {
    final strings = AppStrings.of(context);
    return Scaffold(
      appBar: AppBar(title: Text(strings.passkeysTitle)),
      body: FutureBuilder<List<ManagedPasskey>>(
        future: _items,
        builder: (context, snapshot) {
          if (snapshot.connectionState != ConnectionState.done) {
            return const Center(child: CircularProgressIndicator());
          }
          if (snapshot.hasError) {
            return Center(
              child: FilledButton.icon(
                onPressed: _reload,
                icon: const Icon(Icons.refresh),
                label: Text(strings.retry),
              ),
            );
          }
          final items = snapshot.data!;
          if (items.isEmpty) {
            return Center(child: Text(strings.passkeysEmpty));
          }
          return ListView.separated(
            itemCount: items.length,
            separatorBuilder: (_, _) => const Divider(height: 1),
            itemBuilder: (context, index) {
              final item = items[index];
              final healthy = item.status == ManagedPasskeyStatus.available;
              final date = item.createdAt?.toIso8601String().substring(0, 10);
              return ListTile(
                leading: Icon(
                  healthy ? Icons.key : Icons.warning_amber,
                  color: healthy ? null : Theme.of(context).colorScheme.error,
                ),
                title: Text(
                  item.rpId.isEmpty ? strings.passkeysOrphan : item.rpId,
                ),
                subtitle: Text(
                  healthy
                      ? strings.passkeysCreatedOn(
                          item.userDisplayName,
                          date ?? '',
                        )
                      : _statusLabel(strings, item.status),
                ),
                trailing: IconButton(
                  tooltip: strings.passkeysDelete,
                  onPressed: () => _delete(item),
                  icon: const Icon(Icons.delete_outline),
                ),
              );
            },
          );
        },
      ),
    );
  }
}

String _statusLabel(AppStrings strings, ManagedPasskeyStatus status) =>
    switch (status) {
      ManagedPasskeyStatus.available => strings.passkeyStatusAvailable,
      ManagedPasskeyStatus.missingKey => strings.passkeyStatusMissingKey,
      ManagedPasskeyStatus.invalidKey => strings.passkeyStatusInvalidKey,
      ManagedPasskeyStatus.orphanKey => strings.passkeyStatusOrphanKey,
    };
