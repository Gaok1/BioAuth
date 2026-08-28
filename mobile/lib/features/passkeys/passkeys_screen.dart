import 'package:flutter/material.dart';
import 'package:phone_auth_native/phone_auth_native.dart';

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
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Excluir passkey?'),
        content: Text(
          passkey.kind == 'orphan'
              ? 'Esta chave órfã não possui metadados recuperáveis.'
              : 'A passkey de ${passkey.userName} em ${passkey.rpId} será removida deste telefone. O site pode exigir outro método de acesso.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancelar'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Continuar'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;
    try {
      await _passkeys.delete(passkey);
    } catch (_) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Não foi possível excluir a passkey.')),
        );
      }
      return;
    }
    if (!mounted) return;
    _reload();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Passkeys')),
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
                label: const Text('Tentar novamente'),
              ),
            );
          }
          final items = snapshot.data!;
          if (items.isEmpty) {
            return const Center(child: Text('Nenhuma passkey neste telefone.'));
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
                title: Text(item.rpId.isEmpty ? 'Chave órfã' : item.rpId),
                subtitle: Text(
                  healthy
                      ? '${item.userDisplayName} · criada em $date'
                      : _statusLabel(item.status),
                ),
                trailing: IconButton(
                  tooltip: 'Excluir passkey',
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

String _statusLabel(ManagedPasskeyStatus status) => switch (status) {
  ManagedPasskeyStatus.available => 'Disponível',
  ManagedPasskeyStatus.missingKey => 'Metadados sem chave correspondente',
  ManagedPasskeyStatus.invalidKey => 'Chave invalidada pela biometria',
  ManagedPasskeyStatus.orphanKey => 'Chave sem metadados correspondentes',
};
