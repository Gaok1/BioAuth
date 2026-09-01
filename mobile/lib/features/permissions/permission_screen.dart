import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../app/providers.dart';
import '../../core/permissions/permission_store.dart';
import 'permission_controller.dart';

/// O que um computador pareado pode autorizar, editável daqui.
///
/// A mesma lista existe no computador e as duas se acertam sozinhas. Editar
/// aqui não fala com ele — este lado nunca inicia sessão — então a mudança vale
/// a partir da próxima vez que ele conectar, e a tela diz isso em vez de fingir
/// que já aplicou.
class PermissionScreen extends ConsumerStatefulWidget {
  const PermissionScreen({
    required this.verifierId,
    required this.verifierName,
    super.key,
  });

  final String verifierId;
  final String verifierName;

  @override
  ConsumerState<PermissionScreen> createState() => _PermissionScreenState();
}

class _PermissionScreenState extends ConsumerState<PermissionScreen> {
  late final PermissionController _controller;

  @override
  void initState() {
    super.initState();
    _controller = PermissionController(
      pairings: ref.read(pairingStoreProvider),
      permissions: SharedPreferencesPermissionStore(),
      verifierId: widget.verifierId,
    );
    _controller.addListener(_onChanged);
    _controller.load();
  }

  void _onChanged() {
    if (mounted) setState(() {});
  }

  @override
  void dispose() {
    _controller.removeListener(_onChanged);
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('Permissões · ${widget.verifierName}')),
      body: _controller.loading
          ? const Center(child: CircularProgressIndicator())
          : ListView(
              padding: const EdgeInsets.fromLTRB(16, 8, 16, 32),
              children: [
                const Card(
                  child: Padding(
                    padding: EdgeInsets.all(16),
                    child: Text(
                      'Vale a partir da próxima conexão deste computador. '
                      'Ele também pode editar a mesma lista; a mais recente '
                      'vence, e num empate vale a deste aparelho.',
                    ),
                  ),
                ),
                if (_controller.failure case final failure?) ...[
                  const SizedBox(height: 12),
                  Card(
                    color: Theme.of(context).colorScheme.errorContainer,
                    child: Padding(
                      padding: const EdgeInsets.all(16),
                      child: Text(failure),
                    ),
                  ),
                ],
                if (_controller.credentials.isEmpty)
                  const Padding(
                    padding: EdgeInsets.all(24),
                    child: Text('Nenhuma credencial para este computador.'),
                  ),
                for (final credential in _controller.credentials) ...[
                  const SizedBox(height: 12),
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(16),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            credential.purpose.name,
                            style: Theme.of(context).textTheme.titleMedium,
                          ),
                          Text(
                            credential.credentialId,
                            style: Theme.of(context).textTheme.bodySmall,
                          ),
                          const SizedBox(height: 8),
                          for (final entry
                              in PermissionController.grantable.entries)
                            SwitchListTile(
                              key: Key(
                                'grant ${credential.credentialId} ${entry.key}',
                              ),
                              dense: true,
                              contentPadding: EdgeInsets.zero,
                              title: Text(entry.value),
                              value: credential.services.contains(entry.key),
                              onChanged: (granted) => _controller.toggle(
                                credential.credentialId,
                                entry.key,
                                granted,
                              ),
                            ),
                        ],
                      ),
                    ),
                  ),
                ],
              ],
            ),
    );
  }
}
