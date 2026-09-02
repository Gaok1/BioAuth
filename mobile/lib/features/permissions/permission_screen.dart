import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../app/providers.dart';
import '../../core/permissions/permission_store.dart';
import '../../l10n/app_strings.dart';
import 'permission_controller.dart';

/// What a paired computer may authorize, editable from here.
///
/// The desktop holds the same list and the two reconcile. Editing here does
/// not talk to it -- this side never opens a session -- so the change takes
/// effect the next time it connects, which is what the screen says.
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
    final strings = AppStrings.of(context);
    return Scaffold(
      appBar: AppBar(
        title: Text(strings.permissionsTitle(widget.verifierName)),
      ),
      body: _controller.loading
          ? const Center(child: CircularProgressIndicator())
          : ListView(
              padding: const EdgeInsets.fromLTRB(16, 8, 16, 32),
              children: [
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(16),
                    child: Text(strings.permissionsAppliesOnNextConnection),
                  ),
                ),
                if (_controller.saveFailed) ...[
                  const SizedBox(height: 12),
                  Card(
                    color: Theme.of(context).colorScheme.errorContainer,
                    child: Padding(
                      padding: const EdgeInsets.all(16),
                      child: Text(strings.permissionsSaveFailed),
                    ),
                  ),
                ],
                if (_controller.credentials.isEmpty)
                  Padding(
                    padding: const EdgeInsets.all(24),
                    child: Text(strings.permissionsNoCredentials),
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
                          for (final service in PermissionController.grantable)
                            SwitchListTile(
                              key: Key(
                                'grant ${credential.credentialId} $service',
                              ),
                              dense: true,
                              contentPadding: EdgeInsets.zero,
                              title: Text(strings.permissionService(service)),
                              value: credential.services.contains(service),
                              onChanged: (granted) => _controller.toggle(
                                credential.credentialId,
                                service,
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
