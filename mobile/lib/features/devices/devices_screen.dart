import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../app/app_controller.dart';
import '../../app/app_state.dart';
import '../../shared/authentication_request_card.dart';
import '../../shared/device_card.dart';
import '../../shared/page_heading.dart';
import '../authentication/authentication_request_screen.dart';

class DevicesScreen extends ConsumerWidget {
  const DevicesScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(appControllerProvider);
    return CustomScrollView(
      slivers: [
        const SliverToBoxAdapter(
          child: PageHeading(
            title: 'Phone Auth',
            subtitle: 'Aprovações locais e seguras',
          ),
        ),
        if (state.securityWarning case final warning?)
          SliverToBoxAdapter(child: _SecurityWarningCard(warning: warning)),
        if (state.requests.isNotEmpty) ...[
          const SliverToBoxAdapter(child: _SectionTitle('Solicitações')),
          SliverPadding(
            padding: const EdgeInsets.symmetric(horizontal: 20),
            sliver: SliverList.separated(
              itemCount: state.requests.length,
              separatorBuilder: (_, _) => const SizedBox(height: 10),
              itemBuilder: (context, index) {
                final request = state.requests[index];
                return AuthenticationRequestCard(
                  request: request,
                  onTap: () => Navigator.of(context).push(
                    MaterialPageRoute<void>(
                      builder: (_) =>
                          AuthenticationRequestScreen(requestId: request.id),
                    ),
                  ),
                );
              },
            ),
          ),
        ],
        const SliverToBoxAdapter(child: _SectionTitle('Dispositivos')),
        if (state.devices.isEmpty)
          const SliverToBoxAdapter(
            child: Padding(
              padding: EdgeInsets.symmetric(horizontal: 20),
              child: Card(
                child: Padding(
                  padding: EdgeInsets.all(24),
                  child: Text('Nenhum dispositivo pareado.'),
                ),
              ),
            ),
          )
        else
          SliverPadding(
            padding: const EdgeInsets.fromLTRB(20, 0, 20, 32),
            sliver: SliverList.separated(
              itemCount: state.devices.length,
              separatorBuilder: (_, _) => const SizedBox(height: 10),
              itemBuilder: (context, index) {
                final device = state.devices[index];
                return DeviceCard(
                  device: device,
                  onRevoke: () => ref
                      .read(appControllerProvider.notifier)
                      .revokeDevice(device.id),
                );
              },
            ),
          ),
      ],
    );
  }
}

class _SecurityWarningCard extends ConsumerWidget {
  const _SecurityWarningCard({required this.warning});

  final SecurityWarning warning;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(20, 0, 20, 16),
      child: Card(
        color: Theme.of(context).colorScheme.errorContainer,
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Possível tentativa maliciosa',
                style: Theme.of(context).textTheme.titleMedium,
              ),
              const SizedBox(height: 8),
              Text(
                '${warning.deviceName} enviou ${warning.requestCount} '
                'solicitações em ${warning.window.inSeconds} segundos.',
              ),
              const SizedBox(height: 12),
              FilledButton.tonalIcon(
                onPressed: () => ref
                    .read(appControllerProvider.notifier)
                    .blockDevice(warning.deviceId),
                icon: const Icon(Icons.block),
                label: const Text('Bloquear dispositivo por 15 min'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _SectionTitle extends StatelessWidget {
  const _SectionTitle(this.title);

  final String title;

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.fromLTRB(20, 10, 20, 10),
    child: Text(title, style: Theme.of(context).textTheme.titleLarge),
  );
}
