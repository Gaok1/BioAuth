import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../app/app_controller.dart';
import '../../app/app_state.dart';
import '../../l10n/app_strings.dart';
import '../../shared/authentication_request_card.dart';
import '../../shared/device_card.dart';
import '../../shared/page_heading.dart';
import '../authentication/authentication_request_screen.dart';
import '../permissions/permission_screen.dart';

class DevicesScreen extends ConsumerWidget {
  const DevicesScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final strings = AppStrings.of(context);
    final state = ref.watch(appControllerProvider);
    return CustomScrollView(
      slivers: [
        SliverToBoxAdapter(child: PageHeading(title: strings.appTitle)),
        if (state.securityWarning case final warning?)
          SliverToBoxAdapter(child: _SecurityWarningCard(warning: warning)),
        if (state.requests.isNotEmpty) ...[
          SliverToBoxAdapter(child: _SectionTitle(strings.devicesRequests)),
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
        SliverToBoxAdapter(child: _SectionTitle(strings.devicesPaired)),
        if (state.devices.isEmpty)
          SliverToBoxAdapter(
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 20),
              child: Card(
                child: Padding(
                  padding: const EdgeInsets.all(24),
                  child: Text(strings.devicesEmpty),
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
                  // Where this computer's permissions are edited. The desktop
                  // holds the same list and the two reconcile, so either side
                  // is as good a place to edit as the other -- which is the
                  // point of this screen existing here at all.
                  onPermissions: () => Navigator.of(context).push(
                    MaterialPageRoute<void>(
                      builder: (_) => PermissionScreen(
                        verifierId: device.id,
                        verifierName: device.name,
                      ),
                    ),
                  ),
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
    final strings = AppStrings.of(context);
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
                strings.devicesFloodTitle,
                style: Theme.of(context).textTheme.titleMedium,
              ),
              const SizedBox(height: 8),
              Text(
                strings.devicesFloodBody(
                  warning.deviceName,
                  warning.requestCount,
                  warning.window.inSeconds,
                ),
              ),
              const SizedBox(height: 12),
              FilledButton.tonalIcon(
                onPressed: () => ref
                    .read(appControllerProvider.notifier)
                    .blockDevice(warning.deviceId),
                icon: const Icon(Icons.block),
                label: Text(strings.devicesBlockForFifteenMinutes),
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
