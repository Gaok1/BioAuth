import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'app_controller.dart';
import '../features/devices/devices_screen.dart';
import '../features/history/history_screen.dart';
import '../features/pairing/pairing_screen.dart';
import '../features/settings/settings_screen.dart';
import '../features/vault/vault_screen.dart';
import '../l10n/app_strings.dart';

class HomeShell extends ConsumerStatefulWidget {
  const HomeShell({super.key});

  @override
  ConsumerState<HomeShell> createState() => _HomeShellState();
}

class _HomeShellState extends ConsumerState<HomeShell> {
  int _index = 0;

  static const _screens = [
    DevicesScreen(),
    PairingScreen(),
    VaultScreen(),
    HistoryScreen(),
    SettingsScreen(),
  ];

  @override
  Widget build(BuildContext context) {
    // A request is only listed on the Devices screen, and nothing else on the
    // phone says one arrived: no notification is posted for it. Someone who
    // ran `sudo` and left the app on the Cofre tab saw no sign of it at all
    // and the desktop timed out, which from either seat is the pairing not
    // working. The count is what is already on the tab it points at.
    final waiting = ref.watch(
      appControllerProvider.select((state) => state.requests.length),
    );
    final strings = AppStrings.of(context);
    return Scaffold(
      body: SafeArea(
        child: IndexedStack(index: _index, children: _screens),
      ),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _index,
        onDestinationSelected: (value) => setState(() => _index = value),
        destinations: [
          NavigationDestination(
            icon: _waiting(
              strings,
              waiting,
              const Icon(Icons.devices_outlined),
            ),
            selectedIcon: _waiting(strings, waiting, const Icon(Icons.devices)),
            label: strings.tabDevices,
          ),
          NavigationDestination(
            icon: const Icon(Icons.qr_code_scanner),
            label: strings.tabPair,
          ),
          NavigationDestination(
            icon: const Icon(Icons.lock_outline),
            selectedIcon: const Icon(Icons.lock),
            label: strings.tabVault,
          ),
          NavigationDestination(
            icon: const Icon(Icons.history),
            label: strings.tabHistory,
          ),
          NavigationDestination(
            icon: const Icon(Icons.settings_outlined),
            selectedIcon: const Icon(Icons.settings),
            label: strings.tabSettings,
          ),
        ],
      ),
    );
  }

  /// The tab icon, carrying how many requests are waiting behind it.
  ///
  /// A count rather than a dot: two desktops asking at once is the case where
  /// the difference matters, and it is the case where answering the wrong one
  /// is easiest. Announced, because a badge is drawn and not read out.
  Widget _waiting(AppStrings strings, int count, Icon icon) => count == 0
      ? icon
      : Badge(
          label: Text('$count'),
          child: Semantics(label: strings.requestsWaiting(count), child: icon),
        );
}
