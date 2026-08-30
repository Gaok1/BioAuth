import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'app_controller.dart';
import '../features/devices/devices_screen.dart';
import '../features/history/history_screen.dart';
import '../features/pairing/pairing_screen.dart';
import '../features/settings/settings_screen.dart';
import '../features/vault/vault_screen.dart';

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
    return Scaffold(
      body: SafeArea(
        child: IndexedStack(index: _index, children: _screens),
      ),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _index,
        onDestinationSelected: (value) => setState(() => _index = value),
        destinations: [
          NavigationDestination(
            icon: _waiting(waiting, const Icon(Icons.devices_outlined)),
            selectedIcon: _waiting(waiting, const Icon(Icons.devices)),
            label: 'Dispositivos',
          ),
          const NavigationDestination(
            icon: Icon(Icons.qr_code_scanner),
            label: 'Parear',
          ),
          const NavigationDestination(
            icon: Icon(Icons.lock_outline),
            selectedIcon: Icon(Icons.lock),
            label: 'Cofre',
          ),
          const NavigationDestination(
            icon: Icon(Icons.history),
            label: 'Histórico',
          ),
          const NavigationDestination(
            icon: Icon(Icons.settings_outlined),
            selectedIcon: Icon(Icons.settings),
            label: 'Ajustes',
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
  Widget _waiting(int count, Icon icon) => count == 0
      ? icon
      : Badge(
          label: Text('$count'),
          child: Semantics(
            label: count == 1
                ? '1 solicitação aguardando'
                : '$count solicitações aguardando',
            child: icon,
          ),
        );
}
