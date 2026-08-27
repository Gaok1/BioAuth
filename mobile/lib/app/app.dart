import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../features/onboarding/onboarding_screen.dart';
import 'app_controller.dart';
import 'config.dart';
import 'providers.dart';
import 'router.dart';
import 'theme.dart';

class PhoneAuthApp extends ConsumerWidget {
  const PhoneAuthApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return MaterialApp(
      title: 'Phone Auth',
      debugShowCheckedModeBanner: false,
      theme: buildTheme(Brightness.light),
      darkTheme: buildTheme(Brightness.dark),
      home: const _SessionHost(child: _Home()),
    );
  }
}

class _Home extends ConsumerWidget {
  const _Home();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final onboardingComplete = ref.watch(
      appControllerProvider.select((state) => state.onboardingComplete),
    );
    return onboardingComplete ? const HomeShell() : const OnboardingScreen();
  }
}

/// Holds the connections to paired desktops open while the app is on screen.
///
/// Watching a provider is what starts it, so this is the thing that decides the
/// phone is listening. It is deliberately not in `main`: an app that is not
/// running has no business holding sockets open, and the mock flavour must be
/// able to run with no network at all.
class _SessionHost extends ConsumerStatefulWidget {
  const _SessionHost({required this.child});

  final Widget child;

  @override
  ConsumerState<_SessionHost> createState() => _SessionHostState();
}

class _SessionHostState extends ConsumerState<_SessionHost>
    with WidgetsBindingObserver {
  bool _foreground = true;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    // `inactive` counts as on screen. Android reports it whenever the window
    // loses focus — the notification shade, a permission dialog, and the
    // biometric prompt itself. Tearing the session down there would abandon
    // the very request the user is authenticating.
    final foreground =
        state == AppLifecycleState.resumed ||
        state == AppLifecycleState.inactive;
    if (foreground != _foreground) setState(() => _foreground = foreground);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (!ref.watch(appConfigProvider).mockEnabled) {
      ref.watch(pairedDevicesSyncProvider);
      if (_foreground) ref.watch(pairedSessionRunnerProvider);
    }
    return widget.child;
  }
}
