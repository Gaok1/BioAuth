import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../features/onboarding/onboarding_screen.dart';
import 'app_controller.dart';
import 'config.dart';
import 'navigation.dart';
import 'providers.dart';
import 'router.dart';
import 'theme.dart';

class PhoneAuthApp extends ConsumerWidget {
  const PhoneAuthApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return MaterialApp(
      title: 'Phone Auth',
      navigatorKey: rootNavigatorKey,
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

/// Holds paired-desktop connections while Android's foreground service is up.
///
/// Watching a provider is what starts it, so this is the thing that decides the
/// phone is listening. The mock flavour still runs with no network at all.
class _SessionHost extends ConsumerStatefulWidget {
  const _SessionHost({required this.child});

  final Widget child;

  @override
  ConsumerState<_SessionHost> createState() => _SessionHostState();
}

class _SessionHostState extends ConsumerState<_SessionHost>
    with WidgetsBindingObserver {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      ref.invalidate(backgroundSessionsReadyProvider);
      return;
    }
    // A vault sheet the user can no longer see must not stay answerable. The
    // app going to the background is not an answer, so it becomes a refusal —
    // otherwise a tap landing on the sheet as the phone comes back would
    // approve a request the user never read.
    if (!ref.read(appConfigProvider).mockEnabled) {
      ref.read(vaultApprovalProvider).abandonAll();
    }
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
      if (ref.watch(backgroundSessionsReadyProvider).value == true) {
        ref.watch(pairedSessionRunnerProvider);
      }
    }
    return widget.child;
  }
}
