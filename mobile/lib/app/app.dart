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
class _SessionHost extends ConsumerWidget {
  const _SessionHost({required this.child});

  final Widget child;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    if (!ref.watch(appConfigProvider).mockEnabled) {
      ref.watch(pairedSessionRunnerProvider);
    }
    return child;
  }
}
