import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
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
      // Every string this app writes is in Portuguese; every string Flutter
      // writes was in English, because with no delegates a `MaterialApp` runs
      // on `DefaultMaterialLocalizations` and supports `en_US` alone. That is
      // "Show menu" on each item's overflow button, "Cut / Copy / Paste" over
      // every text field, "Back" on every back button, and "Alert" announced
      // by TalkBack on every dialog the vault puts up.
      //
      // Pinned rather than resolved from the phone: the interface is written
      // in Portuguese and nothing here translates it, so following a phone set
      // to English would produce half an app in each language.
      locale: const Locale('pt', 'BR'),
      supportedLocales: const [Locale('pt', 'BR')],
      localizationsDelegates: GlobalMaterialLocalizations.delegates,
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
    switch (state) {
      case AppLifecycleState.resumed:
        ref.invalidate(backgroundSessionsReadyProvider);

      // Focus lost while the app is still on screen: the biometric prompt,
      // the notification shade, a permission dialog. Approving a vault
      // request *raises* the biometric prompt, so refusing here refused the
      // request the user was in the middle of approving — the desktop was
      // told no by a person who was saying yes, and the phone looked broken
      // rather than strict. The transport already draws this distinction;
      // this handler did not.
      case AppLifecycleState.inactive:
        break;

      // A sheet the user can no longer see must not stay answerable. Leaving
      // is not an answer, so it becomes a refusal — otherwise a tap landing
      // on the sheet as the phone comes back would approve a request nobody
      // read.
      //
      // All three sheets, not just the vault's. The rule was written here in
      // general terms and applied to one of them: an untapped `sudo` and an
      // untapped SSH signature stayed answerable across a trip to the
      // background, and those are the two that grant more than a copied
      // password. `InteractiveSshApproval.abandonAll` even documented itself
      // with this sentence and was never called from here.
      case AppLifecycleState.hidden:
      case AppLifecycleState.paused:
      case AppLifecycleState.detached:
        if (!ref.read(appConfigProvider).mockEnabled) {
          ref.read(vaultApprovalProvider).abandonAll();
          ref.read(sshApprovalProvider).abandonAll();
          ref.read(interactiveAuthorizerProvider).abandonUnanswered();
        }
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
