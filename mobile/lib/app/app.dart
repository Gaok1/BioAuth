import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../features/onboarding/onboarding_screen.dart';
import '../features/pairing/pairing_controller.dart';
import '../l10n/app_strings.dart';
import '../l10n/language_preference.dart';
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
      onGenerateTitle: (context) => AppStrings.of(context).appTitle,
      // Follows the phone unless the user picked one in Settings.
      // `supportedLocales` is what makes that resolution possible: a phone set
      // to anything the app does not ship lands on the first entry, English.
      locale: ref.watch(languageProvider),
      supportedLocales: AppStrings.supportedLocales,
      localizationsDelegates: const [
        AppStrings.delegate,
        ...GlobalMaterialLocalizations.delegates,
      ],
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
          // The verification code is a sheet too, and the most consequential
          // one: confirming it is what makes a computer trusted. It was the
          // one this rule was never applied to. A code left on screen stayed
          // confirmable across a trip to the background, so a tap landing on
          // the way back paired a desktop scanned who knows when -- and until
          // then the phone held an open authenticated socket to it and the
          // desktop held a proposal waiting on an answer.
          if (ref.read(pairingControllerProvider).stage ==
              PairingStage.awaitingCode) {
            unawaited(ref.read(pairingControllerProvider.notifier).reset());
          }
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
