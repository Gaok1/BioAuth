import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../features/onboarding/onboarding_screen.dart';
import 'app_controller.dart';
import 'router.dart';
import 'theme.dart';

class PhoneAuthApp extends ConsumerWidget {
  const PhoneAuthApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final onboardingComplete = ref.watch(
      appControllerProvider.select((state) => state.onboardingComplete),
    );

    return MaterialApp(
      title: 'Phone Auth',
      debugShowCheckedModeBanner: false,
      theme: buildTheme(Brightness.light),
      darkTheme: buildTheme(Brightness.dark),
      home: onboardingComplete ? const HomeShell() : const OnboardingScreen(),
    );
  }
}
