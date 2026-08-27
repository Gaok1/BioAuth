import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../domain/app_seed.dart';

enum AppFlavor { development, staging, production }

class AppConfig {
  const AppConfig.production()
    : flavor = AppFlavor.production,
      mockEnabled = false,
      seed = const AppSeed.empty();

  const AppConfig.staging()
    : flavor = AppFlavor.staging,
      mockEnabled = false,
      seed = const AppSeed.empty();

  AppConfig.development(AppSeed developmentSeed)
    : flavor = AppFlavor.development,
      mockEnabled = !kReleaseMode,
      seed = kReleaseMode ? const AppSeed.empty() : developmentSeed;

  final AppFlavor flavor;
  final bool mockEnabled;
  final AppSeed seed;
}

final appConfigProvider = Provider<AppConfig>(
  (ref) => const AppConfig.production(),
);
