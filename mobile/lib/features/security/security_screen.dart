import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:phone_auth_native/phone_auth_native.dart';

import '../../app/providers.dart';
import '../../l10n/app_strings.dart';
import '../../shared/security_status.dart';

class SecurityScreen extends ConsumerWidget {
  const SecurityScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final strings = AppStrings.of(context);
    final capabilities = ref.watch(securityCapabilitiesProvider);
    final background = ref.watch(backgroundSessionsReadyProvider);
    return Scaffold(
      appBar: AppBar(title: Text(strings.securityTitle)),
      body: ListView(
        padding: const EdgeInsets.symmetric(vertical: 12),
        children: [
          capabilities.when(
            data: (data) => _keyStatus(strings, data),
            loading: () => SecurityStatus(
              title: strings.securityKey,
              detail: strings.securityChecking,
              secure: false,
            ),
            error: (_, _) => SecurityStatus(
              title: strings.securityKey,
              detail: strings.securityKeyUnknown,
              secure: false,
            ),
          ),
          capabilities.when(
            data: (data) => _biometricStatus(strings, data),
            loading: () => SecurityStatus(
              title: strings.securityBiometrics,
              detail: strings.securityChecking,
              secure: false,
            ),
            error: (_, _) => SecurityStatus(
              title: strings.securityBiometrics,
              detail: strings.securityBiometricsUnknown,
              secure: false,
            ),
          ),
          background.when(
            data: (ready) => SecurityStatus(
              title: strings.securityBackground,
              detail: ready
                  ? strings.securityBackgroundRunning
                  : strings.securityBackgroundIdle,
              secure: ready,
            ),
            loading: () => SecurityStatus(
              title: strings.securityBackground,
              detail: strings.securityChecking,
              secure: false,
            ),
            error: (_, _) => SecurityStatus(
              title: strings.securityBackground,
              detail: strings.securityBackgroundUnknown,
              secure: false,
            ),
          ),
        ],
      ),
    );
  }

  static SecurityStatus _keyStatus(
    AppStrings strings,
    SecurityCapabilities capabilities,
  ) {
    final detail = !capabilities.keyExists
        ? strings.securityKeyMissing
        : capabilities.strongBoxBacked
        ? strings.securityKeyStrongBox
        : capabilities.hardwareBacked
        ? strings.securityKeyHardware
        : strings.securityKeySoftware;
    return SecurityStatus(
      title: strings.securityKey,
      detail: detail,
      secure: capabilities.keyExists && capabilities.hardwareBacked,
    );
  }

  static SecurityStatus _biometricStatus(
    AppStrings strings,
    SecurityCapabilities capabilities,
  ) {
    final biometrics = capabilities.biometrics;
    final available =
        biometrics.availability == BiometricAvailability.available;
    return SecurityStatus(
      title: strings.securityBiometrics,
      detail: switch (biometrics.availability) {
        BiometricAvailability.available when biometrics.strongBiometrics =>
          strings.securityBiometricsStrong,
        BiometricAvailability.available => strings.securityBiometricsWeak,
        BiometricAvailability.noneEnrolled =>
          strings.securityBiometricsNoneEnrolled,
        BiometricAvailability.temporarilyUnavailable =>
          strings.securityBiometricsTemporarilyUnavailable,
        BiometricAvailability.unavailable =>
          strings.securityBiometricsUnavailable,
        BiometricAvailability.unsupported =>
          strings.securityBiometricsUnsupported,
        BiometricAvailability.unknown => strings.securityBiometricsUnknown,
      },
      secure: available && biometrics.strongBiometrics,
    );
  }
}
