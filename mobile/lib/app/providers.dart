/// Wiring for the real, non-mock stack.
///
/// Everything here is a `Provider` so the widget tests and the development
/// flavour can override one piece without rebuilding the rest. The production
/// defaults are the real ones: a TCP transport, the platform keystore, and
/// on-device storage.
library;

import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:phone_auth_native/phone_auth_native.dart';

import 'app_controller.dart';
import 'navigation.dart';

import '../core/auth/interactive_authorizer.dart';
import '../core/vault/vault_approval.dart';
import '../features/vault/vault_approval_sheet.dart';
import '../core/auth/native_biometric_authorizer.dart';
import '../core/bluetooth/ble_transport.dart';
import '../core/pairing/pairing_record.dart';
import '../core/pairing/pairing_service.dart';
import '../core/pairing/pairing_store.dart';
import '../domain/connection_phase.dart';
import '../core/session/paired_session_runner.dart';
import '../core/session/phone_auth_core.dart';
import '../core/transport/auth_transport.dart';
import '../core/transport/authenticated_session_establisher.dart';
import '../core/transport/fallback_auth_transport.dart';
import '../core/transport/qr_network_transport.dart';
import '../core/transport/secure_session_establisher.dart';
import '../core/transport/session_identity_crypto.dart';

final pairingStoreProvider = Provider<PairingStore>(
  (ref) => SharedPreferencesPairingStore(),
);

final securityCapabilitiesProvider = FutureProvider<SecurityCapabilities>(
  (ref) => const PhoneAuthNative().getSecurityCapabilities(),
);

/// This phone's stable identifier, created on first use.
final deviceIdProvider = FutureProvider<String>(
  (ref) => ref.watch(pairingStoreProvider).deviceId(),
);

/// The name the desktop shows in its paired-devices list.
///
/// Derived from the device id rather than from the hardware: two phones must be
/// distinguishable in that list, and a name taken from the device would follow
/// the user across every verifier they ever pair with.
final deviceNameProvider = FutureProvider<String>((ref) async {
  final id = await ref.watch(deviceIdProvider.future);
  final suffix = id.length <= 6 ? id : id.substring(id.length - 6);
  return 'PhoneAuth · $suffix';
});

final sessionIdentityProvider = Provider<SessionIdentityCrypto>(
  (ref) => NativeSessionIdentityCrypto(),
);

final sessionEstablisherProvider = FutureProvider<SecureSessionEstablisher>((
  ref,
) async {
  return AuthenticatedSessionEstablisher(
    deviceId: await ref.watch(deviceIdProvider.future),
    identity: ref.watch(sessionIdentityProvider),
  );
});

final transportProvider = FutureProvider<AuthTransport>((ref) async {
  final establisher = await ref.watch(sessionEstablisherProvider.future);
  final network = QrNetworkTransport(sessionEstablisher: establisher);
  if (defaultTargetPlatform != TargetPlatform.android) return network;

  return FallbackAuthTransport(
    primary: network,
    discoveredFallback: BleTransport(sessionEstablisher: establisher),
  );
});

final pairingServiceProvider = FutureProvider<PairingService>((ref) async {
  return PairingService(
    transport: await ref.watch(transportProvider.future),
    store: ref.watch(pairingStoreProvider),
    deviceName: await ref.watch(deviceNameProvider.future),
  );
});

final biometricAuthorizerProvider = Provider<BiometricAuthorizer>(
  (ref) => const NativeBiometricAuthorizer(),
);

/// Pairing records as stored. Invalidate after pairing or revoking.
final pairedVerifiersProvider = FutureProvider<List<PairingRecord>>(
  (ref) => ref.watch(pairingStoreProvider).load(),
);

/// Reflects durable pairings into UI state independently of session startup.
///
/// A provider listener is allowed to update another provider; doing it inside
/// the session runner's build made the devices list depend on transport timing.
final pairedDevicesSyncProvider = Provider<void>((ref) {
  ref.listen(pairedVerifiersProvider, (_, next) {
    next.whenData(ref.read(appControllerProvider.notifier).syncPairedDevices);
  }, fireImmediately: true);
});

/// Desktop sessions are allowed only while Android is showing its persistent
/// foreground-service notification. This is deliberately a hard dependency.
final backgroundSessionsReadyProvider = FutureProvider<bool>((ref) async {
  final records = await ref.watch(pairedVerifiersProvider.future);
  if (defaultTargetPlatform != TargetPlatform.android) {
    return records.isNotEmpty;
  }
  const sessions = PhoneAuthBackgroundSessions();
  if (records.isEmpty) {
    await sessions.setEnabled(false);
    return false;
  }
  return sessions.setEnabled(true);
});

/// The bridge between an arriving request and the screen the user taps.
///
/// Also the app's [PhoneAuthenticator]: the tap and the biometric prompt are
/// two halves of the same exchange, so one object owns both.
final interactiveAuthorizerProvider = Provider<InteractiveAuthorizer>((ref) {
  return InteractiveAuthorizer(
    // Read, not watch: this fires long after the graph is built, and watching
    // the controller from something the controller reads would be a cycle.
    onRequest: (request) =>
        ref.read(appControllerProvider.notifier).receive(request),
  );
});

/// The bridge between a desktop's vault request and the sheet that names it.
///
/// The Keystore prompt the store raises proves a finger, not an intention: it
/// looks identical whether the computer asked for a `sudo` or for a bank
/// password. This is where the request is turned into something a person can
/// actually agree or object to, and it runs before the store is touched.
final vaultApprovalProvider = Provider<InteractiveVaultApproval>((ref) {
  late final InteractiveVaultApproval approval;
  approval = InteractiveVaultApproval(
    onRequest: (request) async {
      // No activity on screen — the phone is locked, or Android killed the UI
      // and kept the service. There is nobody to ask, and an unasked question
      // is a refusal.
      final context = rootNavigatorKey.currentContext;
      if (context == null) {
        approval.settle(request.id, approved: false);
        return;
      }
      final approved = await showVaultApprovalSheet(context, request);
      approval.settle(request.id, approved: approved);
    },
  );
  return approval;
});

/// Holds a connection to every paired desktop while the foreground service is
/// available. The cached engine keeps this provider watched without an activity.
final pairedSessionRunnerProvider = Provider.autoDispose<PairedSessionRunner?>((
  ref,
) {
  final transport = ref.watch(transportProvider).value;
  final records = ref.watch(pairedVerifiersProvider).value;
  if (transport == null || records == null) return null;

  final runner = PairedSessionRunner(
    transport: transport,
    authorizer: ref.watch(biometricAuthorizerProvider),
    consent: ref.watch(interactiveAuthorizerProvider),
    vaultApproval: ref.watch(vaultApprovalProvider),
    // Without this the devices list had no source of truth for connection
    // state at all, so every paired desktop sat on `connecting` forever.
    //
    // Deferred because `sync` below starts the first dial synchronously, and
    // the first status would otherwise land while this provider is still
    // building — which Riverpod refuses, taking the runner down with it.
    //
    // The notifier is read inside the callback rather than captured: a status
    // can arrive long after the controller that was current at build time has
    // been disposed, and using that one throws.
    onStatus: (verifierId, status) {
      final phase = switch (status) {
        PairedSessionStatus.connecting => ConnectionPhase.connecting,
        PairedSessionStatus.connected => ConnectionPhase.connected,
        PairedSessionStatus.unreachable => ConnectionPhase.disconnected,
      };
      Future.microtask(() {
        if (!ref.mounted) return;
        ref
            .read(appControllerProvider.notifier)
            .setDevicePhase(verifierId, phase);
      });
    },
  );
  runner.sync(records);
  ref.onDispose(runner.stop);
  return runner;
});
