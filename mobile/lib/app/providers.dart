/// Wiring for the real, non-mock stack.
///
/// Everything here is a `Provider` so the widget tests and the development
/// flavour can override one piece without rebuilding the rest. The production
/// defaults are the real ones: a TCP transport, the platform keystore, and
/// on-device storage.
library;

import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'app_controller.dart';

import '../core/auth/interactive_authorizer.dart';
import '../core/auth/native_biometric_authorizer.dart';
import '../core/pairing/pairing_record.dart';
import '../core/pairing/pairing_service.dart';
import '../core/pairing/pairing_store.dart';
import '../core/session/paired_session_runner.dart';
import '../core/session/phone_auth_core.dart';
import '../core/transport/auth_transport.dart';
import '../core/transport/authenticated_session_establisher.dart';
import '../core/transport/qr_network_transport.dart';
import '../core/transport/secure_session_establisher.dart';
import '../core/transport/session_identity_crypto.dart';

final pairingStoreProvider = Provider<PairingStore>(
  (ref) => SharedPreferencesPairingStore(),
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
  return QrNetworkTransport(
    sessionEstablisher: await ref.watch(sessionEstablisherProvider.future),
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

/// Holds a connection to every paired desktop for as long as it is watched.
///
/// Nothing runs until a widget watches this, which is deliberate: a phone with
/// the app closed should not be holding sockets open.
final pairedSessionRunnerProvider = Provider<PairedSessionRunner?>((ref) {
  final transport = ref.watch(transportProvider).value;
  final records = ref.watch(pairedVerifiersProvider).value;
  if (transport == null || records == null) return null;

  final runner = PairedSessionRunner(
    transport: transport,
    authorizer: ref.watch(biometricAuthorizerProvider),
    consent: ref.watch(interactiveAuthorizerProvider),
  );
  ref.read(appControllerProvider.notifier).syncPairedDevices(records);
  runner.sync(records);
  ref.onDispose(runner.stop);
  return runner;
});
