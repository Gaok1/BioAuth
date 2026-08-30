import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../core/auth/phone_authenticator.dart';
import '../core/pairing/pairing_record.dart';
import '../core/security/approval_guard.dart';
import '../domain/desktop_device.dart';
import '../domain/audit_entry.dart';
import '../domain/authentication_request.dart';
import '../domain/connection_phase.dart';
import 'app_state.dart';
import 'config.dart';
import 'providers.dart';

final phoneAuthenticatorProvider = Provider<PhoneAuthenticator>(
  (ref) => const UnavailablePhoneAuthenticator(),
);

final appControllerProvider = NotifierProvider<AppController, AppState>(
  AppController.new,
);

class AppController extends Notifier<AppState> {
  final ApprovalGuard _approvalGuard = ApprovalGuard();

  @override
  AppState build() {
    final seed = ref.watch(appConfigProvider).seed;
    return AppState(
      onboardingComplete: seed.devices.isNotEmpty,
      devices: List.unmodifiable(seed.devices),
      requests: List.unmodifiable(seed.requests),
      requestPhases: {
        for (final request in seed.requests)
          request.id: ConnectionPhase.authenticationPending,
      },
      auditEntries: const [],
    );
  }

  void completeOnboarding() {
    state = state.copyWith(onboardingComplete: true);
  }

  /// Reflects the stored pairings into the devices list.
  ///
  /// A request is only accepted from a device that is on this list, so a
  /// verifier that was never paired — or was revoked — cannot put anything on
  /// screen no matter what it sends.
  void syncPairedDevices(List<PairingRecord> records) {
    final existing = {for (final device in state.devices) device.id: device};

    // One entry per computer, not per credential. A desktop paired for logins
    // and again for the vault is still one computer standing in the room, and
    // two identical rows would be a list the user cannot act on — they say the
    // same name and revoking either revokes both.
    final byVerifier = <String, List<PairingRecord>>{};
    for (final record in records) {
      byVerifier.putIfAbsent(record.verifierId, () => []).add(record);
    }

    final devices = byVerifier.entries
        .map((entry) {
          final first = entry.value.first;
          final purposes = entry.value
              .map((record) => record.purpose)
              .toList(growable: false);
          return (existing[entry.key] ??
                  DesktopDevice(
                    id: entry.key,
                    name: entry.key,
                    phase: ConnectionPhase.connecting,
                    lastSeen: first.pairedAt,
                  ))
              .withPurposes(purposes);
        })
        .toList(growable: false);

    state = state.copyWith(
      onboardingComplete: state.onboardingComplete || devices.isNotEmpty,
      devices: List.unmodifiable(devices),
    );
  }

  /// Reports what the connection to a paired desktop is doing.
  void setDevicePhase(String deviceId, ConnectionPhase phase, {DateTime? at}) {
    final devices = state.devices
        .map(
          (device) => device.id == deviceId
              ? device.copyWith(
                  phase: phase,
                  lastSeen: phase == ConnectionPhase.connected
                      ? (at ?? DateTime.now()).toUtc()
                      : null,
                )
              : device,
        )
        .toList(growable: false);
    state = state.copyWith(devices: List.unmodifiable(devices));
  }

  void receive(AuthenticationRequest request, {DateTime? at}) {
    final now = (at ?? DateTime.now()).toUtc();
    final device = state.devices
        .where((candidate) => candidate.id == request.deviceId)
        .firstOrNull;
    if (device == null || device.isBlockedAt(now) || request.isExpiredAt(now)) {
      // Turned away before any sheet, and still owed an answer. A revoked
      // desktop and a blocked one are both live sessions on this phone while
      // they wait, and a blocked desktop retrying is precisely what piles them
      // up -- one held open per attempt until its deadline. Refusing costs the
      // caller nothing it did not already know: the core answers a request
      // outside the pairing's policy with the same denial, just sooner.
      _refuseUnasked(request.id);
      return;
    }

    final decision = _approvalGuard.inspect(request, now);
    final existingIndex = state.requests.indexWhere(
      (candidate) => candidate.fingerprint == request.fingerprint,
    );

    if (decision == ApprovalDecision.flood) {
      state = state.copyWith(
        securityWarning: SecurityWarning(
          deviceId: device.id,
          deviceName: device.name,
          requestCount: _approvalGuard.maxRequestsPerWindow + 1,
          window: _approvalGuard.window,
        ),
      );
      _refuseUnasked(request.id);
      return;
    }

    if (decision == ApprovalDecision.duplicate && existingIndex >= 0) {
      final requests = [...state.requests];
      final existing = requests[existingIndex];
      requests[existingIndex] = existing.copyWith(
        duplicateCount: existing.duplicateCount + 1,
      );
      state = state.copyWith(requests: List.unmodifiable(requests));
      // The repeat is folded into the sheet already up, which is the right
      // thing to *show* and was the wrong thing to leave unanswered. It cannot
      // share that sheet's answer: a different request id is a different
      // payload and so its own signature, which the auth-per-use key would
      // charge a second gesture for. Running `sudo` twice inside the guard's
      // window is the ordinary way to get here.
      _refuseUnasked(request.id);
      return;
    }

    state = state.copyWith(
      requests: List.unmodifiable([...state.requests, request]),
      requestPhases: Map.unmodifiable({
        ...state.requestPhases,
        request.id: ConnectionPhase.authenticationPending,
      }),
    );
  }

  Future<void> approve(String requestId, {DateTime? at}) async {
    final request = _requestById(requestId);
    if (request == null) return;
    final now = (at ?? DateTime.now()).toUtc();
    if (request.isExpiredAt(now)) {
      _finish(request, ConnectionPhase.expired, AuditOutcome.expired, now);
      return;
    }

    try {
      final result = await ref
          .read(phoneAuthenticatorProvider)
          .authorize(
            request,
            onPhase: (phase) => _setRequestPhase(requestId, phase),
          );
      final outcome = result == AuthorizationResult.approved
          ? AuditOutcome.approved
          : AuditOutcome.denied;
      final phase = result == AuthorizationResult.approved
          ? ConnectionPhase.approved
          : ConnectionPhase.denied;
      _finish(request, phase, outcome, DateTime.now().toUtc());
    } on Object {
      _setRequestPhase(requestId, ConnectionPhase.error);
    }
  }

  void deny(String requestId, {DateTime? at}) {
    final request = _requestById(requestId);
    if (request == null) return;
    // The desktop is holding a session open waiting for an answer. Dropping the
    // card off the screen is not one.
    ref.read(phoneAuthenticatorProvider).cancel(requestId);
    _finish(
      request,
      ConnectionPhase.denied,
      AuditOutcome.denied,
      (at ?? DateTime.now()).toUtc(),
    );
  }

  void blockDevice(String deviceId, {DateTime? at}) {
    final now = (at ?? DateTime.now()).toUtc();
    final blockedUntil = now.add(const Duration(minutes: 15));
    final devices = state.devices
        .map(
          (device) => device.id == deviceId
              ? device.copyWith(
                  phase: ConnectionPhase.disconnected,
                  blockedUntil: blockedUntil,
                )
              : device,
        )
        .toList(growable: false);
    final blockedRequests = state.requests
        .where((request) => request.deviceId == deviceId)
        .toList(growable: false);
    final remaining = state.requests
        .where((request) => request.deviceId != deviceId)
        .toList(growable: false);
    final audit = blockedRequests.map(
      (request) => _auditFor(request, AuditOutcome.blocked, now),
    );

    state = state.copyWith(
      devices: List.unmodifiable(devices),
      requests: List.unmodifiable(remaining),
      auditEntries: List.unmodifiable([...audit, ...state.auditEntries]),
      clearSecurityWarning: true,
    );
  }

  /// Revokes a desktop: removes the record, drops the connection, forgets its
  /// requests.
  ///
  /// Deleting the row was never revocation. The record stayed on disk, the
  /// reconnect loop kept dialling, and the phone went on answering that
  /// desktop's authorization requests — a restart would even put it back on
  /// screen. The row is removed last, once the store write is durable, so the
  /// UI never claims something the device has not actually done.
  Future<void> revokeDevice(String deviceId) async {
    if (!state.devices.any((device) => device.id == deviceId)) return;
    setDevicePhase(deviceId, ConnectionPhase.revoking);

    try {
      await ref.read(pairingStoreProvider).remove(deviceId);
    } on Object {
      // The pairing is still real. Saying otherwise would leave the user
      // believing a desktop can no longer reach them when it still can.
      setDevicePhase(deviceId, ConnectionPhase.error);
      rethrow;
    }

    // Only now is the desktop untrusted, so only now is it safe to hang up.
    await ref.read(pairedSessionRunnerProvider)?.stopDevice(deviceId);

    state = state.copyWith(
      devices: List.unmodifiable(
        state.devices.where((device) => device.id != deviceId),
      ),
      requests: List.unmodifiable(
        state.requests.where((request) => request.deviceId != deviceId),
      ),
      clearSecurityWarning: true,
    );
    ref.invalidate(pairedVerifiersProvider);
  }

  /// Refuses a request that will never reach a sheet.
  ///
  /// Whoever is waiting on it is a live session on the phone. Returning
  /// without settling left that session holding a request nobody would ever
  /// answer until its deadline ran out, and the desktop reading a timeout
  /// where a decision had in fact been made about it.
  void _refuseUnasked(String requestId) =>
      ref.read(interactiveAuthorizerProvider).cancel(requestId);

  AuthenticationRequest? _requestById(String id) =>
      state.requests.where((request) => request.id == id).firstOrNull;

  void _setRequestPhase(String id, ConnectionPhase phase) {
    state = state.copyWith(
      requestPhases: Map.unmodifiable({...state.requestPhases, id: phase}),
    );
  }

  void _finish(
    AuthenticationRequest request,
    ConnectionPhase phase,
    AuditOutcome outcome,
    DateTime at,
  ) {
    final phases = {...state.requestPhases, request.id: phase};
    state = state.copyWith(
      requests: List.unmodifiable(
        state.requests.where((candidate) => candidate.id != request.id),
      ),
      requestPhases: Map.unmodifiable(phases),
      auditEntries: List.unmodifiable([
        _auditFor(request, outcome, at),
        ...state.auditEntries,
      ]),
    );
  }

  AuditEntry _auditFor(
    AuthenticationRequest request,
    AuditOutcome outcome,
    DateTime at,
  ) => AuditEntry(
    requestId: request.id,
    deviceName: request.deviceName,
    service: request.service,
    resource: request.resource,
    timestamp: at,
    outcome: outcome,
  );
}
