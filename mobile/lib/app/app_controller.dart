import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../core/auth/phone_authenticator.dart';
import '../core/security/approval_guard.dart';
import '../domain/audit_entry.dart';
import '../domain/authentication_request.dart';
import '../domain/connection_phase.dart';
import 'app_state.dart';
import 'config.dart';

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

  void receive(AuthenticationRequest request, {DateTime? at}) {
    final now = (at ?? DateTime.now()).toUtc();
    final device = state.devices
        .where((candidate) => candidate.id == request.deviceId)
        .firstOrNull;
    if (device == null || device.isBlockedAt(now) || request.isExpiredAt(now)) {
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
      return;
    }

    if (decision == ApprovalDecision.duplicate && existingIndex >= 0) {
      final requests = [...state.requests];
      final existing = requests[existingIndex];
      requests[existingIndex] = existing.copyWith(
        duplicateCount: existing.duplicateCount + 1,
      );
      state = state.copyWith(requests: List.unmodifiable(requests));
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

  void revokeDevice(String deviceId) {
    state = state.copyWith(
      devices: List.unmodifiable(
        state.devices.where((device) => device.id != deviceId),
      ),
      requests: List.unmodifiable(
        state.requests.where((request) => request.deviceId != deviceId),
      ),
      clearSecurityWarning: true,
    );
  }

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
