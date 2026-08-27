import '../domain/audit_entry.dart';
import '../domain/authentication_request.dart';
import '../domain/connection_phase.dart';
import '../domain/desktop_device.dart';

class AppState {
  const AppState({
    required this.onboardingComplete,
    required this.devices,
    required this.requests,
    required this.requestPhases,
    required this.auditEntries,
    this.securityWarning,
  });

  const AppState.empty()
    : onboardingComplete = false,
      devices = const [],
      requests = const [],
      requestPhases = const {},
      auditEntries = const [],
      securityWarning = null;

  final bool onboardingComplete;
  final List<DesktopDevice> devices;
  final List<AuthenticationRequest> requests;
  final Map<String, ConnectionPhase> requestPhases;
  final List<AuditEntry> auditEntries;
  final SecurityWarning? securityWarning;

  AppState copyWith({
    bool? onboardingComplete,
    List<DesktopDevice>? devices,
    List<AuthenticationRequest>? requests,
    Map<String, ConnectionPhase>? requestPhases,
    List<AuditEntry>? auditEntries,
    SecurityWarning? securityWarning,
    bool clearSecurityWarning = false,
  }) => AppState(
    onboardingComplete: onboardingComplete ?? this.onboardingComplete,
    devices: devices ?? this.devices,
    requests: requests ?? this.requests,
    requestPhases: requestPhases ?? this.requestPhases,
    auditEntries: auditEntries ?? this.auditEntries,
    securityWarning: clearSecurityWarning
        ? null
        : securityWarning ?? this.securityWarning,
  );
}

class SecurityWarning {
  const SecurityWarning({
    required this.deviceId,
    required this.deviceName,
    required this.requestCount,
    required this.window,
  });

  final String deviceId;
  final String deviceName;
  final int requestCount;
  final Duration window;
}
