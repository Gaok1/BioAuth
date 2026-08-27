enum AuditOutcome { approved, denied, expired, blocked }

class AuditEntry {
  const AuditEntry({
    required this.requestId,
    required this.deviceName,
    required this.service,
    required this.resource,
    required this.timestamp,
    required this.outcome,
  });

  final String requestId;
  final String deviceName;
  final String service;
  final String resource;
  final DateTime timestamp;
  final AuditOutcome outcome;
}
