import 'connection_phase.dart';

class DesktopDevice {
  const DesktopDevice({
    required this.id,
    required this.name,
    required this.phase,
    required this.lastSeen,
    this.blockedUntil,
  });

  final String id;
  final String name;
  final ConnectionPhase phase;
  final DateTime lastSeen;
  final DateTime? blockedUntil;

  bool isBlockedAt(DateTime now) => blockedUntil?.isAfter(now) ?? false;

  DesktopDevice copyWith({
    ConnectionPhase? phase,
    DateTime? lastSeen,
    DateTime? blockedUntil,
  }) => DesktopDevice(
    id: id,
    name: name,
    phase: phase ?? this.phase,
    lastSeen: lastSeen ?? this.lastSeen,
    blockedUntil: blockedUntil ?? this.blockedUntil,
  );
}
