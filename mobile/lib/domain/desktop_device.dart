import 'connection_phase.dart';
import '../core/protocol/enrolment.dart';

class DesktopDevice {
  const DesktopDevice({
    required this.id,
    required this.name,
    required this.phase,
    required this.lastSeen,
    this.blockedUntil,
    this.purposes = const [],
  });

  final String id;
  final String name;
  final ConnectionPhase phase;
  final DateTime lastSeen;
  final DateTime? blockedUntil;

  /// What this desktop's credentials are for, one entry per credential.
  ///
  /// A computer can hold several: a login credential and a vault one are
  /// different keys with different powers, and the list is the only place the
  /// user can see which of them a given desktop was given.
  final List<CredentialPurpose> purposes;

  /// The same device with its credential list refreshed from the store.
  DesktopDevice withPurposes(List<CredentialPurpose> purposes) => DesktopDevice(
    id: id,
    name: name,
    phase: phase,
    lastSeen: lastSeen,
    blockedUntil: blockedUntil,
    purposes: List.unmodifiable(purposes),
  );

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
    purposes: purposes,
  );
}
