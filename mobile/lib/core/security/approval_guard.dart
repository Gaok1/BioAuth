import 'package:flutter/foundation.dart';

import '../../domain/authentication_request.dart';

enum ApprovalDecision { accept, duplicate, flood }

class ApprovalGuard {
  ApprovalGuard({
    this.window = const Duration(seconds: 30),
    this.maxRequestsPerWindow = 5,
  });

  final Duration window;
  final int maxRequestsPerWindow;
  final Map<String, List<_ObservedRequest>> _observedByDevice = {};

  /// What the guard is holding, across every device.
  ///
  /// Exposed because the ceilings below have no behavioural signature: the
  /// decisions are identical with them and without them, and counting is the
  /// only way to see that they hold.
  @visibleForTesting
  int get observations =>
      _observedByDevice.values.fold(0, (total, list) => total + list.length);

  /// How many devices the guard is still keeping bookkeeping for.
  @visibleForTesting
  int get trackedDevices => _observedByDevice.length;

  ApprovalDecision inspect(AuthenticationRequest request, DateTime now) {
    final cutoff = now.subtract(window);
    // Swept across every device, not only the one asking. The lists were
    // pruned and the keys never were, so the map kept an entry for every
    // device that had ever sent a request -- empty lists nothing would read
    // again, for pairings that no longer exist. That is the same shape as
    // `maxRequestPhases` in the controller that constructs this guard, and the
    // reason that constant is there.
    _observedByDevice.removeWhere((_, seen) {
      seen.removeWhere((item) => item.at.isBefore(cutoff));
      return seen.isEmpty;
    });

    final observed = _observedByDevice.putIfAbsent(request.deviceId, () => []);
    final duplicate = observed.any(
      (item) => item.fingerprint == request.fingerprint,
    );
    observed.add(_ObservedRequest(request.fingerprint, now));

    // A flood is a device that keeps sending after it has been told no, and
    // every one of those arrivals was appended here: the list grew for as long
    // as the flood lasted, holding a fingerprint string per attempt.
    //
    // Trimming the earliest cannot change either answer. `flood` asks whether
    // the length passed [maxRequestsPerWindow], and the ceiling is one above
    // that, so the comparison sees the same thing. `duplicate` is only ever
    // reached when the length is at or below [maxRequestsPerWindow] -- below
    // the ceiling, where nothing has been trimmed -- and anything trimmed is
    // older than everything kept, so it would have been swept by age first
    // anyway.
    final ceiling = maxRequestsPerWindow + 1;
    if (observed.length > ceiling) {
      observed.removeRange(0, observed.length - ceiling);
    }

    if (observed.length > maxRequestsPerWindow) {
      return ApprovalDecision.flood;
    }
    return duplicate ? ApprovalDecision.duplicate : ApprovalDecision.accept;
  }
}

class _ObservedRequest {
  const _ObservedRequest(this.fingerprint, this.at);

  final String fingerprint;
  final DateTime at;
}
