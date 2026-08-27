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

  ApprovalDecision inspect(AuthenticationRequest request, DateTime now) {
    final cutoff = now.subtract(window);
    final observed = _observedByDevice.putIfAbsent(request.deviceId, () => []);
    observed.removeWhere((item) => item.at.isBefore(cutoff));

    final duplicate = observed.any(
      (item) => item.fingerprint == request.fingerprint,
    );
    observed.add(_ObservedRequest(request.fingerprint, now));

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
