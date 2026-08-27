import '../../domain/authentication_request.dart';
import '../../domain/connection_phase.dart';

enum AuthorizationResult { approved, denied }

abstract interface class PhoneAuthenticator {
  Future<AuthorizationResult> authorize(
    AuthenticationRequest request, {
    required void Function(ConnectionPhase phase) onPhase,
  });

  /// The user declined without reaching a biometric prompt.
  ///
  /// Part of the interface rather than a detail of one implementation: a
  /// request that arrived over a live session leaves the desktop waiting until
  /// something answers it, and dropping the card from the screen is not an
  /// answer.
  void cancel(String requestId);
}

class UnavailablePhoneAuthenticator implements PhoneAuthenticator {
  const UnavailablePhoneAuthenticator();

  @override
  Future<AuthorizationResult> authorize(
    AuthenticationRequest request, {
    required void Function(ConnectionPhase phase) onPhase,
  }) =>
      Future.error(UnsupportedError('Autenticador seguro nativo indisponível'));

  @override
  void cancel(String requestId) {}
}
