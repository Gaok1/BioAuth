import '../../domain/authentication_request.dart';
import '../../domain/connection_phase.dart';

enum AuthorizationResult { approved, denied }

abstract interface class PhoneAuthenticator {
  Future<AuthorizationResult> authorize(
    AuthenticationRequest request, {
    required void Function(ConnectionPhase phase) onPhase,
  });
}

class UnavailablePhoneAuthenticator implements PhoneAuthenticator {
  const UnavailablePhoneAuthenticator();

  @override
  Future<AuthorizationResult> authorize(
    AuthenticationRequest request, {
    required void Function(ConnectionPhase phase) onPhase,
  }) =>
      Future.error(UnsupportedError('Autenticador seguro nativo indisponível'));
}
