import '../../domain/authentication_request.dart';
import '../../domain/connection_phase.dart';
import '../auth/phone_authenticator.dart';

class FakePhoneAuthenticator implements PhoneAuthenticator {
  const FakePhoneAuthenticator({this.result = AuthorizationResult.approved});

  final AuthorizationResult result;

  @override
  Future<AuthorizationResult> authorize(
    AuthenticationRequest request, {
    required void Function(ConnectionPhase phase) onPhase,
  }) async {
    onPhase(ConnectionPhase.awaitingBiometric);
    await Future<void>.delayed(const Duration(milliseconds: 150));
    onPhase(ConnectionPhase.signing);
    await Future<void>.delayed(const Duration(milliseconds: 150));
    return result;
  }

  @override
  void cancel(String requestId) {}
}
