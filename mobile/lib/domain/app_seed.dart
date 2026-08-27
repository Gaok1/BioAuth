import 'authentication_request.dart';
import 'desktop_device.dart';

class AppSeed {
  const AppSeed({required this.devices, required this.requests});

  const AppSeed.empty() : devices = const [], requests = const [];

  final List<DesktopDevice> devices;
  final List<AuthenticationRequest> requests;
}
