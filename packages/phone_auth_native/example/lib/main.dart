import 'package:flutter/material.dart';
import 'package:phone_auth_native/phone_auth_native.dart';

void main() => runApp(const PluginExample());

class PluginExample extends StatelessWidget {
  const PluginExample({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text('PhoneAuth Native')),
        body: FutureBuilder<SecurityCapabilities>(
          future: const PhoneAuthNative().getSecurityCapabilities(),
          builder: (context, snapshot) {
            final capabilities = snapshot.data;
            if (capabilities == null) {
              return const Center(child: CircularProgressIndicator());
            }
            return Center(
              child: Text(
                'Strong biometric: '
                '${capabilities.biometrics.strongBiometrics}\n'
                'Hardware-backed key: ${capabilities.hardwareBacked}',
              ),
            );
          },
        ),
      ),
    );
  }
}
