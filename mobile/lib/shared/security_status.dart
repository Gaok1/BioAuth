import 'package:flutter/material.dart';

class SecurityStatus extends StatelessWidget {
  const SecurityStatus({
    required this.title,
    required this.detail,
    required this.secure,
    super.key,
  });

  final String title;
  final String detail;
  final bool secure;

  @override
  Widget build(BuildContext context) {
    return ListTile(
      leading: Icon(
        secure ? Icons.verified_user : Icons.warning_amber,
        color: secure ? Colors.green : Theme.of(context).colorScheme.error,
      ),
      title: Text(title),
      subtitle: Text(detail),
    );
  }
}

class BiometricStatus extends StatelessWidget {
  const BiometricStatus({required this.available, super.key});

  final bool available;

  @override
  Widget build(BuildContext context) => SecurityStatus(
    title: 'Biometria',
    detail: available ? 'Disponível neste dispositivo' : 'Não verificada',
    secure: available,
  );
}
