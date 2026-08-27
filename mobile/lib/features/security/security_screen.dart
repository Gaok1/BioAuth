import 'package:flutter/material.dart';

import '../../shared/security_status.dart';

class SecurityScreen extends StatelessWidget {
  const SecurityScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Segurança')),
      body: ListView(
        padding: const EdgeInsets.symmetric(vertical: 12),
        children: const [
          SecurityStatus(
            title: 'Chave do dispositivo',
            detail: 'A integração nativa ainda não foi inicializada',
            secure: false,
          ),
          BiometricStatus(available: false),
          SecurityStatus(
            title: 'Funcionamento offline',
            detail: 'Nenhuma conexão com nuvem é necessária',
            secure: true,
          ),
        ],
      ),
    );
  }
}
