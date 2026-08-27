import 'package:flutter/material.dart';

import '../../shared/page_heading.dart';
import '../../shared/pairing_qr_code.dart';

class PairingScreen extends StatelessWidget {
  const PairingScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return ListView(
      children: [
        const PageHeading(
          title: 'Parear dispositivo',
          subtitle: 'Escaneie o QR exibido pelo computador',
        ),
        const Center(child: PairingQRCode()),
        const SizedBox(height: 24),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 28),
          child: Text(
            'O QR inicia o pareamento, mas não prova a identidade do '
            'computador. Você confirmará o dispositivo depois do handshake seguro.',
            textAlign: TextAlign.center,
            style: Theme.of(context).textTheme.bodyMedium,
          ),
        ),
      ],
    );
  }
}
