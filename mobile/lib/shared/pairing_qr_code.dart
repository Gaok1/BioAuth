import 'package:flutter/material.dart';

class PairingQRCode extends StatelessWidget {
  const PairingQRCode({super.key});

  @override
  Widget build(BuildContext context) {
    return Semantics(
      label: 'Leitor de QR Code para pareamento',
      child: Container(
        width: 220,
        height: 220,
        decoration: BoxDecoration(
          border: Border.all(color: Theme.of(context).colorScheme.outline),
          borderRadius: BorderRadius.circular(24),
        ),
        child: const Icon(Icons.qr_code_scanner, size: 88),
      ),
    );
  }
}
