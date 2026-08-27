import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../core/transport/pairing_bootstrap.dart';

/// The camera view that reads a pairing code.
///
/// Only QR codes carrying the PhoneAuth prefix are passed on. A camera fires
/// several times a second and users point phones at all sorts of things, so
/// filtering here keeps the controller from starting an attempt per frame.
class PairingQRScanner extends StatefulWidget {
  const PairingQRScanner({super.key, required this.onDetect});

  final void Function(String raw) onDetect;

  @override
  State<PairingQRScanner> createState() => _PairingQRScannerState();
}

class _PairingQRScannerState extends State<PairingQRScanner> {
  final MobileScannerController _controller = MobileScannerController(
    formats: const [BarcodeFormat.qrCode],
    detectionSpeed: DetectionSpeed.noDuplicates,
  );
  String? _lastDelivered;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _handle(BarcodeCapture capture) {
    for (final barcode in capture.barcodes) {
      final raw = barcode.rawValue?.trim();
      if (raw == null || !raw.startsWith(bootstrapPrefix)) continue;
      if (raw == _lastDelivered) continue;
      _lastDelivered = raw;
      widget.onDetect(raw);
      return;
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Semantics(
      label: 'Leitor de QR Code para pareamento',
      child: AspectRatio(
        aspectRatio: 1,
        child: ClipRRect(
          borderRadius: BorderRadius.circular(24),
          child: Stack(
            fit: StackFit.expand,
            children: [
              MobileScanner(
                controller: _controller,
                onDetect: _handle,
                errorBuilder: (context, error) => _ScannerUnavailable(
                  message: switch (error.errorCode) {
                    MobileScannerErrorCode.permissionDenied =>
                      'Permita o acesso à câmera para escanear o código.',
                    MobileScannerErrorCode.unsupported =>
                      'Este dispositivo não tem uma câmera compatível.',
                    _ => 'A câmera não pôde ser aberta.',
                  },
                ),
              ),
              IgnorePointer(
                child: DecoratedBox(
                  decoration: BoxDecoration(
                    border: Border.all(
                      color: theme.colorScheme.primary,
                      width: 3,
                    ),
                    borderRadius: BorderRadius.circular(24),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _ScannerUnavailable extends StatelessWidget {
  const _ScannerUnavailable({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return ColoredBox(
      color: theme.colorScheme.surfaceContainerHighest,
      child: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.no_photography_outlined, size: 48),
              const SizedBox(height: 16),
              Text(
                message,
                textAlign: TextAlign.center,
                style: theme.textTheme.bodyMedium,
              ),
            ],
          ),
        ),
      ),
    );
  }
}
