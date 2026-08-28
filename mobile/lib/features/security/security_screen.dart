import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:phone_auth_native/phone_auth_native.dart';

import '../../app/providers.dart';
import '../../shared/security_status.dart';

class SecurityScreen extends ConsumerWidget {
  const SecurityScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final capabilities = ref.watch(securityCapabilitiesProvider);
    final background = ref.watch(backgroundSessionsReadyProvider);
    return Scaffold(
      appBar: AppBar(title: const Text('Segurança')),
      body: ListView(
        padding: const EdgeInsets.symmetric(vertical: 12),
        children: [
          capabilities.when(
            data: _keyStatus,
            loading: () => const SecurityStatus(
              title: 'Chave do dispositivo',
              detail: 'Verificando o Android Keystore…',
              secure: false,
            ),
            error: (_, _) => const SecurityStatus(
              title: 'Chave do dispositivo',
              detail: 'Não foi possível consultar o Android Keystore',
              secure: false,
            ),
          ),
          capabilities.when(
            data: _biometricStatus,
            loading: () => const SecurityStatus(
              title: 'Biometria forte',
              detail: 'Verificando…',
              secure: false,
            ),
            error: (_, _) => const SecurityStatus(
              title: 'Biometria forte',
              detail: 'Não foi possível verificar a biometria',
              secure: false,
            ),
          ),
          background.when(
            data: (ready) => SecurityStatus(
              title: 'Sessões em segundo plano',
              detail: ready
                  ? 'Serviço persistente ativo'
                  : 'Inativas; pareie um computador para ativar',
              secure: ready,
            ),
            loading: () => const SecurityStatus(
              title: 'Sessões em segundo plano',
              detail: 'Verificando o serviço persistente…',
              secure: false,
            ),
            error: (_, _) => const SecurityStatus(
              title: 'Sessões em segundo plano',
              detail: 'Não foi possível verificar o serviço persistente',
              secure: false,
            ),
          ),
          const SecurityStatus(
            title: 'Funcionamento offline',
            detail: 'Nenhuma conexão com nuvem é necessária',
            secure: true,
          ),
        ],
      ),
    );
  }

  static SecurityStatus _keyStatus(SecurityCapabilities capabilities) {
    final detail = !capabilities.keyExists
        ? 'A chave de autorização ainda não foi criada'
        : capabilities.strongBoxBacked
        ? 'Chave protegida por StrongBox no Android Keystore'
        : capabilities.hardwareBacked
        ? 'Chave protegida por hardware no Android Keystore; sem StrongBox'
        : 'Chave sem proteção de hardware';
    return SecurityStatus(
      title: 'Chave do dispositivo',
      detail: detail,
      secure: capabilities.keyExists && capabilities.hardwareBacked,
    );
  }

  static SecurityStatus _biometricStatus(SecurityCapabilities capabilities) {
    final biometrics = capabilities.biometrics;
    final available =
        biometrics.availability == BiometricAvailability.available;
    return SecurityStatus(
      title: 'Biometria forte',
      detail: switch (biometrics.availability) {
        BiometricAvailability.available when biometrics.strongBiometrics =>
          'BIOMETRIC_STRONG disponível',
        BiometricAvailability.available =>
          'Há biometria, mas ela não atende BIOMETRIC_STRONG',
        BiometricAvailability.noneEnrolled => 'Nenhuma biometria cadastrada',
        BiometricAvailability.temporarilyUnavailable =>
          'Biometria temporariamente indisponível',
        BiometricAvailability.unavailable => 'Biometria indisponível',
        BiometricAvailability.unsupported =>
          'Biometria não suportada neste dispositivo',
        BiometricAvailability.unknown => 'Estado biométrico desconhecido',
      },
      secure: available && biometrics.strongBiometrics,
    );
  }
}
