enum ConnectionPhase {
  disconnected,
  scanning,
  connecting,
  secureHandshake,
  connected,
  authenticationPending,
  awaitingBiometric,
  signing,
  approved,
  denied,
  expired,
  error,
}

extension ConnectionPhaseLabel on ConnectionPhase {
  String get label => switch (this) {
    ConnectionPhase.disconnected => 'Offline',
    ConnectionPhase.scanning => 'Procurando',
    ConnectionPhase.connecting => 'Conectando',
    ConnectionPhase.secureHandshake => 'Validando conexão',
    ConnectionPhase.connected => 'Conectado',
    ConnectionPhase.authenticationPending => 'Solicitação pendente',
    ConnectionPhase.awaitingBiometric => 'Aguardando biometria',
    ConnectionPhase.signing => 'Autenticando',
    ConnectionPhase.approved => 'Aprovado',
    ConnectionPhase.denied => 'Negado',
    ConnectionPhase.expired => 'Expirado',
    ConnectionPhase.error => 'Erro',
  };
}
