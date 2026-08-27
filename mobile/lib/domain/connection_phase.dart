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

  /// The record is being deleted. Shown until the removal is durable, because
  /// a row that vanishes before the store is written promises something that
  /// has not happened yet.
  revoking,
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
    ConnectionPhase.revoking => 'Revogando',
  };
}
