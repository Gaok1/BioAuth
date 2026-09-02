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
