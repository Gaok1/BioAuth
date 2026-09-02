import 'dart:collection';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'application_frame.dart';

/// Coalesces retries of an application operation without retaining its secret
/// request payload.
class ApplicationIdempotency {
  ApplicationIdempotency({this.capacity = 1024});

  final int capacity;
  final LinkedHashMap<(String, String), _Entry> _entries = LinkedHashMap();
  final Hmac _fingerprint = Hmac.sha256();
  final SecretKey _fingerprintKey = SecretKeyData.random(length: 32);

  Future<ApplicationOutcome> run({
    required String scope,
    required ApplicationFrame request,
    required Future<ApplicationOutcome> Function() operation,
  }) async {
    final digest = Uint8List.fromList(
      (await _fingerprint.calculateMac(
        request.payload,
        secretKey: _fingerprintKey,
      )).bytes,
    );
    final key = (scope, request.requestId);
    final existing = _entries[key];
    if (existing != null) {
      if (existing.operation != request.operation ||
          !_sameBytes(existing.payloadDigest, digest)) {
        throw const FormatException('requestId reutilizado com outro pedido');
      }
      return existing.outcome;
    }

    _makeRoom();
    final future = Future.sync(operation);
    final entry = _Entry(request.operation, digest, future);
    _entries[key] = entry;
    try {
      final outcome = await future;
      entry.completed = true;
      if (!outcome.cacheable) _entries.remove(key);
      return outcome;
    } on Object {
      if (identical(_entries[key], entry)) _entries.remove(key);
      rethrow;
    }
  }

  void _makeRoom() {
    while (_entries.length >= capacity) {
      final completed = _entries.entries
          .where((entry) => entry.value.completed)
          .firstOrNull;
      if (completed == null) {
        throw StateError('too many application operations in flight');
      }
      _entries.remove(completed.key);
    }
  }

  static bool _sameBytes(List<int> left, List<int> right) {
    if (left.length != right.length) return false;
    for (var index = 0; index < left.length; index++) {
      if (left[index] != right[index]) return false;
    }
    return true;
  }
}

class ApplicationOutcome {
  ApplicationOutcome(this.kind, List<int> payload, {this.cacheable = true})
    : payload = Uint8List.fromList(payload);

  final ApplicationFrameKind kind;
  final Uint8List payload;
  final bool cacheable;
}

class _Entry {
  _Entry(this.operation, this.payloadDigest, this.outcome);

  final String operation;
  final Uint8List payloadDigest;
  final Future<ApplicationOutcome> outcome;
  bool completed = false;
}
