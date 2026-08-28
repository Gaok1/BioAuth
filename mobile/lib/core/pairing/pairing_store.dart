import 'dart:convert';
import 'dart:math';

import 'package:shared_preferences/shared_preferences.dart';

import '../transport/pairing_bootstrap.dart';
import 'pairing_record.dart';

/// Where pairing records live between launches.
///
/// The contents are public — an identity key, an address, a credential id — so
/// this is app-private storage rather than the keystore. What matters is
/// integrity: an attacker who could rewrite [PairingRecord.verifierIdentitySpki]
/// could impersonate a paired desktop. On Android the app sandbox is what
/// provides that, the same guarantee any app-private file has.
abstract interface class PairingStore {
  Future<List<PairingRecord>> load();

  Future<void> save(PairingRecord record);

  Future<void> remove(String verifierId);

  /// A stable identifier for this phone, created on first use.
  ///
  /// It goes in every ClientHello and is how the desktop finds the stored key
  /// to check the signature against, so it must survive restarts.
  Future<String> deviceId();
}

class SharedPreferencesPairingStore implements PairingStore {
  SharedPreferencesPairingStore({Random? random})
    : _random = random ?? Random.secure();

  static const _legacyRecordsKey = 'bioauth.pairings.v1';
  static const _recordsKey = 'bioauth.pairings.v2';
  static const _previousRecordsKey = 'bioauth.pairings.v2.previous';
  static const _deviceIdKey = 'bioauth.deviceId.v1';

  final Random _random;

  @override
  Future<List<PairingRecord>> load() async {
    final preferences = await SharedPreferences.getInstance();
    final current = preferences.getString(_recordsKey);
    if (current == null) {
      final records = _decodeLegacy(
        preferences.getStringList(_legacyRecordsKey) ?? const [],
      );
      await _persist(preferences, records);
      return records;
    }
    try {
      return _decodeSnapshot(current);
    } on _UnsupportedPairingStoreVersion {
      rethrow;
    } on Object catch (error) {
      final previous = preferences.getString(_previousRecordsKey);
      if (previous == null) {
        throw StateError('Pairing store is corrupt: $error');
      }
      final records = _decodeSnapshot(previous);
      if (!await preferences.setString(_recordsKey, previous) ||
          !await preferences.setStringList(
            _legacyRecordsKey,
            _encodeLegacy(records),
          )) {
        throw StateError('Pairing store is corrupt and rollback failed');
      }
      throw StateError('Pairing store was corrupt and rolled back: $error');
    }
  }

  @override
  Future<void> save(PairingRecord record) async {
    final preferences = await SharedPreferences.getInstance();
    final records =
        (await load())
            .where((existing) => existing.verifierId != record.verifierId)
            .toList()
          ..add(record);
    await _persist(preferences, records);
  }

  @override
  Future<void> remove(String verifierId) async {
    final preferences = await SharedPreferences.getInstance();
    final records = (await load())
        .where((existing) => existing.verifierId != verifierId)
        .toList();
    await _persist(preferences, records);
  }

  @override
  Future<String> deviceId() async {
    final preferences = await SharedPreferences.getInstance();
    final existing = preferences.getString(_deviceIdKey);
    if (existing != null && existing.isNotEmpty) return existing;

    // Random rather than a hardware identifier: the desktop only needs to tell
    // paired phones apart, and a value derived from the device would follow the
    // user across every verifier they ever pair with.
    final bytes = List<int>.generate(16, (_) => _random.nextInt(256));
    final generated = 'phone-${toBase64Url(bytes)}';
    await preferences.setString(_deviceIdKey, generated);
    return generated;
  }

  Future<void> _persist(
    SharedPreferences preferences,
    List<PairingRecord> records,
  ) async {
    final current = preferences.getString(_recordsKey);
    if (current != null &&
        !await preferences.setString(_previousRecordsKey, current)) {
      throw StateError('Unable to preserve the previous pairing store');
    }
    if (!await preferences.setString(_recordsKey, _encodeSnapshot(records))) {
      throw StateError('Unable to persist pairing records');
    }
    if (!await preferences.setStringList(
      _legacyRecordsKey,
      _encodeLegacy(records),
    )) {
      throw StateError('Unable to persist the pairing compatibility snapshot');
    }
  }

  static String _encodeSnapshot(List<PairingRecord> records) => jsonEncode({
    'version': 2,
    'records': records.map((record) => record.toJson()).toList(),
  });

  static List<String> _encodeLegacy(List<PairingRecord> records) => records
      .map((record) => jsonEncode(record.toJson()))
      .toList(growable: false);

  static List<PairingRecord> _decodeSnapshot(String encoded) {
    final value = jsonDecode(encoded);
    if (value is! Map<String, dynamic>) {
      throw const FormatException('Pairing snapshot is not an object');
    }
    if (value['version'] != 2) {
      throw _UnsupportedPairingStoreVersion(value['version']);
    }
    final records = value['records'];
    if (records is! List) {
      throw const FormatException('Pairing snapshot has no records');
    }
    return records
        .map(
          (record) =>
              PairingRecord.fromJson(Map<String, Object?>.from(record as Map)),
        )
        .toList(growable: false);
  }

  static List<PairingRecord> _decodeLegacy(List<String> stored) => stored
      .map(
        (entry) => PairingRecord.fromJson(
          Map<String, Object?>.from(jsonDecode(entry) as Map),
        ),
      )
      .toList(growable: false);
}

final class _UnsupportedPairingStoreVersion implements Exception {
  const _UnsupportedPairingStoreVersion(this.version);

  final Object? version;

  @override
  String toString() => 'Unsupported pairing store version: $version';
}

/// An in-memory store, for tests and for the development flavour.
class InMemoryPairingStore implements PairingStore {
  InMemoryPairingStore({List<PairingRecord> seed = const [], String? id})
    : _records = [...seed],
      _id = id ?? 'phone-development';

  final List<PairingRecord> _records;
  final String _id;

  @override
  Future<List<PairingRecord>> load() async => List.unmodifiable(_records);

  @override
  Future<void> save(PairingRecord record) async {
    _records
      ..removeWhere((existing) => existing.verifierId == record.verifierId)
      ..add(record);
  }

  @override
  Future<void> remove(String verifierId) async {
    _records.removeWhere((existing) => existing.verifierId == verifierId);
  }

  @override
  Future<String> deviceId() async => _id;
}
