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

  static const _recordsKey = 'bioauth.pairings.v1';
  static const _deviceIdKey = 'bioauth.deviceId.v1';

  final Random _random;

  @override
  Future<List<PairingRecord>> load() async {
    final preferences = await SharedPreferences.getInstance();
    final stored = preferences.getStringList(_recordsKey) ?? const [];
    final records = <PairingRecord>[];
    for (final entry in stored) {
      try {
        records.add(
          PairingRecord.fromJson(jsonDecode(entry) as Map<String, Object?>),
        );
      } on Object {
        // A record this build cannot read is dropped rather than guessed at.
        // Guessing would mean pairing against a key that was not stored.
        continue;
      }
    }
    return records;
  }

  @override
  Future<void> save(PairingRecord record) async {
    final preferences = await SharedPreferences.getInstance();
    final records =
        (await load())
            .where((existing) => existing.verifierId != record.verifierId)
            .toList()
          ..add(record);
    await preferences.setStringList(
      _recordsKey,
      records.map((entry) => jsonEncode(entry.toJson())).toList(),
    );
  }

  @override
  Future<void> remove(String verifierId) async {
    final preferences = await SharedPreferences.getInstance();
    final records = (await load())
        .where((existing) => existing.verifierId != verifierId)
        .map((entry) => jsonEncode(entry.toJson()))
        .toList();
    await preferences.setStringList(_recordsKey, records);
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
