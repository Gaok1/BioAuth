import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/pairing/pairing_record.dart';
import 'package:phone_auth/core/pairing/pairing_store.dart';
import 'package:phone_auth/core/protocol/enrolment.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  const legacyKey = 'bioauth.pairings.v1';
  const currentKey = 'bioauth.pairings.v2';
  const previousKey = 'bioauth.pairings.v2.previous';

  test('migrates v1 atomically and keeps a compatibility snapshot', () async {
    final record = _record('desktop-1');
    SharedPreferences.setMockInitialValues({
      legacyKey: [jsonEncode(record.toJson())],
    });

    final store = SharedPreferencesPairingStore();
    expect((await store.load()).single.verifierId, 'desktop-1');
    await store.save(_record('desktop-2'));

    final preferences = await SharedPreferences.getInstance();
    expect(jsonDecode(preferences.getString(currentKey)!)['version'], 2);
    expect(preferences.getString(previousKey), isNotNull);
    expect(preferences.getStringList(legacyKey), hasLength(2));
  });

  test('detects corruption, rolls back once, and reports it', () async {
    final previous = jsonEncode({
      'version': 2,
      'records': [_record('desktop-safe').toJson()],
    });
    SharedPreferences.setMockInitialValues({
      currentKey: '{broken',
      previousKey: previous,
    });
    final store = SharedPreferencesPairingStore();

    await expectLater(store.load(), throwsA(isA<StateError>()));
    expect((await store.load()).single.verifierId, 'desktop-safe');
  });

  test('never rolls an unknown future version back as corruption', () async {
    const future = '{"version":99,"records":[]}';
    SharedPreferences.setMockInitialValues({
      currentKey: future,
      previousKey: '{"version":2,"records":[]}',
    });

    await expectLater(
      SharedPreferencesPairingStore().load(),
      throwsA(predicate((error) => error.toString().contains('version: 99'))),
    );
    expect(
      (await SharedPreferences.getInstance()).getString(currentKey),
      future,
    );
  });
}

PairingRecord _record(String verifierId) => PairingRecord(
  verifierId: verifierId,
  verifierIdentitySpki: Uint8List.fromList([1, 2, 3]),
  endpoint: '192.0.2.1:42371',
  credentialId: '$verifierId-authorization-v1',
  keyKind: KeyKind.hardware,
  purpose: CredentialPurpose.authorization,
  pairedAt: DateTime.utc(2026, 8, 28),
);
