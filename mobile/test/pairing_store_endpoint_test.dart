/// Where a paired desktop is, as opposed to which desktop it is.
///
/// The identity key never changes and the address always does — a new DHCP
/// lease, Wi-Fi to cable, a different network entirely. A record keeps both,
/// and only the address can be wrong while the record is still valid.
library;

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/pairing/pairing_record.dart';
import 'package:phone_auth/core/pairing/pairing_store.dart';
import 'package:phone_auth/core/protocol/enrolment.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  test('re-pairing one credential moves the whole computer', () async {
    final store = SharedPreferencesPairingStore();
    await store.save(_record('desktop-1', CredentialPurpose.authorization));
    await store.save(
      _record('desktop-1', CredentialPurpose.vault, endpoint: '192.0.2.9:4000'),
    );

    // The login credential was paired at the old address and never dialled
    // again after the router moved the desktop. Nothing about it expired; it
    // simply pointed somewhere the desktop no longer was.
    final records = await store.load();
    expect(records, hasLength(2));
    expect(
      records.map((record) => record.endpoint),
      everyElement('192.0.2.9:4000'),
    );
  });

  test('a different computer answering to the name moves nothing', () async {
    final store = SharedPreferencesPairingStore();
    await store.save(_record('desktop-1', CredentialPurpose.authorization));
    await store.save(
      _record(
        'desktop-1',
        CredentialPurpose.vault,
        endpoint: '198.51.100.4:4000',
        identity: [9, 9, 9],
      ),
    );

    final login = (await store.load()).singleWhere(
      (record) => record.purpose == CredentialPurpose.authorization,
    );
    expect(login.endpoint, '192.0.2.1:42371');
  });

  test('another computer is left where it is', () async {
    final store = SharedPreferencesPairingStore();
    await store.save(_record('desktop-1', CredentialPurpose.authorization));
    await store.save(
      _record(
        'desktop-2',
        CredentialPurpose.authorization,
        endpoint: '192.0.2.9:4000',
      ),
    );

    final first = (await store.load()).singleWhere(
      (record) => record.verifierId == 'desktop-1',
    );
    expect(first.endpoint, '192.0.2.1:42371');
  });
}

PairingRecord _record(
  String verifierId,
  CredentialPurpose purpose, {
  String endpoint = '192.0.2.1:42371',
  List<int> identity = const [1, 2, 3],
}) => PairingRecord(
  verifierId: verifierId,
  verifierIdentitySpki: Uint8List.fromList(identity),
  endpoint: endpoint,
  credentialId: '$verifierId-${purpose.name}-v1',
  keyKind: KeyKind.hardware,
  purpose: purpose,
  pairedAt: DateTime.utc(2026, 8, 28),
);
