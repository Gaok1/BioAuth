package com.bioauth.phone_auth_native

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class PasskeyStoreMigrationTest {
    @Test
    fun migratesLegacyRecordsIntoTheVersionedEnvelope() {
        val record = record()
        val snapshot = readPasskeySnapshot(null, null, PasskeyStoreCodec.encodeLegacy(listOf(record)))

        assertTrue(snapshot.migrated)
        assertEquals("example.com", PasskeyStoreCodec.decode(snapshot.encoded).single().rpId)
    }

    @Test
    fun corruptionRollsBackButAnUnknownFutureVersionDoesNot() {
        val previous = PasskeyStoreCodec.encode(listOf(record()))
        val recovered = readPasskeySnapshot("{broken", previous, null)
        assertTrue(recovered.rolledBack)
        assertEquals("alias", recovered.records.single().keyAlias)

        assertFailsWith<UnsupportedPasskeyStoreVersion> {
            readPasskeySnapshot("{\"version\":99,\"records\":[]}", previous, null)
        }
    }

    private fun record() = PasskeyRecord(
        credentialId = byteArrayOf(1, 2, 3),
        rpId = "example.com",
        userHandle = byteArrayOf(4, 5),
        userName = "person@example.com",
        userDisplayName = "Person",
        keyAlias = "alias",
        signCount = 7u,
        createdAtMillis = 1_777_680_000_000,
    )
}
