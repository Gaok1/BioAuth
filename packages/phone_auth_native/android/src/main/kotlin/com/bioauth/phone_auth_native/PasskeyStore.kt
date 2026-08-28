package com.bioauth.phone_auth_native

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

internal data class PasskeyRecord(
    val credentialId: ByteArray,
    val rpId: String,
    val userHandle: ByteArray,
    val userName: String,
    val userDisplayName: String,
    val keyAlias: String,
    val signCount: UInt,
    val createdAtMillis: Long,
)

internal class PasskeyStore(context: Context) {
    private val preferences = context.getSharedPreferences(FILE_NAME, Context.MODE_PRIVATE)

    @Synchronized
    fun allForRp(rpId: String): List<PasskeyRecord> = read().filter { it.rpId == rpId }

    @Synchronized
    fun all(): List<PasskeyRecord> = read()

    @Synchronized
    fun find(credentialId: ByteArray): PasskeyRecord? =
        read().firstOrNull { it.credentialId.contentEquals(credentialId) }

    @Synchronized
    fun save(record: PasskeyRecord) {
        val records = read()
        require(records.none { it.credentialId.contentEquals(record.credentialId) }) {
            "Passkey credential ID collision"
        }
        write(records + record)
    }

    @Synchronized
    fun updateCounter(credentialId: ByteArray, expected: UInt, next: UInt) {
        require(next > expected) { "WebAuthn signature counter must increase" }
        val records = read().toMutableList()
        val index = records.indexOfFirst { it.credentialId.contentEquals(credentialId) }
        require(index >= 0 && records[index].signCount == expected) { "Passkey counter changed concurrently" }
        records[index] = records[index].copy(signCount = next)
        write(records)
    }

    @Synchronized
    fun delete(credentialId: ByteArray) {
        val records = read()
        require(records.any { it.credentialId.contentEquals(credentialId) }) { "Passkey not found" }
        write(records.filterNot { it.credentialId.contentEquals(credentialId) })
    }

    private fun read(): List<PasskeyRecord> {
        val snapshot = readPasskeySnapshot(
            preferences.getString(KEY_RECORDS_V2, null),
            preferences.getString(KEY_PREVIOUS_RECORDS_V2, null),
            preferences.getString(KEY_RECORDS, null),
        )
        if (snapshot.migrated) commit(snapshot.records, null)
        if (snapshot.rolledBack) {
            check(
                preferences.edit()
                    .putString(KEY_RECORDS_V2, snapshot.encoded)
                    .putString(KEY_RECORDS, PasskeyStoreCodec.encodeLegacy(snapshot.records))
                    .commit(),
            ) { "Unable to roll back corrupt passkey metadata" }
            throw IllegalStateException("Stored passkey metadata was corrupt and rolled back")
        }
        return snapshot.records
    }

    private fun write(records: List<PasskeyRecord>) {
        commit(records, preferences.getString(KEY_RECORDS_V2, null))
    }

    private fun commit(records: List<PasskeyRecord>, previous: String?) {
        val editor = preferences.edit()
        if (previous != null) editor.putString(KEY_PREVIOUS_RECORDS_V2, previous)
        editor
            .putString(KEY_RECORDS_V2, PasskeyStoreCodec.encode(records))
            .putString(KEY_RECORDS, PasskeyStoreCodec.encodeLegacy(records))
        check(editor.commit()) { "Unable to persist passkey metadata" }
    }

    companion object {
        private const val FILE_NAME = "bioauth_webauthn_credentials_v1"
        private const val KEY_RECORDS = "records"
        private const val KEY_RECORDS_V2 = "records_v2"
        private const val KEY_PREVIOUS_RECORDS_V2 = "records_v2_previous"
    }
}

internal data class PasskeyStoreSnapshot(
    val records: List<PasskeyRecord>,
    val encoded: String,
    val migrated: Boolean = false,
    val rolledBack: Boolean = false,
)

internal fun readPasskeySnapshot(
    current: String?,
    previous: String?,
    legacy: String?,
): PasskeyStoreSnapshot {
    if (current == null) {
        val records = PasskeyStoreCodec.decodeLegacy(legacy)
        return PasskeyStoreSnapshot(records, PasskeyStoreCodec.encode(records), migrated = true)
    }
    return try {
        PasskeyStoreSnapshot(PasskeyStoreCodec.decode(current), current)
    } catch (error: UnsupportedPasskeyStoreVersion) {
        throw error
    } catch (error: Exception) {
        val rollback = previous ?: throw IllegalStateException("Stored passkey metadata is corrupt", error)
        val records = runCatching { PasskeyStoreCodec.decode(rollback) }
            .getOrElse { throw IllegalStateException("Passkey metadata and rollback are corrupt", error) }
        PasskeyStoreSnapshot(records, rollback, rolledBack = true)
    }
}

internal object PasskeyStoreCodec {
    private const val VERSION = 2

    fun encode(records: List<PasskeyRecord>): String = JSONObject().apply {
        put("version", VERSION)
        put("records", recordsArray(records))
    }.toString()

    fun encodeLegacy(records: List<PasskeyRecord>): String = recordsArray(records).toString()

    fun decode(encoded: String): List<PasskeyRecord> {
        val root = JSONObject(encoded)
        val version = root.getInt("version")
        if (version != VERSION) throw UnsupportedPasskeyStoreVersion(version)
        return decodeRecords(root.getJSONArray("records"))
    }

    fun decodeLegacy(encoded: String?): List<PasskeyRecord> =
        decodeRecords(JSONArray(encoded ?: "[]"))

    private fun decodeRecords(array: JSONArray): List<PasskeyRecord> =
        (0 until array.length()).map { index ->
            val item = array.getJSONObject(index)
            val signCount = item.getLong("signCount")
            require(signCount in 0..UInt.MAX_VALUE.toLong()) { "Invalid passkey signature counter" }
            PasskeyRecord(
                credentialId = WebAuthnRequestParser.decode(item.getString("credentialId"), "credentialId"),
                rpId = item.getString("rpId"),
                userHandle = WebAuthnRequestParser.decode(item.getString("userHandle"), "userHandle"),
                userName = item.getString("userName"),
                userDisplayName = item.getString("userDisplayName"),
                keyAlias = item.getString("keyAlias"),
                signCount = signCount.toUInt(),
                createdAtMillis = item.getLong("createdAtMillis"),
            )
        }

    private fun recordsArray(records: List<PasskeyRecord>) = JSONArray().apply {
        records.forEach { record ->
            put(JSONObject().apply {
                put("credentialId", WebAuthnRequestParser.base64Url(record.credentialId))
                put("rpId", record.rpId)
                put("userHandle", WebAuthnRequestParser.base64Url(record.userHandle))
                put("userName", record.userName)
                put("userDisplayName", record.userDisplayName)
                put("keyAlias", record.keyAlias)
                put("signCount", record.signCount.toLong())
                put("createdAtMillis", record.createdAtMillis)
            })
        }
    }
}

internal class UnsupportedPasskeyStoreVersion(version: Int) :
    IllegalStateException("Unsupported passkey store version: $version")
