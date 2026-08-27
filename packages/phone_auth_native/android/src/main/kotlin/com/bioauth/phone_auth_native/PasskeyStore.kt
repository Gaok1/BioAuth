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

    private fun read(): List<PasskeyRecord> {
        val encoded = preferences.getString(KEY_RECORDS, null) ?: return emptyList()
        return runCatching {
            val array = JSONArray(encoded)
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
        }.getOrElse { throw IllegalStateException("Stored passkey metadata is corrupt", it) }
    }

    private fun write(records: List<PasskeyRecord>) {
        val array = JSONArray()
        records.forEach { record ->
            array.put(JSONObject().apply {
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
        check(preferences.edit().putString(KEY_RECORDS, array.toString()).commit()) {
            "Unable to persist passkey metadata"
        }
    }

    companion object {
        private const val FILE_NAME = "bioauth_webauthn_credentials_v1"
        private const val KEY_RECORDS = "records"
    }
}
