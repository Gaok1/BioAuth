package com.bioauth.phone_auth_native

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.AtomicFile
import java.io.File
import java.security.KeyStore
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONArray
import org.json.JSONObject

internal data class VaultItem(
    val id: String,
    val revision: Int,
    val kind: Int,
    val name: String,
    val username: String,
    val uri: String,
    val secret: String,
    val updatedAtMs: Long,
) {
    fun summary(): Map<String, Any> = mapOf(
        "id" to id,
        "revision" to revision,
        "kind" to kind,
        "name" to name,
        "username" to username,
        "uri" to uri,
        "updatedAtMs" to updatedAtMs,
    )
}

internal data class VaultItemInput(
    val id: String?,
    val kind: Int,
    val name: String,
    val username: String,
    val uri: String,
    val secret: String,
) {
    companion object {
        fun from(arguments: Any?, requireId: Boolean): VaultItemInput {
            val map = arguments as? Map<*, *> ?: invalid("item must be a map")
            val id = map["id"]?.let { it as? String ?: invalid("id must be a string") }
            if (requireId && id == null) invalid("id is required")
            id?.let { validateText("id", it, 64, allowEmpty = false) }
            val kindValue = map["kind"] as? Number ?: invalid("kind is required")
            val kind = kindValue.exactLongOrNull()?.takeIf { it in KIND_RANGE }?.toInt()
                ?: invalid("kind must be a known item kind")
            val name = map.string("name")
            val username = map.optionalString("username")
            val uri = map.optionalString("uri")
            val secret = map.string("secret")
            validateText("name", name, 255, allowEmpty = false)
            validateText("username", username, 255, allowEmpty = true)
            validateText("uri", uri, 1024, allowEmpty = true)
            validateText("secret", secret, 4096, allowEmpty = false)
            return VaultItemInput(id, kind, name, username, uri, secret)
        }
    }
}

internal class VaultStoreFailure(
    val code: String,
    override val message: String,
    val details: Any? = null,
) : RuntimeException(message)

/**
 * The item kinds this build understands: login, note, TOTP seed.
 *
 * Named once rather than spelled `0..1` in two places, which is how the two
 * drifted apart the last time a kind was added — one path accepting an item
 * the other calls corruption.
 */
internal val KIND_RANGE = 0L..2L

internal object VaultStoreData {
    const val PAGE_SIZE = 32

    /**
     * The ceiling a restore may not cross.
     *
     * The vault is one blob decrypted into memory on every operation, so a
     * vault that will not fit is not slow, it is a vault that stops opening.
     * Matching the exporter's own cap keeps the failure at the point where it
     * can still be explained.
     */
    const val MAX_ITEMS = 4096

    fun create(items: List<VaultItem>, input: VaultItemInput, nowMs: Long, id: String = UUID.randomUUID().toString()): Pair<List<VaultItem>, VaultItem> {
        validateText("id", id, 64, allowEmpty = false)
        if (items.any { it.id == id }) throw VaultStoreFailure("id_conflict", "Vault item id already exists")
        val created = input.item(id, revision = 1, nowMs)
        return (items + created) to created
    }

    fun update(items: List<VaultItem>, input: VaultItemInput, expectedRevision: Int, nowMs: Long): Pair<List<VaultItem>, VaultItem> {
        requireRevision(expectedRevision)
        val id = input.id ?: invalid("id is required")
        val index = items.indexOfFirst { it.id == id }
        if (index < 0) throw VaultStoreFailure("not_found", "Vault item does not exist")
        val current = items[index]
        checkRevision(current, expectedRevision)
        if (current.revision == Int.MAX_VALUE) throw VaultStoreFailure("revision_overflow", "Vault item revision cannot be advanced")
        val updated = input.item(id, current.revision + 1, nowMs)
        return items.toMutableList().also { it[index] = updated } to updated
    }

    fun delete(items: List<VaultItem>, id: String, expectedRevision: Int): List<VaultItem> {
        validateText("id", id, 64, allowEmpty = false)
        requireRevision(expectedRevision)
        val current = items.find { it.id == id }
            ?: throw VaultStoreFailure("not_found", "Vault item does not exist")
        checkRevision(current, expectedRevision)
        return items.filterNot { it.id == id }
    }

    /**
     * Every item, secrets included, for one encrypted export.
     *
     * The whole vault is a single blob under a key that demands a biometric
     * per use, so reading it item by item would be one prompt per item. This
     * is the same single decryption `list` already performs; what is new is
     * that the secrets come back with it, which is why nothing but the export
     * flow may call it.
     */
    fun export(items: List<VaultItem>): List<Map<String, Any>> = items.map {
        mapOf(
            "kind" to it.kind,
            "name" to it.name,
            "username" to it.username,
            "uri" to it.uri,
            "secret" to it.secret,
        )
    }

    /**
     * Adds restored items to whatever is already here.
     *
     * Additive on purpose: a restore that replaced the vault would turn one
     * mistaken tap — the wrong backup file, the right file from a year ago —
     * into losing everything stored since. Nothing here deletes, and an item
     * that already exists is counted rather than duplicated.
     *
     * Ids are generated fresh. The id in a backup belonged to the vault it
     * came from, and reusing it would collide with an unrelated item on a
     * phone that has been in use.
     */
    fun restore(
        items: List<VaultItem>,
        incoming: List<VaultItemInput>,
        nowMs: Long,
    ): Triple<List<VaultItem>, Int, Int> {
        if (items.size + incoming.size > MAX_ITEMS) {
            throw VaultStoreFailure("vault_full", "Restoring would exceed the vault's limit")
        }
        val existing = items.mapTo(mutableSetOf()) { it.identity() }
        val restored = items.toMutableList()
        var added = 0
        var skipped = 0
        for (input in incoming) {
            if (!existing.add(input.identity())) {
                skipped++
                continue
            }
            restored += input.item(UUID.randomUUID().toString(), revision = 1, nowMs)
            added++
        }
        return Triple(restored, added, skipped)
    }

    /**
     * What makes two entries the same entry, for a restore.
     *
     * The secret is not part of it. Two rows for the same login on the same
     * site with different passwords are one account whose password changed,
     * and adding both would leave the user guessing which is current.
     */
    private fun VaultItem.identity() = listOf(kind.toString(), name, username, uri)

    private fun VaultItemInput.identity() = listOf(kind.toString(), name, username, uri)

    fun fetch(items: List<VaultItem>, id: String): VaultItem {
        validateText("id", id, 64, allowEmpty = false)
        return items.find { it.id == id }
            ?: throw VaultStoreFailure("not_found", "Vault item does not exist")
    }

    fun page(items: List<VaultItem>, cursor: String?): Map<String, Any?> {
        if (cursor != null) validateText("cursor", cursor, 128, allowEmpty = true)
        val offset = if (cursor.isNullOrEmpty()) 0 else cursor.toIntOrNull()
            ?: invalid("cursor is invalid")
        if (offset !in 0..items.size) invalid("cursor is invalid")
        val sorted = ordered(items)
        val page = sorted.drop(offset).take(PAGE_SIZE)
        val next = (offset + page.size).takeIf { it < sorted.size }?.toString()
        return mapOf("items" to page.map(VaultItem::summary), "nextCursor" to next)
    }

    /**
     * Every item's metadata in one answer, in the order [page] hands them out.
     *
     * The key is auth-per-use, so each trip through the channel costs a
     * biometric prompt and a paged walk costs one per [PAGE_SIZE] items.
     * Opening a vault of a hundred items asked for four fingerprints in a row,
     * and cancelling any of them left the vault shut reporting a cancelled
     * authentication -- a vault that, from the outside, does not open. Same
     * reasoning as [export], which is one call for exactly this reason.
     *
     * Metadata only. The secrets stay behind [fetch], one at a time, in front
     * of a user who was told which one.
     */
    fun all(items: List<VaultItem>): Map<String, Any?> =
        mapOf("items" to ordered(items).map(VaultItem::summary))

    /** Newest first, ties broken by id so the order is total and stable. */
    private fun ordered(items: List<VaultItem>) =
        items.sortedWith(compareByDescending<VaultItem> { it.updatedAtMs }.thenBy { it.id })

    private fun VaultItemInput.item(id: String, revision: Int, nowMs: Long) =
        VaultItem(id, revision, kind, name, username, uri, secret, nowMs)

    private fun checkRevision(item: VaultItem, expected: Int) {
        if (item.revision != expected) {
            throw VaultStoreFailure(
                "revision_conflict",
                "Vault item revision changed",
                mapOf("expectedRevision" to expected, "currentRevision" to item.revision),
            )
        }
    }
}

internal object VaultStoreCodec {
    fun encode(items: List<VaultItem>): ByteArray {
        val array = JSONArray()
        items.forEach { item ->
            array.put(
                JSONObject()
                    .put("id", item.id)
                    .put("revision", item.revision)
                    .put("kind", item.kind)
                    .put("name", item.name)
                    .put("username", item.username)
                    .put("uri", item.uri)
                    .put("secret", item.secret)
                    .put("updatedAtMs", item.updatedAtMs),
            )
        }
        return JSONObject().put("version", 1).put("items", array).toString().toByteArray(Charsets.UTF_8)
    }

    fun decode(bytes: ByteArray): List<VaultItem> {
        val root = runCatching { JSONObject(bytes.toString(Charsets.UTF_8)) }
            .getOrElse { throw VaultStoreFailure("store_corrupt", "Vault storage is corrupt") }
        if (root.strictInt("version") != 1) throw VaultStoreFailure("store_version_unsupported", "Vault storage version is unsupported")
        val array = root.opt("items") as? JSONArray
            ?: throw VaultStoreFailure("store_corrupt", "Vault storage is corrupt")
        val ids = mutableSetOf<String>()
        return List(array.length()) { index ->
            val value = array.opt(index) as? JSONObject
                ?: throw VaultStoreFailure("store_corrupt", "Vault storage is corrupt")
            val item = VaultItem(
                id = value.strictString("id"),
                revision = value.strictInt("revision"),
                kind = value.strictInt("kind"),
                name = value.strictString("name"),
                username = value.strictString("username"),
                uri = value.strictString("uri"),
                secret = value.strictString("secret"),
                updatedAtMs = value.strictLong("updatedAtMs"),
            )
            validate(item)
            if (!ids.add(item.id)) throw VaultStoreFailure("store_corrupt", "Vault storage is corrupt")
            item
        }
    }

    private fun validate(item: VaultItem) {
        validateText("id", item.id, 64, allowEmpty = false)
        requireRevision(item.revision)
        if (item.kind.toLong() !in KIND_RANGE) throw VaultStoreFailure("store_corrupt", "Vault storage is corrupt")
        validateText("name", item.name, 255, allowEmpty = false)
        validateText("username", item.username, 255, allowEmpty = true)
        validateText("uri", item.uri, 1024, allowEmpty = true)
        validateText("secret", item.secret, 4096, allowEmpty = false)
    }
}

internal object VaultCiphertext {
    private const val VERSION: Byte = 1
    private const val MAX_IV_BYTES = 16
    private const val TAG_BYTES = 16
    private val AAD = "bioauth-vault-store-v1".toByteArray(Charsets.UTF_8)

    fun aad(): ByteArray = AAD.copyOf()

    fun seal(cipher: Cipher, plaintext: ByteArray): ByteArray {
        cipher.updateAAD(AAD)
        val encrypted = cipher.doFinal(plaintext)
        val iv = cipher.iv
        if (iv.isEmpty() || iv.size > MAX_IV_BYTES) throw VaultStoreFailure("encryption_failed", "Unexpected vault cipher IV")
        return ByteArray(2 + iv.size + encrypted.size).also { blob ->
            blob[0] = VERSION
            blob[1] = iv.size.toByte()
            iv.copyInto(blob, 2)
            encrypted.copyInto(blob, 2 + iv.size)
        }
    }

    fun iv(blob: ByteArray): ByteArray {
        if (blob.size < 2 + 1 + TAG_BYTES || blob[0] != VERSION) malformed()
        val length = blob[1].toInt() and 0xff
        if (length !in 1..MAX_IV_BYTES || blob.size < 2 + length + TAG_BYTES) malformed()
        return blob.copyOfRange(2, 2 + length)
    }

    fun open(cipher: Cipher, blob: ByteArray): ByteArray {
        val length = iv(blob).size
        cipher.updateAAD(AAD)
        return cipher.doFinal(blob, 2 + length, blob.size - 2 - length)
    }

    private fun malformed(): Nothing = throw VaultStoreFailure("store_corrupt", "Vault storage is corrupt")
}

internal class VaultFileStorage(context: Context) {
    private val file = AtomicFile(File(context.noBackupFilesDir, FILE_NAME))

    fun exists(): Boolean = file.baseFile.isFile

    fun read(): ByteArray = runCatching { file.readFully() }
        .getOrElse { throw VaultStoreFailure("storage_failed", "Unable to read vault storage") }

    fun write(bytes: ByteArray) {
        val output = runCatching { file.startWrite() }
            .getOrElse { throw VaultStoreFailure("storage_failed", "Unable to write vault storage") }
        try {
            output.write(bytes)
            file.finishWrite(output)
        } catch (_: Exception) {
            file.failWrite(output)
            throw VaultStoreFailure("storage_failed", "Unable to write vault storage")
        }
    }

    fun delete() {
        file.delete()
    }

    internal fun pathForTest(): File = file.baseFile

    companion object {
        const val FILE_NAME = "bioauth_vault_store.bin"
    }
}

internal class VaultKeyStore(private val context: Context) {
    private val keyStore: KeyStore
        get() = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    fun ensureKey() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            throw VaultStoreFailure("unsupported_android", "Vault storage requires Android 11 or newer")
        }
        if (keyStore.containsAlias(KEY_ALIAS)) return
        val strongBoxAvailable = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        if (strongBoxAvailable) {
            try {
                createKey(useStrongBox = true)
                return
            } catch (_: StrongBoxUnavailableException) {
                keyStore.deleteEntry(KEY_ALIAS)
            }
        }
        createKey(useStrongBox = false)
    }

    fun encryptCipher(): Cipher = Cipher.getInstance(TRANSFORMATION).apply {
        init(Cipher.ENCRYPT_MODE, secretKey())
    }

    fun decryptCipher(blob: ByteArray): Cipher = Cipher.getInstance(TRANSFORMATION).apply {
        init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(TAG_BITS, VaultCiphertext.iv(blob)))
    }

    fun deleteKey() = keyStore.deleteEntry(KEY_ALIAS)

    internal fun secretKeyForTest(): SecretKey = secretKey()

    private fun secretKey(): SecretKey = keyStore.getKey(KEY_ALIAS, null) as? SecretKey
        ?: throw VaultStoreFailure("key_not_found", "Vault key does not exist")

    @android.annotation.TargetApi(Build.VERSION_CODES.R)
    private fun createKey(useStrongBox: Boolean) {
        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(KEY_BITS)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            .setInvalidatedByBiometricEnrollment(true)
        if (useStrongBox) builder.setIsStrongBoxBacked(true)
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            .apply { init(builder.build()) }
            .generateKey()
    }

    companion object {
        const val KEY_ALIAS = "bioauth_vault_store_v1"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val KEY_BITS = 256
        private const val TAG_BITS = 128
    }
}

private fun Map<*, *>.string(key: String): String = this[key] as? String ?: invalid("$key is required")
private fun Map<*, *>.optionalString(key: String): String = this[key]?.let {
    it as? String ?: invalid("$key must be a string")
} ?: ""

private fun JSONObject.strictString(key: String): String = opt(key) as? String
    ?: throw VaultStoreFailure("store_corrupt", "Vault storage is corrupt")

private fun JSONObject.strictInt(key: String): Int {
    val number = opt(key) as? Number ?: throw VaultStoreFailure("store_corrupt", "Vault storage is corrupt")
    val long = number.exactLongOrNull()
    if (long == null || long !in Int.MIN_VALUE..Int.MAX_VALUE) {
        throw VaultStoreFailure("store_corrupt", "Vault storage is corrupt")
    }
    return long.toInt()
}

private fun JSONObject.strictLong(key: String): Long {
    val number = opt(key) as? Number ?: throw VaultStoreFailure("store_corrupt", "Vault storage is corrupt")
    return number.exactLongOrNull() ?: throw VaultStoreFailure("store_corrupt", "Vault storage is corrupt")
}

private fun Number.exactLongOrNull(): Long? = when (this) {
    is Byte, is Short, is Int, is Long -> toLong()
    else -> toString().toLongOrNull()
}

private fun requireRevision(revision: Int) {
    if (revision < 1) invalid("revision must be at least 1")
}

private fun validateText(name: String, value: String, max: Int, allowEmpty: Boolean) {
    if ((!allowEmpty && value.isEmpty()) || value.length > max) invalid("$name is invalid")
}

private fun invalid(message: String): Nothing = throw VaultStoreFailure("invalid_arguments", message)
