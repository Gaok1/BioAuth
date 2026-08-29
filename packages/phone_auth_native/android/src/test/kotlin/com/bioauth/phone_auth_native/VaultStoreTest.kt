package com.bioauth.phone_auth_native

import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull

class VaultStoreTest {
    @Test
    fun `codec round trips all encrypted fields while summaries omit the secret`() {
        val item = item(secret = "correct horse battery staple")

        assertEquals(listOf(item), VaultStoreCodec.decode(VaultStoreCodec.encode(listOf(item))))
        assertFalse(item.summary().containsKey("secret"))
    }

    @Test
    fun `ciphertext uses pinned AAD and rejects a different one or a changed blob`() {
        assertContentEquals("bioauth-vault-store-v1".toByteArray(), VaultCiphertext.aad())
        val key = SecretKeySpec(ByteArray(32) { it.toByte() }, "AES")
        val encrypt = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
        val blob = VaultCiphertext.seal(encrypt, "vault".toByteArray())
        val decrypt = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, VaultCiphertext.iv(blob)))
        }
        assertContentEquals("vault".toByteArray(), VaultCiphertext.open(decrypt, blob))

        val tampered = blob.copyOf().also { it[it.lastIndex] = (it.last() + 1).toByte() }
        val tamperedCipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, VaultCiphertext.iv(tampered)))
        }
        assertFails { VaultCiphertext.open(tamperedCipher, tampered) }
    }

    @Test
    fun `revisions start at one advance and reject stale or zero writes`() {
        val (createdItems, created) = VaultStoreData.create(emptyList(), input(), 10, "item-1")
        assertEquals(1, created.revision)
        val (updatedItems, updated) = VaultStoreData.update(
            createdItems,
            input(id = "item-1", secret = "changed"),
            expectedRevision = 1,
            nowMs = 20,
        )
        assertEquals(2, updated.revision)
        assertEquals("changed", updatedItems.single().secret)

        val stale = assertFailsWith<VaultStoreFailure> {
            VaultStoreData.update(updatedItems, input(id = "item-1"), 1, 30)
        }
        assertEquals("revision_conflict", stale.code)
        assertEquals(mapOf("expectedRevision" to 1, "currentRevision" to 2), stale.details)
        assertEquals("invalid_arguments", assertFailsWith<VaultStoreFailure> {
            VaultStoreData.delete(updatedItems, "item-1", 0)
        }.code)
    }

    @Test
    fun `delete is optimistic and never silently removes a newer item`() {
        val items = listOf(item(revision = 4))
        assertEquals("revision_conflict", assertFailsWith<VaultStoreFailure> {
            VaultStoreData.delete(items, "item-1", 3)
        }.code)
        assertEquals(emptyList(), VaultStoreData.delete(items, "item-1", 4))
    }

    @Test
    fun `list pages at 32 without exposing secrets`() {
        val items = (0 until 33).map { index ->
            item(id = "item-$index", updatedAtMs = index.toLong(), secret = "secret-$index")
        }
        val first = VaultStoreData.page(items, null)
        val firstItems = first["items"] as List<*>
        assertEquals(32, firstItems.size)
        assertEquals("32", first["nextCursor"])
        assertFalse((firstItems.first() as Map<*, *>).containsKey("secret"))

        val second = VaultStoreData.page(items, "32")
        assertEquals(1, (second["items"] as List<*>).size)
        assertNull(second["nextCursor"])
    }

    @Test
    fun `every item comes back in one answer, in the order the pages use`() {
        // The paged walk is one biometric prompt per page, because the key is
        // auth-per-use and every call decrypts the blob again. This is the
        // whole vault for one prompt, and it has to agree with `page` about
        // the order or the same vault would list differently on two screens.
        val items = (0 until 70).map { index ->
            item(id = "item-$index", updatedAtMs = index.toLong(), secret = "secret-$index")
        }
        val all = VaultStoreData.all(items)["items"] as List<*>
        assertEquals(70, all.size)
        assertFalse((all.first() as Map<*, *>).containsKey("secret"))

        val paged = mutableListOf<Any?>()
        var cursor: String? = null
        do {
            val page = VaultStoreData.page(items, cursor)
            paged.addAll(page["items"] as List<*>)
            cursor = page["nextCursor"] as String?
        } while (cursor != null)
        assertEquals(all, paged.toList())
    }

    @Test
    fun `item validation enforces the protocol bounds`() {
        assertEquals(0, inputMap()["kind"])
        assertFailsWith<VaultStoreFailure> {
            VaultItemInput.from(inputMap(secret = ""), requireId = false)
        }
        // One past the last known kind, derived rather than written as a
        // literal: `2` used to be the unknown one and became `totp`, which
        // turned this assertion into a test of a valid value.
        assertFailsWith<VaultStoreFailure> {
            VaultItemInput.from(
                inputMap(kind = (KIND_RANGE.last + 1).toInt()),
                requireId = false,
            )
        }
        // And the kind that was just added is accepted, so widening the range
        // is not something a later change can quietly undo.
        assertEquals(
            KIND_RANGE.last.toInt(),
            VaultItemInput.from(
                inputMap(kind = KIND_RANGE.last.toInt()),
                requireId = false,
            ).kind,
        )
        assertFailsWith<VaultStoreFailure> {
            VaultItemInput.from(inputMap(name = "x".repeat(256)), requireId = false)
        }
    }

    private fun item(
        id: String = "item-1",
        revision: Int = 1,
        secret: String = "secret",
        updatedAtMs: Long = 1,
    ) = VaultItem(id, revision, 0, "Example", "person", "https://example.com", secret, updatedAtMs)

    private fun input(id: String? = null, secret: String = "secret") =
        VaultItemInput(id, 0, "Example", "person", "https://example.com", secret)

    private fun inputMap(kind: Int = 0, name: String = "Example", secret: String = "secret") = mapOf(
        "kind" to kind,
        "name" to name,
        "username" to "person",
        "uri" to "https://example.com",
        "secret" to secret,
    )

    @Test
    fun `export carries the secrets a summary withholds`() {
        val items = listOf(item(id = "a", secret = "hunter2"), item(id = "b", secret = "correct horse"))

        val exported = VaultStoreData.export(items)

        assertEquals(listOf("hunter2", "correct horse"), exported.map { it["secret"] })
        // The id is deliberately absent: it belongs to the vault this came
        // from, and a restore mints its own.
        assertFalse(exported.first().containsKey("id"))
        assertFalse(exported.first().containsKey("revision"))
    }

    @Test
    fun `restore adds to a vault instead of replacing it`() {
        val existing = listOf(item(id = "keep", secret = "already here"))
        val incoming = listOf(input(secret = "from the backup").copy(name = "Outro"))

        val (restored, added, skipped) = VaultStoreData.restore(existing, incoming, nowMs = 99)

        assertEquals(1, added)
        assertEquals(0, skipped)
        assertEquals(2, restored.size)
        assertEquals("already here", restored.first { it.id == "keep" }.secret)
    }

    @Test
    fun `restoring the same backup twice does not duplicate it`() {
        val incoming = listOf(input(secret = "s"))

        val (once, firstAdded, _) = VaultStoreData.restore(emptyList(), incoming, nowMs = 1)
        val (twice, secondAdded, skipped) = VaultStoreData.restore(once, incoming, nowMs = 2)

        assertEquals(1, firstAdded)
        assertEquals(0, secondAdded)
        assertEquals(1, skipped)
        assertEquals(1, twice.size)
    }

    /// A restored item gets a fresh id, because the one in the backup belonged
    /// to another vault and could collide with an unrelated item here.
    @Test
    fun `restore mints new ids rather than reusing the backup's`() {
        val incoming = listOf(input(id = "id-from-elsewhere", secret = "s").copy(name = "Novo"))

        val (restored, _, _) = VaultStoreData.restore(emptyList(), incoming, nowMs = 7)

        assertEquals(1, restored.size)
        assertFalse(restored.single().id == "id-from-elsewhere")
        assertEquals(1, restored.single().revision)
        assertEquals(7, restored.single().updatedAtMs)
    }

    @Test
    fun `a restore that would overflow the vault is refused whole`() {
        val incoming = List(VaultStoreData.MAX_ITEMS + 1) { input(secret = "s").copy(name = "n$it") }

        assertFailsWith<VaultStoreFailure> {
            VaultStoreData.restore(emptyList(), incoming, nowMs = 1)
        }
    }
}
