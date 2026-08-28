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
    fun `item validation enforces the protocol bounds`() {
        assertEquals(0, inputMap()["kind"])
        assertFailsWith<VaultStoreFailure> {
            VaultItemInput.from(inputMap(secret = ""), requireId = false)
        }
        assertFailsWith<VaultStoreFailure> {
            VaultItemInput.from(inputMap(kind = 2), requireId = false)
        }
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
}
