package com.bioauth.phone_auth_native

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

class LuksKeyStoreTest {
    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }

    private fun binding() = ByteArray(32) { it.toByte() }

    @Test
    fun `wrapper additional data is pinned`() {
        assertContentEquals(
            "2cc47ec0c5b66f95b3419c0b264d59166ed00b43f9f28ef0c4bb99e4f3f22cb0".chunked(2)
                .map { it.toInt(16).toByte() }
                .toByteArray(),
            LuksKeyStore.wrapperAad(binding(), "disk-cred-1"),
        )
    }

    @Test
    fun `LUKS and File Locker cannot share key or domain`() {
        assertNotEquals(LuksKeyStore.KEY_ALIAS, LockerKeyStore.KEY_ALIAS)
        assertNotEquals(
            hex(LuksKeyStore.wrapperAad(binding(), "disk-cred-1")),
            hex(LockerKeyStore.wrapperAad(binding(), "disk-cred-1")),
        )
    }

    @Test
    fun `credential and volume are authenticated`() {
        assertNotEquals(
            hex(LuksKeyStore.wrapperAad(binding(), "disk-cred-1")),
            hex(LuksKeyStore.wrapperAad(binding(), "disk-cred-2")),
        )
        assertNotEquals(
            hex(LuksKeyStore.wrapperAad(binding(), "disk-cred-1")),
            hex(LuksKeyStore.wrapperAad(ByteArray(32) { (it + 1).toByte() }, "disk-cred-1")),
        )
    }

    @Test
    fun `invalid binding is refused`() {
        assertFailsWith<IllegalArgumentException> {
            LuksKeyStore.wrapperAad(ByteArray(31), "disk-cred-1")
        }
    }
}
