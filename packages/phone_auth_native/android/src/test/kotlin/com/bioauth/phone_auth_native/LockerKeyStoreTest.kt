package com.bioauth.phone_auth_native

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/**
 * The half of the locker key store that does not need a device.
 *
 * The additional data is computed independently on both sides — in Rust when
 * the desktop builds a container, and here when the phone wraps its key — so it
 * is pinned in both. If either side changes it, one of the two tests fails
 * instead of every container quietly refusing to open on a phone.
 */
class LockerKeyStoreTest {
    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }

    private fun binding() = ByteArray(32) { it.toByte() }

    @Test
    fun `wrapper additional data matches the desktop vector`() {
        assertArrayEquals(
            // Same value as `format::tests::the_wrapper_additional_data_is_pinned_for_the_phone`.
            "1e4fbb889c27e1d7ed6dfc9989f638393416c0c2b84648cefa70f1af63241d20".chunked(2)
                .map { it.toInt(16).toByte() }
                .toByteArray(),
            LockerKeyStore.wrapperAad(binding(), "locker-cred-1"),
        )
    }

    @Test
    fun `a different credential gives different additional data`() {
        assertNotEquals(
            hex(LockerKeyStore.wrapperAad(binding(), "locker-cred-1")),
            hex(LockerKeyStore.wrapperAad(binding(), "locker-cred-2")),
        )
    }

    @Test
    fun `a different container gives different additional data`() {
        val other = ByteArray(32) { (it + 1).toByte() }
        assertNotEquals(
            hex(LockerKeyStore.wrapperAad(binding(), "locker-cred-1")),
            hex(LockerKeyStore.wrapperAad(other, "locker-cred-1")),
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `a binding that is not 32 bytes is refused`() {
        LockerKeyStore.wrapperAad(ByteArray(31), "locker-cred-1")
    }
}
