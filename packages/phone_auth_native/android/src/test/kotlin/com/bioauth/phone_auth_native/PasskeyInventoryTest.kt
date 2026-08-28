package com.bioauth.phone_auth_native

import kotlin.test.Test
import kotlin.test.assertEquals

internal class PasskeyInventoryTest {
    @Test
    fun detectsMissingInvalidAndOrphanedNativeKeys() {
        val available = record("available")
        val invalid = record("invalid")
        val missing = record("missing")
        val orphan = WebAuthnKeyStore.ALIAS_PREFIX + "orphan"

        val inventory = passkeyInventory(
            listOf(available, invalid, missing),
            setOf(available.keyAlias, invalid.keyAlias, orphan),
        ) { alias -> alias == available.keyAlias }

        assertEquals(
            listOf("available", "invalidKey", "missingKey", "orphanKey"),
            inventory.map { it["status"] },
        )
        assertEquals("orphan", inventory.last()["kind"])
        assertEquals(orphan, inventory.last()["identifier"])
    }

    private fun record(name: String) = PasskeyRecord(
        credentialId = name.toByteArray(),
        rpId = "example.com",
        userHandle = byteArrayOf(1),
        userName = name,
        userDisplayName = name,
        keyAlias = WebAuthnKeyStore.ALIAS_PREFIX + name,
        signCount = 0u,
        createdAtMillis = 1,
    )
}
