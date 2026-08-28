package com.bioauth.phone_auth_native

import kotlin.test.Test
import kotlin.test.assertContentEquals

internal class WebAuthnAccountSelectionTest {
    @Test
    fun keepsEveryDiscoverableAccountInCredentialOrder() {
        val records = listOf(
            record("alice", "Alice"),
            record("work", "Alice Work"),
        )

        assertContentEquals(
            arrayOf("Alice · alice", "Alice Work · work"),
            accountLabels(records),
        )
    }

    private fun record(userName: String, displayName: String) = PasskeyRecord(
        credentialId = byteArrayOf(userName.length.toByte()),
        rpId = "example.com",
        userHandle = byteArrayOf(1),
        userName = userName,
        userDisplayName = displayName,
        keyAlias = WebAuthnKeyStore.ALIAS_PREFIX + userName,
        signCount = 0u,
        createdAtMillis = 1,
    )
}
