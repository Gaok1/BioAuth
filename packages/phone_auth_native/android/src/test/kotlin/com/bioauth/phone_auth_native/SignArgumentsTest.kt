package com.bioauth.phone_auth_native

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

internal class SignArgumentsTest {
    @Test
    fun parsesBoundedCanonicalPayloadAndContext() {
        val payload = byteArrayOf(1, 2, 3)
        val parsed = SignArguments.parse(
            mapOf(
                "payload" to payload,
                "context" to mapOf(
                    "title" to "Desktop-NixOS",
                    "subtitle" to "sudo",
                    "description" to "nixos-rebuild switch",
                ),
            ),
        )

        assertContentEquals(payload, parsed.payload)
        assertEquals("sudo", parsed.subtitle)
    }

    @Test
    fun rejectsMissingOrOversizedPayloads() {
        val context = mapOf(
            "title" to "Verifier",
            "subtitle" to "service",
            "description" to "action",
        )
        assertFailsWith<IllegalArgumentException> {
            SignArguments.parse(mapOf("payload" to byteArrayOf(), "context" to context))
        }
        assertFailsWith<IllegalArgumentException> {
            SignArguments.parse(mapOf("payload" to ByteArray(8193), "context" to context))
        }
    }
}
