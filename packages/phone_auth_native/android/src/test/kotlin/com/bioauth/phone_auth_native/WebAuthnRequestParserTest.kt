package com.bioauth.phone_auth_native

import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

internal class WebAuthnRequestParserTest {
    @Test
    fun parsesCreationAndAssertionOptions() {
        val challenge = b64(ByteArray(32) { it.toByte() })
        val user = b64(byteArrayOf(1, 2, 3))
        val creation = WebAuthnRequestParser.creation(
            """{
              "rp":{"id":"example.org","name":"Example"},
              "user":{"id":"$user","name":"alice","displayName":"Alice"},
              "challenge":"$challenge",
              "pubKeyCredParams":[{"type":"public-key","alg":-7}]
            }""",
        )
        val request = WebAuthnRequestParser.request(
            """{"rpId":"example.org","challenge":"$challenge"}""",
        )

        assertEquals("example.org", creation.rpId)
        assertContentEquals(byteArrayOf(1, 2, 3), creation.userHandle)
        assertEquals("example.org", request.rpId)
        assertContentEquals(ByteArray(32) { it.toByte() }, request.challenge)
    }

    @Test
    fun rejectsUnsupportedAlgorithmsAndMalformedRpIds() {
        val challenge = b64(ByteArray(32))
        val base = """{
          "rp":{"id":"%s","name":"Example"},
          "user":{"id":"AQ","name":"alice"},
          "challenge":"$challenge",
          "pubKeyCredParams":[{"type":"public-key","alg":%d}]
        }"""

        assertFailsWith<IllegalArgumentException> {
            WebAuthnRequestParser.creation(base.format("example.org", -257))
        }
        assertFailsWith<IllegalArgumentException> {
            WebAuthnRequestParser.creation(base.format("https://example.org", -7))
        }
        assertFailsWith<IllegalArgumentException> {
            WebAuthnRequestParser.creation(base.format("example.org?internal", -7))
        }
    }

    @Test
    fun rejectsShortChallengesAndOversizedUserHandles() {
        val template = """{
          "rp":{"id":"example.org","name":"Example"},
          "user":{"id":"%s","name":"alice"},
          "challenge":"%s",
          "pubKeyCredParams":[{"type":"public-key","alg":-7}]
        }"""
        assertFailsWith<IllegalArgumentException> {
            WebAuthnRequestParser.creation(template.format("AQ", b64(ByteArray(15))))
        }
        assertFailsWith<IllegalArgumentException> {
            WebAuthnRequestParser.creation(template.format(b64(ByteArray(65)), b64(ByteArray(32))))
        }
    }

    @Test
    fun rejectsMalformedCredentialDescriptorsInsteadOfTreatingThemAsDiscoverable() {
        val challenge = b64(ByteArray(32))
        assertFailsWith<IllegalArgumentException> {
            WebAuthnRequestParser.request(
                """{
                  "rpId":"example.org",
                  "challenge":"$challenge",
                  "allowCredentials":[{"type":"password","id":"AQ"}]
                }""",
            )
        }
    }

    @Test
    fun validatesSelectionAttestationVerificationAndExtensions() {
        val challenge = b64(ByteArray(32))
        val supported = WebAuthnRequestParser.creation(
            """{
              "rp":{"id":"example.org","name":"Example"},
              "user":{"id":"AQ","name":"alice"},
              "challenge":"$challenge",
              "pubKeyCredParams":[{"type":"public-key","alg":-7}],
              "authenticatorSelection":{"authenticatorAttachment":"platform","residentKey":"required","userVerification":"required"},
              "attestation":"none",
              "extensions":{"credProps":true}
            }""",
        )
        assertTrue(supported.reportCredentialProperties)

        // The one a real site asks for by default, and the one this relay
        // actually is: the browser is on a computer and the authenticator is a
        // phone somewhere else. Refusing it ended the ceremony before any key
        // was touched, with the site saying the authenticator would not do it.
        WebAuthnRequestParser.creation(
            """{
              "rp":{"id":"example.org","name":"Example"},
              "user":{"id":"AQ","name":"alice"},
              "challenge":"$challenge",
              "pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],
              "authenticatorSelection":{"authenticatorAttachment":"cross-platform","requireResidentKey":true,"residentKey":"required","userVerification":"required"},
              "attestation":"direct",
              "timeout":60000
            }""",
        )

        // Attestation conveyance is a preference the relying party states and the
        // client answers as best it can. Every value the spec defines is accepted
        // and answered with none attestation; refusing `direct` refused
        // registration outright on most real sites, before a key was ever touched.
        for (preference in listOf("none", "indirect", "direct", "enterprise")) {
            WebAuthnRequestParser.creation(
                """{
                  "rp":{"id":"example.org","name":"Example"},
                  "user":{"id":"AQ","name":"alice"},
                  "challenge":"$challenge",
                  "pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],
                  "attestation":"$preference"
                }""",
            )
        }

        for (unsupported in listOf(
            "\"authenticatorSelection\":{\"authenticatorAttachment\":\"roaming\"}",
            "\"attestation\":\"whatever\"",
            "\"extensions\":{\"largeBlob\":{\"support\":\"required\"}}",
        )) {
            assertFailsWith<IllegalArgumentException> {
                WebAuthnRequestParser.creation(
                    """{
                      "rp":{"id":"example.org","name":"Example"},
                      "user":{"id":"AQ","name":"alice"},
                      "challenge":"$challenge",
                      "pubKeyCredParams":[{"type":"public-key","alg":-7}],
                      $unsupported
                    }""",
                )
            }
        }

        assertFailsWith<IllegalArgumentException> {
            WebAuthnRequestParser.request(
                """{"rpId":"example.org","challenge":"$challenge","userVerification":"sometimes"}""",
            )
        }
    }

    private fun b64(value: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(value)
}
