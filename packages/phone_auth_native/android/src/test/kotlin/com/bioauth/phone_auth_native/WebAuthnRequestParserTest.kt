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
    fun acceptsAChallengeTheRelyingPartySizedItself() {
        // Sixteen bytes was a floor taken from advice the specification gives
        // to *relying parties* about their own ceremonies. Enforced here it
        // made no relying party safer and turned Google's sign-in away: the
        // audit log read "challenge must contain 16..1024 bytes", and because
        // only the assertion was out of range, the passkey could be registered
        // on the same site and then never used.
        val short = WebAuthnRequestParser.request(
            """{"rpId":"example.org","challenge":"${b64(ByteArray(8) { it.toByte() })}"}""",
        )
        assertContentEquals(ByteArray(8) { it.toByte() }, short.challenge)

        // There is still a ceiling, and it is the one every base64url field
        // shares rather than a second one layered over it.
        val huge = assertFailsWith<IllegalArgumentException> {
            WebAuthnRequestParser.request(
                """{"rpId":"example.org","challenge":"${b64(ByteArray(4096))}"}""",
            )
        }
        // The message carries the limit and the length. That is not a nicety:
        // the bound this test exists for was found in seconds only because the
        // rejection happened to name its numbers in the audit log.
        assertTrue(huge.message!!.contains("4096"), huge.message!!)
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

        // A list that names algorithms this authenticator cannot sign with is
        // a refusal, above. A list that names none is not: absent or empty
        // means the relying party stated no preference, and `create()`
        // substitutes the client defaults, ES256 among them.
        for (unstated in listOf("", ""","pubKeyCredParams":[]""")) {
            WebAuthnRequestParser.creation(
                """{
                  "rp":{"id":"example.org","name":"Example"},
                  "user":{"id":"AQ","name":"alice"},
                  "challenge":"$challenge"
                  $unstated
                }""",
            )
        }
    }

    @Test
    fun rejectsOversizedUserHandles() {
        val template = """{
          "rp":{"id":"example.org","name":"Example"},
          "user":{"id":"%s","name":"alice"},
          "challenge":"%s",
          "pubKeyCredParams":[{"type":"public-key","alg":-7}]
        }"""
        // A fifteen-byte challenge used to be refused here too. It is not this
        // side's call -- see `acceptsAChallengeTheRelyingPartySizedItself`.
        // The user handle is different: sixty-four bytes is the limit the
        // specification puts on the relying party, and a longer one is a
        // request that cannot be served rather than one we disapprove of.
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
    fun acceptsOnlyAFullWindowsClientDataHash() {
        val hash = ByteArray(32) { it.toByte() }
        val client = relayClientData(
            "https://example.org",
            """{"clientDataHash":"${b64(hash)}"}""",
        )
        assertContentEquals(hash, client.suppliedHash)
        // The desktop relay is not a platform authenticator and must not say
        // it is: the browser is on the computer and the key is on a phone at
        // the other end of a link. It is the same fact the parser leans on
        // when it accepts a `cross-platform` request.
        assertEquals(ATTACHMENT_CROSS_PLATFORM, client.attachment)
        assertEquals(
            ATTACHMENT_CROSS_PLATFORM,
            relayClientData("https://example.org", "{}").attachment,
        )
        // Credential Manager runs on the same phone, so there it is the truth.
        assertEquals(ATTACHMENT_PLATFORM, WebAuthnClientData("https://x.example", null).attachment)
        assertEquals(null, relayClientData("https://example.org", "{}").suppliedHash)
        assertFailsWith<IllegalArgumentException> {
            relayClientData("https://example.org", """{"clientDataHash":"${b64(ByteArray(31))}"}""")
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
              "extensions":{"credProps":true},
              "returnAuthenticatorData":true
            }""",
        )
        assertTrue(supported.reportCredentialProperties)
        assertTrue(supported.returnAuthenticatorData)

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

        // An extension this provider does not implement is ignored, and the
        // one it does is still read. Refusing the rest is what kept PhoneAuth
        // out of the passkey picker on sites that send U2F migration hints:
        // `appidExclude` on registration, `appid` on sign-in. The desktop
        // extension strips both as the WebAuthn client it stands in for, so
        // this only ever failed on the phone's own browser, where Credential
        // Manager hands the site's JSON straight through.
        val ignored = WebAuthnRequestParser.creation(
            """{
              "rp":{"id":"example.org","name":"Example"},
              "user":{"id":"AQ","name":"alice"},
              "challenge":"$challenge",
              "pubKeyCredParams":[{"type":"public-key","alg":-7}],
              "extensions":{
                "appidExclude":"https://example.org/u2f",
                "credProps":true,
                "largeBlob":{"support":"required"},
                "prf":{}
              }
            }""",
        )
        assertTrue(ignored.reportCredentialProperties)

        // The assertion side of the same rule, and the one that was silent: a
        // request carrying `appid` was thrown out before any credential was
        // looked up, so the provider returned no entries at all.
        val asserted = WebAuthnRequestParser.request(
            """{
              "rpId":"example.org",
              "challenge":"$challenge",
              "userVerification":"required",
              "extensions":{"appid":"https://example.org/u2f","uvm":true}
            }""",
        )
        assertEquals("example.org", asserted.rpId)

        // Malformed stays malformed: `extensions` is an object, and the one
        // extension this provider answers is a boolean.
        for (malformed in listOf(
            """{"rpId":"example.org","challenge":"$challenge","extensions":"appid"}""",
        )) {
            assertFailsWith<IllegalArgumentException> { WebAuthnRequestParser.request(malformed) }
        }

        for (unsupported in listOf(
            "\"authenticatorSelection\":{\"authenticatorAttachment\":\"roaming\"}",
            "\"attestation\":\"whatever\"",
            "\"extensions\":{\"credProps\":\"yes\"}",
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
