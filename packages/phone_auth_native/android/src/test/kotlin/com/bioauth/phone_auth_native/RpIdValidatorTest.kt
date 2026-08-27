package com.bioauth.phone_auth_native

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

internal class RpIdValidatorTest {
    private val assetLinks = """[
      {
        "relation":["delegate_permission/common.get_login_creds"],
        "target":{
          "namespace":"android_app",
          "package_name":"com.example.app",
          "sha256_cert_fingerprints":["AA:BB"]
        }
      }
    ]"""

    @Test
    fun acceptsOnlyTheBoundPackageCertificateAndRelation() {
        assertTrue(RpIdValidator.validateAssetLinks(assetLinks, "com.example.app", listOf("AA:BB")))
        assertFalse(RpIdValidator.validateAssetLinks(assetLinks, "com.phishing.app", listOf("AA:BB")))
        assertFalse(RpIdValidator.validateAssetLinks(assetLinks, "com.example.app", listOf("CC:DD")))
        assertFalse(RpIdValidator.validateAssetLinks("[]", "com.example.app", listOf("AA:BB")))
    }

    // Enough of the real list to cover an ICANN suffix, a multi-label one, a
    // wildcard with its exception, and the private section that matters most.
    private val suffixes = PublicSuffixList(
        sequenceOf(
            "// comment", "com", "net", "br", "com.br", "uk", "co.uk",
            "*.ck", "!www.ck", "io", "github.io", "app", "vercel.app",
        ),
    )

    @Test
    fun webOriginsAreBoundToTheRpIdAndHttps() {
        RpIdValidator.requireOriginMatchesRpId("https://login.example.com", "example.com", suffixes)
        assertFailsWith<IllegalArgumentException> {
            RpIdValidator.requireOriginMatchesRpId("https://example.net", "example.com", suffixes)
        }
        assertFailsWith<IllegalArgumentException> {
            RpIdValidator.requireOriginMatchesRpId("http://example.com", "example.com", suffixes)
        }
        assertFailsWith<IllegalArgumentException> {
            RpIdValidator.requireOriginMatchesRpId("https://example.com/phishing", "example.com", suffixes)
        }
    }

    @Test
    fun anRpIdIsComparedWithoutRegardToCase() {
        RpIdValidator.requireOriginMatchesRpId("https://login.example.com", "Example.COM", suffixes)
    }

    /**
     * The attack this closes: a page under a public suffix claiming the suffix
     * itself, which every sibling site could then ask for.
     */
    @Test
    fun aPublicSuffixIsNeverAValidRelyingParty() {
        for (suffix in listOf("com", "com.br", "co.uk", "github.io", "vercel.app", "foo.ck")) {
            assertFailsWith<IllegalArgumentException>("`$suffix` must be rejected") {
                RpIdValidator.requireOriginMatchesRpId("https://evil.$suffix", suffix, suffixes)
            }
        }
        // One label deeper is registrable and stays allowed.
        RpIdValidator.requireOriginMatchesRpId("https://a.shop.com.br", "shop.com.br", suffixes)
        RpIdValidator.requireOriginMatchesRpId("https://mine.github.io", "mine.github.io", suffixes)
        // The exception rule makes `www.ck` registrable even under `*.ck`.
        RpIdValidator.requireOriginMatchesRpId("https://www.ck", "www.ck", suffixes)
    }
}
