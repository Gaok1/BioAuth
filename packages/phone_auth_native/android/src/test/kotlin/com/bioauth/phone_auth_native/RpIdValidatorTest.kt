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

    @Test
    fun webOriginsAreBoundToTheRpIdAndHttps() {
        RpIdValidator.requireOriginMatchesRpId("https://login.example.com", "example.com")
        assertFailsWith<IllegalArgumentException> {
            RpIdValidator.requireOriginMatchesRpId("https://example.net", "example.com")
        }
        assertFailsWith<IllegalArgumentException> {
            RpIdValidator.requireOriginMatchesRpId("http://example.com", "example.com")
        }
        assertFailsWith<IllegalArgumentException> {
            RpIdValidator.requireOriginMatchesRpId("https://example.com/phishing", "example.com")
        }
    }
}
