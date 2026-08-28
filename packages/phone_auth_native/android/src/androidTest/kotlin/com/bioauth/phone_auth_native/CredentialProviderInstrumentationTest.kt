package com.bioauth.phone_auth_native

import android.Manifest
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.SystemClock
import android.provider.Settings
import androidx.biometric.BiometricManager
import androidx.credentials.CredentialManager
import androidx.credentials.provider.CallingAppInfo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import androidx.test.platform.app.InstrumentationRegistry
import java.security.MessageDigest
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.xmlpull.v1.XmlPullParser

@RunWith(AndroidJUnit4::class)
@SdkSuppress(minSdkVersion = 35)
class CredentialProviderInstrumentationTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val component by lazy { ComponentName(context, BioAuthCredentialProviderService::class.java) }
    private var originalProviders: String? = null

    @Before
    fun enableProvider() {
        assertTrue(Build.VERSION.SDK_INT >= 35)
        assertTrue(context.packageManager.hasSystemFeature(PackageManager.FEATURE_CREDENTIALS))
        originalProviders = Settings.Secure.getString(context.contentResolver, CREDENTIAL_SERVICE)
        val enabled = originalProviders.orEmpty().split(';')
            .filter { it.isNotBlank() && it != "null" }
            .plus(component.flattenToString())
            .distinct()
            .joinToString(";")
        writeProviders(enabled)
    }

    @After
    fun restoreProviders() {
        writeProviders(originalProviders)
    }

    @Test
    fun systemDiscoversAndEnablesTheCredentialProvider() {
        val service = context.packageManager.queryIntentServices(
            Intent(android.service.credentials.CredentialProviderService.SERVICE_INTERFACE)
                .setPackage(context.packageName),
            PackageManager.ResolveInfoFlags.of(PackageManager.GET_META_DATA.toLong()),
        ).map { it.serviceInfo }.single { it.name == BioAuthCredentialProviderService::class.java.name }

        assertTrue(service.exported)
        assertTrue(service.enabled)
        assertEquals(Manifest.permission.BIND_CREDENTIAL_PROVIDER_SERVICE, service.permission)
        val metadata = service.metaData.getInt(android.service.credentials.CredentialProviderService.SERVICE_META_DATA)
        assertNotEquals(0, metadata)
        assertEquals(setOf("androidx.credentials.TYPE_PUBLIC_KEY_CREDENTIAL"), capabilities(metadata))
        assertEquals(
            PackageManager.PERMISSION_DENIED,
            context.packageManager.checkPermission(
                Manifest.permission.BIND_CREDENTIAL_PROVIDER_SERVICE,
                instrumentation.context.packageName,
            ),
        )

        val platform = context.getSystemService(android.credentials.CredentialManager::class.java)
        val deadline = SystemClock.uptimeMillis() + 5000
        while (!platform.isEnabledCredentialProviderService(component) && SystemClock.uptimeMillis() < deadline) {
            SystemClock.sleep(100)
        }
        assertTrue(platform.isEnabledCredentialProviderService(component))
        assertTrue(CredentialManager.create(context).createSettingsPendingIntent().isActivity)
    }

    @Test
    fun selectionPendingIntentIsMutableButTargetsOnlyThePrivateActivity() {
        val activity = context.packageManager.getActivityInfo(componentForActivity(), 0)
        assertFalse(activity.exported)

        val first = credentialEntryPendingIntent(
            context,
            WebAuthnCredentialActivity.ACTION_GET,
            byteArrayOf(1),
        )
        val second = credentialEntryPendingIntent(
            context,
            WebAuthnCredentialActivity.ACTION_GET,
            byteArrayOf(2),
        )
        try {
            assertTrue(first.isActivity)
            assertFalse(first.isImmutable)
            assertEquals(context.packageName, first.creatorPackage)
            assertNotEquals(first, second)
        } finally {
            first.cancel()
            second.cancel()
        }
    }

    @Test
    fun privilegedOriginRequiresTheRealCallerCertificateInTheAllowlist() {
        val signatures = currentSignatures()
        val fingerprint = fingerprint(signatures.single().toByteArray())
        val caller = CallingAppInfo(context.packageName, signatures, "https://login.example.com")
        var fetched = false
        val validator = validator(
            privilegedAllowlist(context.packageName, fingerprint),
            AssetLinksFetcher {
                fetched = true
                error("asset links must not be fetched for a privileged browser")
            },
        )

        assertEquals("https://login.example.com", validator.validate("example.com", caller).origin)
        assertFalse(fetched)
        assertTrue(
            runCatching {
                validator(
                    privilegedAllowlist(context.packageName, "AA:BB"),
                    AssetLinksFetcher { error("unexpected fetch") },
                )
                    .validate("example.com", caller)
            }.isFailure,
        )
    }

    @Test
    fun nativeCallerMustBeAuthorizedByAssetLinksForItsInstalledCertificate() {
        val signatures = currentSignatures()
        val fingerprints = signatures.map { fingerprint(it.toByteArray()) }
        var fetchedRp: String? = null
        val validator = validator("{\"apps\":[]}", AssetLinksFetcher { rpId ->
            fetchedRp = rpId
            assetLinks(context.packageName, fingerprints)
        })

        val client = validator.validate("example.com", CallingAppInfo(context.packageName, signatures))
        assertEquals("example.com", fetchedRp)
        assertEquals(context.packageName, client.packageName)
        assertTrue(client.origin.startsWith("android:apk-key-hash:"))

        val denied = validator("{\"apps\":[]}", AssetLinksFetcher {
            assetLinks("com.example.phishing", fingerprints)
        })
        assertTrue(
            runCatching {
                denied.validate("example.com", CallingAppInfo(context.packageName, signatures))
            }.isFailure,
        )
    }

    @Test
    fun biometricPolicyAllowsOnlyStrongBiometricsAndConfirmation() {
        val info = webAuthnPromptInfo("Usar passkey", "example.com", null)
        assertEquals(BiometricManager.Authenticators.BIOMETRIC_STRONG, info.allowedAuthenticators)
        assertTrue(info.isConfirmationRequired)
        assertEquals("Cancelar", info.negativeButtonText)
        assertNotEquals(
            BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED,
            BiometricManager.from(context).canAuthenticate(
                BiometricManager.Authenticators.BIOMETRIC_STRONG,
            ),
        )
    }

    private fun componentForActivity() = ComponentName(context, WebAuthnCredentialActivity::class.java)

    private fun capabilities(resourceId: Int): Set<String> {
        val result = mutableSetOf<String>()
        context.resources.getXml(resourceId).use { parser ->
            while (parser.eventType != XmlPullParser.END_DOCUMENT) {
                if (parser.eventType == XmlPullParser.START_TAG && parser.name == "capability") {
                    parser.getAttributeValue(ANDROID_NAMESPACE, "name")?.let(result::add)
                }
                parser.next()
            }
        }
        return result
    }

    private fun currentSignatures() = context.packageManager.getPackageInfo(
        context.packageName,
        PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong()),
    ).signingInfo.let(::requireNotNull).apkContentsSigners.toList()

    private fun validator(allowlist: String, fetcher: AssetLinksFetcher) = RpIdValidator(
        allowlist,
        context.resources.openRawResource(R.raw.public_suffix_list).bufferedReader().use {
            PublicSuffixList(it.readLines().asSequence())
        },
        fetcher,
    )

    private fun writeProviders(value: String?) {
        instrumentation.uiAutomation.adoptShellPermissionIdentity(Manifest.permission.WRITE_SECURE_SETTINGS)
        try {
            assertTrue(Settings.Secure.putString(context.contentResolver, CREDENTIAL_SERVICE, value))
        } finally {
            instrumentation.uiAutomation.dropShellPermissionIdentity()
        }
    }

    private fun fingerprint(bytes: ByteArray) = MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString(":") { "%02X".format(it) }

    private fun privilegedAllowlist(packageName: String, fingerprint: String) = JSONObject()
        .put(
            "apps",
            JSONArray().put(
                JSONObject()
                    .put("type", "android")
                    .put(
                        "info",
                        JSONObject()
                            .put("package_name", packageName)
                            .put(
                                "signatures",
                                JSONArray().put(
                                    JSONObject()
                                        .put("build", "debug")
                                        .put("cert_fingerprint_sha256", fingerprint),
                                ),
                            ),
                    ),
            ),
        ).toString()

    private fun assetLinks(packageName: String, fingerprints: List<String>) = JSONArray()
        .put(
            JSONObject()
                .put("relation", JSONArray().put("delegate_permission/common.get_login_creds"))
                .put(
                    "target",
                    JSONObject()
                        .put("namespace", "android_app")
                        .put("package_name", packageName)
                        .put("sha256_cert_fingerprints", JSONArray(fingerprints)),
                ),
        ).toString()

    companion object {
        private const val CREDENTIAL_SERVICE = "credential_service"
        private const val ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"
    }
}
