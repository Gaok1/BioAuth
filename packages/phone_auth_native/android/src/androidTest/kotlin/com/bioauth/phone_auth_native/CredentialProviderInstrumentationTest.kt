package com.bioauth.phone_auth_native

import android.Manifest
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
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
        originalProviders = readProviders()
        val enabled = originalProviders.orEmpty().split(PROVIDER_SEPARATOR)
            .filter { it.isNotBlank() && it != "null" }
            .plus(component.flattenToString())
            .distinct()
            .joinToString(PROVIDER_SEPARATOR)
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
        assertEquals(
            setOf(
                "androidx.credentials.TYPE_PUBLIC_KEY_CREDENTIAL",
                "androidx.credentials.TYPE_PASSWORD_CREDENTIAL",
            ),
            capabilities(metadata),
        )
        assertEquals(
            PackageManager.PERMISSION_DENIED,
            context.packageManager.checkPermission(
                Manifest.permission.BIND_CREDENTIAL_PROVIDER_SERVICE,
                instrumentation.context.packageName,
            ),
        )

        // The setting is written by `@Before`; the system server adopts it from
        // a settings observer, so this is a wait rather than a read. Every test
        // in this class writes and restores the same key, so the server is
        // rebuilding its provider list around all of them and the window has to
        // cover the slowest of those rebuilds, not the median one.
        val platform = context.getSystemService(android.credentials.CredentialManager::class.java)
        val deadline = SystemClock.uptimeMillis() + ADOPTION_WINDOW_MS
        while (!platform.isEnabledCredentialProviderService(component) && SystemClock.uptimeMillis() < deadline) {
            SystemClock.sleep(100)
        }
        // Named, because a bare `assertTrue` here reports `java.lang.AssertionError`
        // and nothing else -- and on CI this runs on an emulator nobody can open
        // afterwards, so whatever the failure does not say is not knowable.
        assertTrue(
            "the system did not adopt this provider within ${ADOPTION_WINDOW_MS}ms; " +
                "$CREDENTIAL_SERVICE holds <${readProviders()}> and this component is " +
                "<${component.flattenToString()}>",
            platform.isEnabledCredentialProviderService(component),
        )
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
        val signingInfo = currentSigningInfo()
        val fingerprint = fingerprint(signingInfo.apkContentsSigners.single().toByteArray())
        val caller = CallingAppInfo(context.packageName, signingInfo, "https://login.example.com")
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
        val signingInfo = currentSigningInfo()
        val fingerprints = signingInfo.apkContentsSigners.map { fingerprint(it.toByteArray()) }
        var fetchedRp: String? = null
        val validator = validator("{\"apps\":[]}", AssetLinksFetcher { rpId ->
            fetchedRp = rpId
            assetLinks(context.packageName, fingerprints)
        })

        val client = validator.validate("example.com", CallingAppInfo(context.packageName, signingInfo))
        assertEquals("example.com", fetchedRp)
        assertEquals(context.packageName, client.packageName)
        assertTrue(client.origin.startsWith("android:apk-key-hash:"))

        val denied = validator("{\"apps\":[]}", AssetLinksFetcher {
            assetLinks("com.example.phishing", fingerprints)
        })
        assertTrue(
            runCatching {
                denied.validate("example.com", CallingAppInfo(context.packageName, signingInfo))
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

    /// The credential types the provider XML declares.
    ///
    /// `name` is looked up in either namespace. The shipped XML writes it
    /// unqualified, so reading it only under the android namespace found
    /// nothing -- an empty set, which reads as a provider that declares no
    /// capabilities at all rather than as a test looking in the wrong place.
    private fun capabilities(resourceId: Int): Set<String> {
        val result = mutableSetOf<String>()
        context.resources.getXml(resourceId).use { parser ->
            while (parser.eventType != XmlPullParser.END_DOCUMENT) {
                if (parser.eventType == XmlPullParser.START_TAG && parser.name == "capability") {
                    val name = parser.getAttributeValue(ANDROID_NAMESPACE, "name")
                        ?: parser.getAttributeValue(null, "name")
                    name?.let(result::add)
                }
                parser.next()
            }
        }
        return result
    }

    /// The signing identity the platform holds for this package.
    ///
    /// Handed to [CallingAppInfo] whole rather than as a list of signatures.
    /// The list-taking constructors still exist but throw on sight -- "Use
    /// SigningInfoCompat.fromSigningInfo(SigningInfo) instead" -- and a
    /// `SigningInfo` is what the platform actually hands a provider, so this
    /// is also the shape the service sees in production.
    private fun currentSigningInfo() = context.packageManager.getPackageInfo(
        context.packageName,
        PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong()),
    ).signingInfo.let(::requireNotNull)

    private fun validator(allowlist: String, fetcher: AssetLinksFetcher) = RpIdValidator(
        allowlist,
        context.resources.openRawResource(R.raw.public_suffix_list).bufferedReader().use {
            PublicSuffixList(it.readLines().asSequence())
        },
        fetcher,
    )

    /// Reads the enabled-providers setting, as the shell rather than as us.
    ///
    /// `credential_service` is `@hide`, and from S+ a `@hide` key is unreadable
    /// by an ordinary app -- the restriction is on who is asking, not on what
    /// they hold, so adopting the shell's *permissions* does not lift it.
    /// Running the command adopts the shell's *uid*, which does.
    private fun readProviders(): String? =
        shell("settings get secure $CREDENTIAL_SERVICE").trim()
            .takeUnless { it.isEmpty() || it == "null" }

    private fun writeProviders(value: String?) {
        // Same route as the read, for the same reason. Neither the component
        // list nor the key contains whitespace, and nothing here is run by a
        // shell -- the command is split on spaces and exec'd -- so the
        // separator needs no quoting and would not survive it.
        if (value == null) {
            shell("settings delete secure $CREDENTIAL_SERVICE")
        } else {
            shell("settings put secure $CREDENTIAL_SERVICE $value")
        }
        assertEquals(value, readProviders())
    }

    private fun shell(command: String): String =
        ParcelFileDescriptor.AutoCloseInputStream(
            instrumentation.uiAutomation.executeShellCommand(command),
        ).use { it.readBytes().decodeToString() }

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

        /**
         * What separates one enabled provider from the next in that setting.
         *
         * `CredentialManagerService` splits the value on `:`. Written with a
         * `;` the whole setting is a single token that resolves to no
         * component at all, so nothing was enabled -- not this provider, and
         * not the Google one that was already there. The setting still read
         * back exactly as written, which is why the failure looked like the
         * system ignoring a component it had plainly been given.
         */
        private const val PROVIDER_SEPARATOR = ":"

        /**
         * How long the system server gets to pick up a written provider list.
         *
         * Only ever spent in full on the way to a failure, so it is generous.
         */
        private const val ADOPTION_WINDOW_MS = 15000L
        private const val ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"
    }
}
