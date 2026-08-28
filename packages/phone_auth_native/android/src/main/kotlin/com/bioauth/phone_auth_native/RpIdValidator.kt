package com.bioauth.phone_auth_native

import android.content.Context
import androidx.credentials.provider.CallingAppInfo
import androidx.annotation.RequiresApi
import org.json.JSONArray
import java.io.IOException
import java.net.URL
import java.net.URI
import java.security.MessageDigest
import javax.net.ssl.HttpsURLConnection

internal fun interface AssetLinksFetcher {
    fun fetch(rpId: String): String
}

internal class RpIdValidator(
    private val privilegedAllowlist: String,
    private val publicSuffixes: PublicSuffixList,
    private val fetcher: AssetLinksFetcher = AssetLinksFetcher(::fetchAssetLinks),
) {
    /**
     * The web origin a privileged browser is speaking for, or null when the
     * caller is an ordinary app speaking for itself.
     *
     * Exists so callers can ask without the allowlist leaving this class. The
     * allowlist is what decides whether a caller may claim to be a website at
     * all, and handing it out invites a second, wronger copy of that check.
     */
    @RequiresApi(28)
    fun originOf(caller: CallingAppInfo): String? =
        if (caller.isOriginPopulated()) caller.getOrigin(privilegedAllowlist) else null

    @RequiresApi(28)
    fun validate(rpId: String, caller: CallingAppInfo): WebAuthnClientData {
        if (caller.isOriginPopulated()) {
            val origin = caller.getOrigin(privilegedAllowlist)
                ?: throw SecurityException("Privileged browser origin is unavailable")
            requireOriginMatchesRpId(origin, rpId, publicSuffixes)
            return WebAuthnClientData(origin = origin, packageName = null)
        }

        requireRegistrableDomain(rpId, publicSuffixes)
        val signatures = caller.signingInfoCompat.apkContentsSigners
        require(signatures.size == 1) { "Calling app must have one current signing certificate" }
        val fingerprints = signatures.map { fingerprint(it.toByteArray()) }
        require(validateAssetLinks(fetcher.fetch(rpId), caller.packageName, fingerprints)) {
            "Relying party does not authorize the calling Android app"
        }
        val originHash = MessageDigest.getInstance("SHA-256").digest(signatures.single().toByteArray())
        return WebAuthnClientData(
            origin = "android:apk-key-hash:${WebAuthnRequestParser.base64Url(originHash)}",
            packageName = caller.packageName,
        )
    }

    companion object {
        private const val RELATION = "delegate_permission/common.get_login_creds"

        /** Builds a validator over the two bundled lists. */
        fun fromResources(context: Context): RpIdValidator {
            val resources = context.resources
            val allowlist = resources.openRawResource(R.raw.privileged_browsers)
                .bufferedReader().use { it.readText() }
            val suffixes = resources.openRawResource(R.raw.public_suffix_list)
                .bufferedReader().use { PublicSuffixList(it.readLines().asSequence()) }
            return RpIdValidator(allowlist, suffixes)
        }

        /**
         * A relying party may only scope credentials to a domain someone can
         * register. Without this a page under a public suffix could claim the
         * suffix itself and share the credential with every sibling site.
         */
        fun requireRegistrableDomain(rpId: String, publicSuffixes: PublicSuffixList) {
            require(rpId.isNotEmpty() && !publicSuffixes.isPublicSuffix(rpId)) {
                "`$rpId` is a public suffix, not a registrable domain"
            }
        }

        fun requireOriginMatchesRpId(
            origin: String,
            rpId: String,
            publicSuffixes: PublicSuffixList,
        ) {
            requireRegistrableDomain(rpId, publicSuffixes)
            val uri = URI(origin)
            val host = uri.host?.lowercase()
            // The RP ID is compared case-insensitively: a relying party that
            // sends `Example.com` means the same host as `example.com`.
            val target = rpId.lowercase()
            require(uri.scheme == "https" &&
                uri.rawPath.orEmpty() in setOf("", "/") &&
                uri.rawQuery == null &&
                uri.rawFragment == null &&
                uri.userInfo == null &&
                host != null &&
                (host == target || host.endsWith(".$target"))
            ) { "Browser origin is not authorized for this relying party" }
        }

        fun validateAssetLinks(json: String, packageName: String, fingerprints: List<String>): Boolean =
            runCatching {
                val statements = JSONArray(json)
                (0 until statements.length()).any { index ->
                    val statement = statements.optJSONObject(index) ?: return@any false
                    val relations = statement.optJSONArray("relation") ?: return@any false
                    val hasRelation = (0 until relations.length()).any { relations.optString(it) == RELATION }
                    val target = statement.optJSONObject("target") ?: return@any false
                    val certs = target.optJSONArray("sha256_cert_fingerprints") ?: return@any false
                    val authorized = (0 until certs.length()).map { certs.getString(it).uppercase() }.toSet()
                    hasRelation &&
                        target.optString("namespace") == "android_app" &&
                        target.optString("package_name") == packageName &&
                        fingerprints.all { it.uppercase() in authorized }
                }
            }.getOrDefault(false)

        private fun fingerprint(bytes: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(bytes)
                .joinToString(":") { "%02X".format(it) }

        private fun fetchAssetLinks(rpId: String): String {
            val connection = URL("https://$rpId/.well-known/assetlinks.json").openConnection() as HttpsURLConnection
            connection.connectTimeout = 3000
            connection.readTimeout = 3000
            connection.instanceFollowRedirects = false
            connection.setRequestProperty("Accept", "application/json")
            try {
                if (connection.responseCode != HttpsURLConnection.HTTP_OK) {
                    throw IOException("assetlinks.json returned HTTP ${connection.responseCode}")
                }
                val bytes = connection.inputStream.use { input ->
                    val output = java.io.ByteArrayOutputStream()
                    val buffer = ByteArray(8192)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        if (output.size() + count > 256 * 1024) {
                            throw IOException("assetlinks.json is too large")
                        }
                        output.write(buffer, 0, count)
                    }
                    output.toByteArray()
                }
                return bytes.toString(Charsets.UTF_8)
            } finally {
                connection.disconnect()
            }
        }
    }
}
