package com.bioauth.phone_auth_native

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
    private val fetcher: AssetLinksFetcher = AssetLinksFetcher(::fetchAssetLinks),
) {
    @RequiresApi(28)
    fun validate(rpId: String, caller: CallingAppInfo): WebAuthnClientData {
        if (caller.isOriginPopulated()) {
            val origin = caller.getOrigin(privilegedAllowlist)
                ?: throw SecurityException("Privileged browser origin is unavailable")
            requireOriginMatchesRpId(origin, rpId)
            return WebAuthnClientData(origin = origin, packageName = null)
        }

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

        fun requireOriginMatchesRpId(origin: String, rpId: String) {
            val uri = URI(origin)
            val host = uri.host?.lowercase()
            require(uri.scheme == "https" &&
                uri.rawPath.orEmpty() in setOf("", "/") &&
                uri.rawQuery == null &&
                uri.rawFragment == null &&
                uri.userInfo == null &&
                host != null &&
                (host == rpId || host.endsWith(".$rpId"))
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
