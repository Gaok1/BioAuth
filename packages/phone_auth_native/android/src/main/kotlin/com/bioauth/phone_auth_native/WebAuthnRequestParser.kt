package com.bioauth.phone_auth_native

import org.json.JSONArray
import org.json.JSONObject

internal data class WebAuthnCreationOptions(
    val rpId: String,
    val rpName: String,
    val userHandle: ByteArray,
    val userName: String,
    val userDisplayName: String,
    val challenge: ByteArray,
    val excludedCredentialIds: List<ByteArray>,
)

internal data class WebAuthnRequestOptions(
    val rpId: String,
    val challenge: ByteArray,
    val allowedCredentialIds: List<ByteArray>,
)

internal object WebAuthnRequestParser {
    fun creation(json: String): WebAuthnCreationOptions {
        require(json.length in 2..65536) { "Invalid WebAuthn creation request" }
        val root = JSONObject(json)
        val rp = root.requiredObject("rp")
        val user = root.requiredObject("user")
        val rpId = validRpId(rp.requiredString("id"))
        val userHandle = decode(user.requiredString("id"), "user.id")
        require(userHandle.size in 1..64) { "user.id must contain 1..64 bytes" }
        val challenge = challenge(root.requiredString("challenge"))
        val algorithms = root.optJSONArray("pubKeyCredParams") ?: JSONArray()
        require((0 until algorithms.length()).any { index ->
            algorithms.optJSONObject(index)?.let {
                it.optString("type") == "public-key" && it.optInt("alg", Int.MIN_VALUE) == Ctap2Encoder.ES256
            } == true
        }) { "ES256 is not permitted by the relying party" }

        return WebAuthnCreationOptions(
            rpId = rpId,
            rpName = bounded(rp.optString("name", rpId), "rp.name", 128),
            userHandle = userHandle,
            userName = bounded(user.requiredString("name"), "user.name", 128),
            userDisplayName = bounded(
                user.optString("displayName", user.requiredString("name")),
                "user.displayName",
                128,
            ),
            challenge = challenge,
            excludedCredentialIds = credentialIds(root.optJSONArray("excludeCredentials")),
        )
    }

    fun request(json: String): WebAuthnRequestOptions {
        require(json.length in 2..65536) { "Invalid WebAuthn assertion request" }
        val root = JSONObject(json)
        return WebAuthnRequestOptions(
            rpId = validRpId(root.requiredString("rpId")),
            challenge = challenge(root.requiredString("challenge")),
            allowedCredentialIds = credentialIds(root.optJSONArray("allowCredentials")),
        )
    }

    fun base64Url(value: ByteArray): String =
        buildString((value.size * 4 + 2) / 3) {
            var accumulator = 0
            var bits = 0
            value.forEach { byte ->
                accumulator = (accumulator shl 8) or (byte.toInt() and 0xff)
                bits += 8
                while (bits >= 6) {
                    bits -= 6
                    append(BASE64URL[(accumulator shr bits) and 0x3f])
                }
            }
            if (bits > 0) append(BASE64URL[(accumulator shl (6 - bits)) and 0x3f])
        }

    fun decode(value: String, field: String): ByteArray {
        require(value.isNotEmpty() && value.length <= 4096) { "$field is invalid" }
        require(value.length % 4 != 1 && value.all { it in BASE64URL }) {
            "$field is not base64url"
        }
        val output = ByteArray(value.length * 6 / 8)
        var accumulator = 0
        var bits = 0
        var offset = 0
        value.forEach { character ->
            accumulator = (accumulator shl 6) or BASE64URL.indexOf(character)
            bits += 6
            if (bits >= 8) {
                bits -= 8
                output[offset++] = (accumulator shr bits).toByte()
            }
        }
        require(bits == 0 || (accumulator and ((1 shl bits) - 1)) == 0) {
            "$field is not canonical base64url"
        }
        return output
    }

    private fun challenge(encoded: String): ByteArray =
        decode(encoded, "challenge").also { require(it.size in 16..1024) { "challenge must contain 16..1024 bytes" } }

    private fun credentialIds(array: JSONArray?): List<ByteArray> {
        if (array == null) return emptyList()
        require(array.length() <= 64) { "Too many credential descriptors" }
        return (0 until array.length()).map { index ->
            val descriptor = array.optJSONObject(index)
                ?: throw IllegalArgumentException("credential descriptor is invalid")
            require(descriptor.optString("type") == "public-key") {
                "credential descriptor type is invalid"
            }
            decode(descriptor.requiredString("id"), "credential.id").also {
                require(it.size in 1..1024) { "credential.id is invalid" }
            }
        }
    }

    private fun validRpId(value: String): String {
        val rpId = value.lowercase()
        val labels = rpId.split('.')
        require(rpId.length in 1..253 &&
            rpId == value &&
            rpId.all { it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '.' } &&
            labels.all { it.isNotEmpty() && it.length <= 63 && !it.startsWith('-') && !it.endsWith('-') }
        ) { "rpId is invalid" }
        return rpId
    }

    private fun bounded(value: String, field: String, max: Int): String =
        value.trim().also { require(it.isNotEmpty() && it.length <= max) { "$field is invalid" } }

    private fun JSONObject.requiredObject(name: String): JSONObject =
        optJSONObject(name) ?: throw IllegalArgumentException("$name is required")

    private fun JSONObject.requiredString(name: String): String =
        optString(name).takeIf { it.isNotEmpty() } ?: throw IllegalArgumentException("$name is required")

    private const val BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
}
