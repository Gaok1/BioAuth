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
    val reportCredentialProperties: Boolean,
    val returnAuthenticatorData: Boolean,
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
        // Absent or empty is not a refusal. The spec has `create()` substitute
        // the client's defaults -- ES256 and RS256 -- when a relying party
        // states no preference, so an empty list is a party that will take
        // either, which includes the one algorithm this authenticator signs
        // with. Reading it as "nothing is permitted" failed a ceremony that
        // every client is required to honour, and failed it with a message
        // blaming the site for a list it never sent.
        val algorithms = root.optJSONArray("pubKeyCredParams") ?: JSONArray()
        require(
            algorithms.length() == 0 ||
                (0 until algorithms.length()).any { index ->
                    algorithms.optJSONObject(index)?.let {
                        it.optString("type") == "public-key" &&
                            it.optInt("alg", Int.MIN_VALUE) == Ctap2Encoder.ES256
                    } == true
                },
        ) { "ES256 is not permitted by the relying party" }
        val selection = root.optionalObject("authenticatorSelection")
        // Both, because from the browser's side this authenticator is both.
        //
        // A relying party asking for `cross-platform` is asking for something
        // that is not the computer it is running on -- a security key, or a
        // phone reached over a link, which is exactly what the desktop relay
        // is and the entire reason it exists. Refusing that value refused the
        // case this product was built for, and refused it before any key was
        // touched: the ceremony ended with the site reporting that the
        // authenticator would not do it. `platform` stays accepted for the
        // browser on the phone itself, where it is the true answer.
        //
        // Like `attestation` below, this is a preference the party states so
        // the client can choose among authenticators. By the time a request
        // arrives here the choosing is done -- someone picked this phone --
        // and failing the ceremony over the hint is the wrong end to fail at.
        // The vocabulary stays closed: a third value is still malformed.
        selection?.optionalEnum("authenticatorAttachment", ATTACHMENT_VALUES)
        selection?.optionalEnum("residentKey", RESIDENT_KEY_VALUES)
        selection?.optionalEnum("userVerification", USER_VERIFICATION_VALUES)
        selection?.optionalBoolean("requireResidentKey")
        // Attestation conveyance is a *preference*, and the spec is explicit that
        // a client may answer a request for `direct` with none attestation and
        // leave the relying party to decide whether that is enough. Refusing the
        // ceremony because the party asked for more than this provider emits was
        // the wrong end to fail at: `direct` is what most real sites ask for, the
        // refusal happened before any key was touched, and what the person saw was
        // the browser reporting that their authenticator would not do it. The
        // vocabulary stays closed -- a value outside the four the spec defines is
        // still a malformed request -- and what comes back is still `fmt: "none"`.
        root.optionalEnum("attestation", ATTESTATION_VALUES)
        // An extension this authenticator does not implement is ignored, not
        // refused -- the same rule `attestation` and `authenticatorAttachment`
        // above are held to, and for the same reason. WebAuthn defines client
        // extensions as inputs a client processes when it can and ignores when
        // it cannot; a relying party is required to cope with an output that
        // never came back. Refusing them ended whole ceremonies over something
        // optional, before any key was touched, so the site reported an
        // authenticator that would not do it.
        //
        // The two that reach real requests are U2F migration hints this
        // authenticator has no part in: `appidExclude` here, which GitHub
        // sends on registration, and `appid` on the assertion side. The
        // desktop extension already strips both, acting as the WebAuthn client
        // it stands in for. Nothing does that in front of Credential Manager,
        // which is why the same sites failed on the phone's own browser and
        // nowhere else.
        //
        // `credProps` is the one this provider answers, so it is still read
        // strictly: present and not a boolean is a malformed request.
        val reportCredentialProperties =
            root.optionalObject("extensions")?.optionalBoolean("credProps") ?: false

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
            reportCredentialProperties = reportCredentialProperties,
            returnAuthenticatorData = root.optionalBoolean("returnAuthenticatorData") ?: false,
        )
    }

    fun request(json: String): WebAuthnRequestOptions {
        require(json.length in 2..65536) { "Invalid WebAuthn assertion request" }
        val root = JSONObject(json)
        root.optionalEnum("userVerification", USER_VERIFICATION_VALUES)
        // Still required to be an object, then ignored -- see `creation`.
        //
        // This is the path where refusing them was worst, because it failed
        // silently. `onBeginGetCredentialRequest` parses every option before
        // it looks up a single credential, so one unrecognised extension threw
        // the whole request out and the provider returned an error instead of
        // entries. What that looks like on the phone is not an error: it is
        // PhoneAuth simply not being among the passkeys the picker offers,
        // with nothing on screen to say why. Registration on the same site
        // worked, because registration sends different extensions.
        root.optionalObject("extensions")
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

    private fun JSONObject.optionalObject(name: String): JSONObject? {
        if (!has(name)) return null
        return optJSONObject(name) ?: throw IllegalArgumentException("$name is invalid")
    }

    private fun JSONObject.optionalEnum(name: String, supported: Set<String>): String? {
        if (!has(name)) return null
        val value = optString(name)
        require(value in supported) { "$name is unsupported" }
        return value
    }

    private fun JSONObject.optionalBoolean(name: String): Boolean? {
        if (!has(name)) return null
        require(get(name) is Boolean) { "$name is invalid" }
        return getBoolean(name)
    }

    private const val BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    private val ATTACHMENT_VALUES = setOf("platform", "cross-platform")
    private val ATTESTATION_VALUES = setOf("none", "indirect", "direct", "enterprise")
    private val RESIDENT_KEY_VALUES = setOf("discouraged", "preferred", "required")
    private val USER_VERIFICATION_VALUES = setOf("discouraged", "preferred", "required")
}
