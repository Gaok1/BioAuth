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
    /**
     * Whether the relying party named the credentials it will accept.
     *
     * Not the same question as whether [allowedCredentialIds] is empty, and
     * that is the point: descriptors this authenticator has to ignore are
     * dropped from that list, so a request naming three credentials of a type
     * we do not support arrives here with nothing in it. An empty list means
     * "any credential", and reading that request as one would widen a ceremony
     * the relying party had scoped.
     */
    val credentialsRestricted: Boolean,
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
            rpName = display(rp.optString("name").ifBlank { rpId }),
            userHandle = userHandle,
            userName = display(user.requiredString("name")),
            userDisplayName = display(
                user.optString("displayName").ifBlank { user.requiredString("name") },
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
            credentialsRestricted =
                (root.optJSONArray("allowCredentials")?.length() ?: 0) > 0,
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
        // Says the limit and the length, not just that something was wrong.
        // A relying party whose field does not fit is a ceremony that fails
        // for a reason nobody can see from the outside, and the one time a
        // bound here turned a real site away it was found in seconds only
        // because the message happened to carry its numbers.
        require(value.isNotEmpty() && value.length <= MAX_ENCODED_CHARS) {
            "$field must be 1..$MAX_ENCODED_CHARS base64url characters, not ${value.length}"
        }
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

    /**
     * The relying party's challenge, bounded only where this side has standing
     * to bound it.
     *
     * The floor was sixteen bytes, and it turned Google's sign-in away. That
     * number comes from the specification's advice **to relying parties** --
     * challenges SHOULD be at least sixteen bytes -- and it is advice about
     * the risk the relying party is taking with its own ceremony. An
     * authenticator enforcing it does not make that party safer; it refuses to
     * sign, and what the person sees is a passkey that does not work on a site
     * where it plainly should. No browser enforces it either.
     *
     * Registration on the same site succeeded throughout, which is what made
     * this so hard to read from the outside: only the assertion challenge was
     * out of range, so the passkey could be created and never used.
     *
     * There is still a ceiling, and it is the one every base64url field here
     * already has: [decode] refuses anything over four thousand characters
     * before it allocates. A second bound on top of it was reachable only by
     * inputs the first had already turned away, so it decided nothing.
     */
    private fun challenge(encoded: String): ByteArray = decode(encoded, "challenge")

    /**
     * The credential ids in a descriptor list, skipping what is not ours to act on.
     *
     * `allowCredentials` and `excludeCredentials` are lists a relying party
     * writes for every authenticator at once, so an entry this one cannot use
     * is an ordinary thing to find there, not a malformed request. WebAuthn
     * says as much: a descriptor whose `type` the client does not recognise is
     * to be ignored. Refusing the whole list instead meant one entry naming a
     * credential type we do not implement -- or a list longer than a bound we
     * invented -- cost the user the login they had a passkey for.
     *
     * Skipping is safe here because a descriptor we drop could never have
     * matched: the ids this authenticator issues are a fixed size, and one that
     * does not decode is not one of them. What it must not do is turn a scoped
     * request into an open one, which is what `credentialsRestricted` is for.
     */
    private fun credentialIds(array: JSONArray?): List<ByteArray> {
        if (array == null) return emptyList()
        val ids = mutableListOf<ByteArray>()
        for (index in 0 until array.length()) {
            // A bound on work rather than on the request: past this many, the
            // list is read no further and the ceremony still happens.
            if (ids.size >= MAX_CREDENTIAL_DESCRIPTORS) break
            val descriptor = array.optJSONObject(index) ?: continue
            if (descriptor.optString("type") != "public-key") continue
            val id = runCatching { decode(descriptor.requiredString("id"), "credential.id") }
                .getOrNull() ?: continue
            if (id.size in 1..1024) ids.add(id)
        }
        return ids
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

    /**
     * A name to put in front of the user, cut to something a phone can show.
     *
     * Truncating rather than refusing, because CTAP2 says an authenticator may
     * do exactly that -- it names 64 bytes as the least it must keep -- and
     * because the alternative was a relying party with a long product name
     * being unable to register a passkey at all. What the user sees is a
     * shortened title; what they saw before was a ceremony that failed.
     */
    private fun display(value: String): String {
        // The untrimmed value when trimming leaves nothing: whitespace is a
        // poor name, and inventing one would be worse.
        val chosen = value.trim().ifEmpty { value }
        if (chosen.length <= MAX_DISPLAY_CHARS) return chosen
        // Never between the halves of a surrogate pair. The cut string is
        // encoded as CBOR text, and half a pair is not UTF-8.
        val end = if (Character.isHighSurrogate(chosen[MAX_DISPLAY_CHARS - 1])) {
            MAX_DISPLAY_CHARS - 1
        } else {
            MAX_DISPLAY_CHARS
        }
        return chosen.substring(0, end)
    }

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


    /** The one ceiling every base64url field here shares. */
    private const val MAX_ENCODED_CHARS = 4096

    /** How many descriptors are read out of one credential list. */
    private const val MAX_CREDENTIAL_DESCRIPTORS = 256

    /** How long a name from the relying party may be before it is cut. */
    private const val MAX_DISPLAY_CHARS = 128

    private const val BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    private val ATTACHMENT_VALUES = setOf("platform", "cross-platform")
    private val ATTESTATION_VALUES = setOf("none", "indirect", "direct", "enterprise")
    private val RESIDENT_KEY_VALUES = setOf("discouraged", "preferred", "required")
    private val USER_VERIFICATION_VALUES = setOf("discouraged", "preferred", "required")
}
