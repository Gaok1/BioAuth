package com.bioauth.phone_auth_native

import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom
import java.security.Signature

internal data class WebAuthnClientData(
    val origin: String,
    val packageName: String?,
    val suppliedHash: ByteArray? = null,
)

internal data class PreparedWebAuthnAssertion(
    val credential: PasskeyRecord,
    val clientDataJson: ByteArray?,
    val authenticatorData: ByteArray,
    val signature: Signature,
    val dataToSign: ByteArray,
    val previousSignCount: UInt,
    val nextSignCount: UInt,
)

internal class WebAuthnCore(
    private val store: PasskeyStore,
    private val keyStore: WebAuthnKeyStore,
    private val random: SecureRandom = SecureRandom(),
    private val clock: () -> Long = System::currentTimeMillis,
) {
    fun creationOptions(requestJson: String) = WebAuthnRequestParser.creation(requestJson)
    fun requestOptions(requestJson: String) = WebAuthnRequestParser.request(requestJson)

    fun credentialsFor(request: WebAuthnRequestOptions): List<PasskeyRecord> =
        store.allForRp(request.rpId).filter { credential ->
            request.allowedCredentialIds.isEmpty() ||
                request.allowedCredentialIds.any { it.contentEquals(credential.credentialId) }
        }.filter { runCatching { keyStore.publicKey(it.keyAlias) }.isSuccess }

    fun create(
        options: WebAuthnCreationOptions,
        client: WebAuthnClientData,
    ): String {
        require(options.excludedCredentialIds.none { excluded ->
            store.allForRp(options.rpId).any { it.credentialId.contentEquals(excluded) }
        }) { "A credential excluded by the relying party already exists" }

        val credentialId = ByteArray(32).also(random::nextBytes)
        val alias = WebAuthnKeyStore.ALIAS_PREFIX + Ctap2Encoder.sha256(credentialId).hex()
        val publicKey = keyStore.create(alias)
        val record = PasskeyRecord(
            credentialId = credentialId,
            rpId = options.rpId,
            userHandle = options.userHandle,
            userName = options.userName,
            userDisplayName = options.userDisplayName,
            keyAlias = alias,
            signCount = 0u,
            createdAtMillis = clock(),
        )
        try {
            store.save(record)
        } catch (error: Throwable) {
            keyStore.delete(alias)
            throw error
        }

        val clientData = clientData("webauthn.create", options.challenge, client)
        val authData = Ctap2Encoder.registrationAuthenticatorData(
            options.rpId,
            credentialId,
            publicKey,
        )
        return credentialJson(
            credentialId,
            JSONObject().apply {
                clientData.bytes?.let { put("clientDataJSON", b64(it)) }
                put("attestationObject", b64(Ctap2Encoder.noneAttestationObject(authData)))
                put("transports", JSONArray().put("internal"))
            },
        )
    }

    fun prepareAssertion(
        options: WebAuthnRequestOptions,
        credentialId: ByteArray,
        client: WebAuthnClientData,
    ): PreparedWebAuthnAssertion {
        val credential = store.find(credentialId)
            ?: throw IllegalArgumentException("Passkey not found")
        require(credential.rpId == options.rpId) { "Passkey belongs to another relying party" }
        require(options.allowedCredentialIds.isEmpty() ||
            options.allowedCredentialIds.any { it.contentEquals(credentialId) }
        ) { "Passkey is not allowed by the relying party" }
        val next = credential.signCount + 1u
        require(next != 0u) { "WebAuthn signature counter exhausted" }
        val clientData = clientData("webauthn.get", options.challenge, client)
        val authData = Ctap2Encoder.assertionAuthenticatorData(options.rpId, next)
        val toSign = authData + clientData.hash
        return PreparedWebAuthnAssertion(
            credential,
            clientData.bytes,
            authData,
            keyStore.initializedSignature(credential.keyAlias),
            toSign,
            credential.signCount,
            next,
        )
    }

    fun finishAssertion(prepared: PreparedWebAuthnAssertion): String {
        val signatureBytes = prepared.signature.run {
            update(prepared.dataToSign)
            sign()
        }
        store.updateCounter(
            prepared.credential.credentialId,
            prepared.previousSignCount,
            prepared.nextSignCount,
        )
        return credentialJson(
            prepared.credential.credentialId,
            JSONObject().apply {
                prepared.clientDataJson?.let { put("clientDataJSON", b64(it)) }
                put("authenticatorData", b64(prepared.authenticatorData))
                put("signature", b64(signatureBytes))
                put("userHandle", b64(prepared.credential.userHandle))
            },
        )
    }

    private fun clientData(type: String, challenge: ByteArray, client: WebAuthnClientData): ClientData {
        if (client.suppliedHash != null) {
            require(client.suppliedHash.size == 32) { "clientDataHash must contain 32 bytes" }
            // Privileged browser callers already own clientDataJSON. Credential
            // Manager expects providers to omit it and sign the supplied hash.
            return ClientData(null, client.suppliedHash.copyOf())
        }
        val json = JSONObject().apply {
            put("type", type)
            put("challenge", b64(challenge))
            put("origin", client.origin)
            put("crossOrigin", false)
            client.packageName?.let { put("androidPackageName", it) }
        }.toString().toByteArray(Charsets.UTF_8)
        return ClientData(json, Ctap2Encoder.sha256(json))
    }

    private fun credentialJson(credentialId: ByteArray, response: JSONObject): String =
        JSONObject().apply {
            put("id", b64(credentialId))
            put("rawId", b64(credentialId))
            put("type", "public-key")
            put("authenticatorAttachment", "platform")
            put("response", response)
            put("clientExtensionResults", JSONObject())
        }.toString()

    private fun b64(value: ByteArray) = WebAuthnRequestParser.base64Url(value)
    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }
    private data class ClientData(val bytes: ByteArray?, val hash: ByteArray)
}
