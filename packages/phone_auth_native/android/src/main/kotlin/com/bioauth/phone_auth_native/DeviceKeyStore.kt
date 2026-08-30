package com.bioauth.phone_auth_native

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec

internal class DeviceKeyStore(
    private val context: Context,
) {
    private val keyStore: KeyStore
        get() = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    fun generateKey(purpose: String = AUTHORIZATION): ByteArray {
        val alias = aliasFor(purpose)
        publicKeyOrNull(alias)?.let { return it }

        val strongBoxAvailable =
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        if (strongBoxAvailable) {
            try {
                return createKey(alias, useStrongBox = true)
            } catch (_: StrongBoxUnavailableException) {
                keyStore.deleteEntry(alias)
            }
        }
        return createKey(alias, useStrongBox = false)
    }

    fun publicKey(purpose: String = AUTHORIZATION): ByteArray =
        publicKeyOrNull(aliasFor(purpose))
            ?: throw IllegalStateException("Signing key does not exist")

    fun initializedSignature(purpose: String = AUTHORIZATION): Signature {
        val privateKey = keyStore.getKey(aliasFor(purpose), null) as? PrivateKey
            ?: throw IllegalStateException("Signing key does not exist")
        return Signature.getInstance(SIGNATURE_ALGORITHM).apply { initSign(privateKey) }
    }

    // One alias per purpose. Sharing a key across purposes would mean a
    // signature made to approve a `sudo` is a signature an SSH server or a
    // vault-holding desktop would also accept, which is the whole reason the
    // purposes exist. An unknown name throws rather than falling back to the
    // authorization key: a typo must not quietly become key reuse.
    private fun aliasFor(purpose: String): String {
        require(purpose in KNOWN_PURPOSES) { "unknown credential purpose" }
        return if (purpose == AUTHORIZATION) KEY_ALIAS else "bioauth_${purpose}_v1"
    }

    fun generateSessionIdentityKey(): ByteArray {
        sessionIdentityPublicKeyOrNull()?.let { return it }
        return createSessionIdentityKey()
    }

    fun sessionIdentityPublicKey(): ByteArray =
        sessionIdentityPublicKeyOrNull()
            ?: throw IllegalStateException("Session identity key does not exist")

    fun signSessionIdentity(transcript: ByteArray): ByteArray {
        val privateKey = keyStore.getKey(SESSION_IDENTITY_ALIAS, null) as? PrivateKey
            ?: throw IllegalStateException("Session identity key does not exist")
        return Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initSign(privateKey)
            update(transcript)
            sign()
        }
    }

    fun verifySessionIdentity(
        publicKey: ByteArray,
        transcript: ByteArray,
        signatureBytes: ByteArray,
    ): Boolean {
        val key = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC)
            .generatePublic(X509EncodedKeySpec(publicKey))
        return Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initVerify(key)
            update(transcript)
            verify(signatureBytes)
        }
    }

    /**
     * How well protected the key for [purpose] is.
     *
     * Takes the purpose for the same reason every other method here does: there
     * is one key per purpose, and this used to read the authorization alias no
     * matter which key was being asked about. A pairing therefore enrolled one
     * key and described a different one -- and a phone that never paired for
     * login has no authorization key at all, so a Keystore-backed passkey
     * credential was enrolled as `Software`. The other direction is the one
     * that matters: StrongBox is attempted per key and falls back per key, so
     * an authorization key that got StrongBox would have vouched for a purpose
     * key that did not. This value exists to withhold authority, never to grant
     * more of it, and vouching for the wrong key can only do the second.
     */
    fun keySecurity(purpose: String = AUTHORIZATION): KeySecurity {
        val privateKey = keyStore.getKey(aliasFor(purpose), null) as? PrivateKey
            ?: return KeySecurity(keyExists = false, hardwareBacked = false, strongBoxBacked = false)
        val keyInfo = KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEYSTORE)
            .getKeySpec(privateKey, KeyInfo::class.java)
        val strongBoxBacked =
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
                keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
        val hardwareBacked = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
        } else {
            @Suppress("DEPRECATION")
            keyInfo.isInsideSecureHardware
        }
        return KeySecurity(
            keyExists = true,
            hardwareBacked = hardwareBacked,
            strongBoxBacked = strongBoxBacked,
        )
    }

    private fun publicKeyOrNull(alias: String = KEY_ALIAS): ByteArray? =
        keyStore.getCertificate(alias)?.publicKey?.encoded

    private fun sessionIdentityPublicKeyOrNull(): ByteArray? =
        keyStore.getCertificate(SESSION_IDENTITY_ALIAS)?.publicKey?.encoded

    private fun createSessionIdentityKey(): ByteArray {
        val pair = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
            .apply {
                initialize(
                    KeyGenParameterSpec.Builder(
                        SESSION_IDENTITY_ALIAS,
                        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                    ).setAlgorithmParameterSpec(ECGenParameterSpec(EC_CURVE))
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setUserAuthenticationRequired(false)
                        .build(),
                )
            }.generateKeyPair()
        return pair.public.encoded
    }

    private fun createKey(alias: String, useStrongBox: Boolean): ByteArray {
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        ).setAlgorithmParameterSpec(ECGenParameterSpec(EC_CURVE))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }
        if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }

        val pair = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
            .apply { initialize(builder.build()) }
            .generateKeyPair()
        return pair.public.encoded
    }

    data class KeySecurity(
        val keyExists: Boolean,
        val hardwareBacked: Boolean,
        val strongBoxBacked: Boolean,
    )

    companion object {
        const val PUBLIC_KEY_ALGORITHM = "EC_P256_SPKI"
        const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val AUTHORIZATION = "authorization"

        // The names the Dart side sends, which are the wire purposes. Kept as
        // a set so an unrecognised one is a failure rather than a new alias.
        private val KNOWN_PURPOSES = setOf(
            AUTHORIZATION,
            "diskUnlock",
            "webAuthn",
            "vault",
            "fileLocker",
            "ssh",
        )

        // Unchanged for authorization: a phone that paired before purposes had
        // their own keys must keep answering with the key it enrolled.
        private const val KEY_ALIAS = "bioauth_authorization_v1"
        private const val SESSION_IDENTITY_ALIAS = "bioauth_session_identity_v1"
        private const val EC_CURVE = "secp256r1"
    }
}
