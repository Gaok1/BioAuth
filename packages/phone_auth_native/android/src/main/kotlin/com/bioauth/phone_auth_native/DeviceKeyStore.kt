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

    fun generateKey(): ByteArray {
        publicKeyOrNull()?.let { return it }

        val strongBoxAvailable =
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        if (strongBoxAvailable) {
            try {
                return createKey(useStrongBox = true)
            } catch (_: StrongBoxUnavailableException) {
                keyStore.deleteEntry(KEY_ALIAS)
            }
        }
        return createKey(useStrongBox = false)
    }

    fun publicKey(): ByteArray =
        publicKeyOrNull() ?: throw IllegalStateException("Device signing key does not exist")

    fun initializedSignature(): Signature {
        val privateKey = keyStore.getKey(KEY_ALIAS, null) as? PrivateKey
            ?: throw IllegalStateException("Device signing key does not exist")
        return Signature.getInstance(SIGNATURE_ALGORITHM).apply { initSign(privateKey) }
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

    fun keySecurity(): KeySecurity {
        val privateKey = keyStore.getKey(KEY_ALIAS, null) as? PrivateKey
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

    private fun publicKeyOrNull(): ByteArray? = keyStore.getCertificate(KEY_ALIAS)?.publicKey?.encoded

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

    private fun createKey(useStrongBox: Boolean): ByteArray {
        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
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
        private const val KEY_ALIAS = "bioauth_authorization_v1"
        private const val SESSION_IDENTITY_ALIAS = "bioauth_session_identity_v1"
        private const val EC_CURVE = "secp256r1"
    }
}
