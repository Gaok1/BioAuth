package com.bioauth.phone_auth_native

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * The key that wraps File Locker data keys.
 *
 * It is an AES-256-GCM key of its own, never the authorization key and never
 * the vault or WebAuthn key: `bioauth_authorization_v1` signs, and a signature
 * is not a key. It requires a strong biometric for every single use, so a
 * device left unlocked on a table does not unlock a stack of files, and it is
 * invalidated when biometrics are re-enrolled.
 *
 * The desktop stores what this produces and cannot read it. Nothing here logs
 * a key, a blob, or a container binding.
 */
internal class LockerKeyStore(
    private val context: Context,
) {
    private val keyStore: KeyStore
        get() = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    fun keyExists(): Boolean = keyStore.containsAlias(KEY_ALIAS)

    /** Creates the key if it is missing. Trying StrongBox first, as elsewhere. */
    fun ensureKey() {
        if (keyExists()) return
        val strongBoxAvailable =
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        if (strongBoxAvailable) {
            try {
                createKey(useStrongBox = true)
                return
            } catch (_: StrongBoxUnavailableException) {
                keyStore.deleteEntry(KEY_ALIAS)
            }
        }
        createKey(useStrongBox = false)
    }

    /** Removes the key, and with it every container only this phone could open. */
    fun deleteKey() {
        keyStore.deleteEntry(KEY_ALIAS)
    }

    /**
     * A cipher ready to wrap, to be handed to `BiometricPrompt` first.
     *
     * `init` is what triggers the per-use authentication requirement, so this
     * must happen before the prompt and the `doFinal` must happen after it.
     */
    fun wrapCipher(): Cipher =
        Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, secretKey()) }

    /** A cipher ready to unwrap the blob, whose IV it reads. */
    fun unwrapCipher(blob: ByteArray): Cipher {
        val iv = ivOf(blob)
        return Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(TAG_BITS, iv))
        }
    }

    /**
     * Wraps a data key with the authenticated cipher.
     *
     * The blob is `[version][ivLength][iv][ciphertext||tag]`. Its shape is this
     * file's business: to the desktop it is opaque bytes it stores and hands
     * back, which is why the container format says nothing about it.
     */
    fun wrap(cipher: Cipher, binding: ByteArray, credentialId: String, dataKey: ByteArray): ByteArray {
        require(dataKey.size == DATA_KEY_BYTES) { "A locker data key is 32 bytes" }
        cipher.updateAAD(wrapperAad(binding, credentialId))
        val ciphertext = cipher.doFinal(dataKey)
        val iv = cipher.iv
        require(iv.size <= MAX_IV_BYTES) { "Unexpected GCM IV length" }
        return ByteArray(2 + iv.size + ciphertext.size).also { blob ->
            blob[0] = BLOB_VERSION
            blob[1] = iv.size.toByte()
            iv.copyInto(blob, 2)
            ciphertext.copyInto(blob, 2 + iv.size)
        }
    }

    /** Unwraps a data key. A wrong binding or credential fails the GCM tag. */
    fun unwrap(cipher: Cipher, binding: ByteArray, credentialId: String, blob: ByteArray): ByteArray {
        cipher.updateAAD(wrapperAad(binding, credentialId))
        val ivLength = ivOf(blob).size
        val dataKey = cipher.doFinal(blob, 2 + ivLength, blob.size - 2 - ivLength)
        require(dataKey.size == DATA_KEY_BYTES) { "A locker data key is 32 bytes" }
        return dataKey
    }

    fun keySecurity(): Security {
        val key = runCatching { keyStore.getKey(KEY_ALIAS, null) as? SecretKey }.getOrNull()
            ?: return Security(keyExists = false, hardwareBacked = false, strongBoxBacked = false)
        val keyInfo = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
            .getKeySpec(key, KeyInfo::class.java) as KeyInfo
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
        return Security(keyExists = true, hardwareBacked = hardwareBacked, strongBoxBacked = strongBoxBacked)
    }

    private fun secretKey(): SecretKey =
        keyStore.getKey(KEY_ALIAS, null) as? SecretKey
            ?: throw IllegalStateException("File locker key does not exist")

    private fun ivOf(blob: ByteArray): ByteArray {
        require(blob.size > 2) { "Malformed locker wrapper" }
        require(blob[0] == BLOB_VERSION) { "Unsupported locker wrapper version" }
        val ivLength = blob[1].toInt() and 0xff
        require(ivLength in 1..MAX_IV_BYTES && blob.size > 2 + ivLength + TAG_BITS / 8) {
            "Malformed locker wrapper"
        }
        return blob.copyOfRange(2, 2 + ivLength)
    }

    private fun createKey(useStrongBox: Boolean) {
        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(KEY_BITS)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // Zero seconds means per-use: no grace period, and no falling back
            // to the device credential.
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }
        if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }

        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            .apply { init(builder.build()) }
            .generateKey()
    }

    data class Security(
        val keyExists: Boolean,
        val hardwareBacked: Boolean,
        val strongBoxBacked: Boolean,
    )

    companion object {
        /**
         * The additional data a locker wrapper is bound to, mirroring
         * `phone_auth_locker::wrapper_aad`.
         *
         * Computed here from the binding the desktop sent and the credential id
         * this phone holds, so an edited wrapper id in a container produces a
         * different value and the tag fails.
         */
        fun wrapperAad(binding: ByteArray, credentialId: String): ByteArray {
            require(binding.size == BINDING_BYTES) { "A container binding is 32 bytes" }
            return MessageDigest.getInstance("SHA-256").run {
                update(WRAPPER_DOMAIN)
                update(binding)
                update(byteArrayOf(WRAPPER_KIND_PHONE))
                update(credentialId.toByteArray(Charsets.UTF_8))
                digest()
            }
        }

        const val DATA_KEY_BYTES = 32
        const val BINDING_BYTES = 32

        /** Alias for the locker's own key. Never reused by another purpose. */
        const val KEY_ALIAS = "bioauth_file_locker_v1"

        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val KEY_BITS = 256
        private const val TAG_BITS = 128
        private const val MAX_IV_BYTES = 16
        private const val BLOB_VERSION: Byte = 1
        private const val WRAPPER_KIND_PHONE: Byte = 0
        private val WRAPPER_DOMAIN = "bioauth-locker-wrapper-v1".toByteArray(Charsets.UTF_8)
    }
}
