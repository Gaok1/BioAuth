package com.bioauth.phone_auth_native

import android.os.Build
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import androidx.test.platform.app.InstrumentationRegistry
import javax.crypto.SecretKeyFactory
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
@SdkSuppress(minSdkVersion = 35)
class VaultStoreInstrumentationTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val storage = VaultFileStorage(context)
    private val keyStore = VaultKeyStore(context)

    @After
    fun cleanUp() {
        storage.delete()
        keyStore.deleteKey()
    }

    @Test
    fun ciphertextIsStoredAtomicallyInPrivateNoBackupStorage() {
        val bytes = byteArrayOf(1, 2, 3, 4)
        storage.write(bytes)

        assertArrayEquals(bytes, storage.read())
        assertEquals(context.noBackupFilesDir.canonicalFile, storage.pathForTest().parentFile?.canonicalFile)
        assertFalse(storage.pathForTest().path.contains("shared_prefs"))
    }

    @Test
    fun generatedKeyIsAes256GcmStrongBiometricPerUseAndEnrollmentInvalidated() {
        assertTrue(Build.VERSION.SDK_INT >= 35)
        assumeTrue(
            BiometricManager.from(context).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
                BiometricManager.BIOMETRIC_SUCCESS,
        )
        keyStore.ensureKey()

        val key = keyStore.secretKeyForTest()
        val info = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
            .getKeySpec(key, KeyInfo::class.java) as KeyInfo
        assertEquals(256, info.keySize)
        assertArrayEquals(arrayOf(KeyProperties.BLOCK_MODE_GCM), info.blockModes)
        assertArrayEquals(arrayOf(KeyProperties.ENCRYPTION_PADDING_NONE), info.encryptionPaddings)
        assertTrue(info.isUserAuthenticationRequired)
        assertEquals(0, info.userAuthenticationValidityDurationSeconds)
        assertEquals(KeyProperties.AUTH_BIOMETRIC_STRONG, info.userAuthenticationType)
        assertTrue(info.isInvalidatedByBiometricEnrollment)
    }
}
