package com.bioauth.phone_auth_native

import androidx.biometric.BiometricManager
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import org.mockito.Mockito.mock
import org.mockito.Mockito.`when`

class VaultStoreChannelTest {
    /**
     * The bug this exists for: `load` answered `list` and `listAll` out of the
     * "no file yet" branch, which returns before `requireCryptoReady` and
     * before any prompt. So a fresh install -- and any vault whose contents
     * had been discarded, since discarding deletes the file -- opened with
     * nothing asked.
     *
     * What is pinned here is that both listings reach `requireCryptoReady`.
     * On the JVM `Build.VERSION.SDK_INT` is 0, so that gate throws
     * `unsupported_android` and the channel reports an error; an answer of any
     * kind means the branch returned before the gate, which is the bug.
     */
    @Test
    fun `listing a vault with no file still has to go through the crypto gate`() {
        for (method in listOf("list", "listAll")) {
            val result = RecordingResult()
            channelWithNoVaultFile().onMethodCall(MethodCall(method, emptyMap<String, Any>()), result)

            assertNull(result.value, "`$method` answered without asking for anything")
            assertEquals("unsupported_android", result.code, "for `$method`")
        }
    }

    private fun channelWithNoVaultFile(): VaultStoreChannel {
        val storage = mock(VaultFileStorage::class.java)
        `when`(storage.exists()).thenReturn(false)
        return VaultStoreChannel(
            mock(BiometricManager::class.java),
            mock(VaultKeyStore::class.java),
            storage,
        )
    }

    private class RecordingResult : MethodChannel.Result {
        var value: Any? = null
        var code: String? = null

        override fun success(result: Any?) {
            value = result
        }

        override fun error(errorCode: String, errorMessage: String?, errorDetails: Any?) {
            code = errorCode
        }

        override fun notImplemented() {
            code = "notImplemented"
        }
    }
}
