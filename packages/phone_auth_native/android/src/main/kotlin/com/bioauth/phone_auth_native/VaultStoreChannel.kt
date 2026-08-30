package com.bioauth.phone_auth_native

import android.app.Activity
import android.os.Build
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import java.util.concurrent.atomic.AtomicBoolean

internal class VaultStoreChannel(
    private val biometricManager: BiometricManager,
    private val keyStore: VaultKeyStore,
    private val storage: VaultFileStorage,
    private val nowMs: () -> Long = System::currentTimeMillis,
) : MethodChannel.MethodCallHandler {
    private var activity: Activity? = null
    private var prompt: BiometricPrompt? = null
    private var pendingResult: MethodChannel.Result? = null
    private var pendingCleanup: (() -> Unit)? = null

    fun attach(activity: Activity) {
        this.activity = activity
    }

    fun detach() {
        activity = null
        prompt?.cancelAuthentication()
        cleanPending()
        fail(VaultStoreFailure("activity_unavailable", "Biometric activity detached"))
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        if (pendingResult != null) {
            result.error("operation_in_progress", "Another vault operation is in progress", null)
            return
        }
        val request = runCatching { request(call) }.getOrElse {
            respondError(result, failureFor(it))
            return
        }
        if (!operationInProgress.compareAndSet(false, true)) {
            result.error("operation_in_progress", "Another vault operation is in progress", null)
            return
        }
        pendingResult = result
        runCatching { load(request) }.onFailure { fail(failureFor(it)) }
    }

    private fun load(request: Request) {
        // Discarding needs neither the key nor the blob to be readable — that
        // is the whole point of it. A vault whose key a new fingerprint
        // invalidated, or whose file is corrupt, cannot be unlocked by anyone
        // ever again, so requiring an unlock here would leave the user with a
        // permanently bricked vault and no button.
        //
        // No biometric prompt either, for the same reason: there is nothing to
        // authorise against. The confirmation is on the screen instead, which
        // is why this is the one operation whose safety lives in the UI.
        if (request is Request.Discard) {
            storage.delete()
            runCatching { keyStore.deleteKey() }
            succeed(mapOf("discarded" to true))
            return
        }
        if (!storage.exists()) {
            when (request) {
                is Request.List -> succeed(VaultStoreData.page(emptyList(), request.cursor))
                is Request.ListAll -> succeed(VaultStoreData.all(emptyList()))
                is Request.Create -> write(emptyList(), request)
                // A vault with no file is an empty vault, not a broken one.
                // Exporting it yields nothing and restoring into it is the
                // new-phone case this exists for, so neither is an error.
                is Request.Export -> succeed(mapOf("items" to emptyList<Any>()))
                is Request.Restore -> restore(emptyList(), request)
                else -> fail(VaultStoreFailure("not_found", "Vault item does not exist"))
            }
            return
        }
        requireCryptoReady()
        val blob = storage.read()
        authenticate(keyStore.decryptCipher(blob)) { cipher ->
            val items = VaultStoreCodec.decode(VaultCiphertext.open(cipher, blob))
            process(request, items)
        }
    }

    private fun process(request: Request, items: List<VaultItem>) {
        when (request) {
            is Request.List -> succeed(VaultStoreData.page(items, request.cursor))
            is Request.ListAll -> succeed(VaultStoreData.all(items))
            is Request.Fetch -> {
                val item = VaultStoreData.fetch(items, request.id)
                succeed(mapOf("id" to item.id, "revision" to item.revision, "secret" to item.secret))
            }
            // Answered in `load`, before anything is decrypted — that is the
            // point of it. Reaching here would mean discarding had waited on
            // an unlock that a discardable vault cannot provide.
            is Request.Discard -> fail(
                VaultStoreFailure("vault_operation_failed", "Discard is handled before unlocking"),
            )
            is Request.Export -> succeed(mapOf("items" to VaultStoreData.export(items)))
            is Request.Restore -> restore(items, request)
            is Request.Create -> write(items, request)
            is Request.Update -> write(items, request)
            is Request.Delete -> {
                val updated = VaultStoreData.delete(items, request.id, request.expectedRevision)
                if (updated.isEmpty()) {
                    storage.delete()
                    succeed(mapOf("id" to request.id) + VaultStoreData.all(emptyList()))
                } else {
                    persist(updated, mapOf("id" to request.id))
                }
            }
        }
    }

    private fun restore(items: List<VaultItem>, request: Request.Restore) {
        val (updated, added, skipped) = VaultStoreData.restore(items, request.items, nowMs())
        // Nothing new means nothing to write. Re-sealing the same items would
        // cost a second biometric prompt to change nothing.
        if (added == 0) {
            succeed(mapOf("added" to 0, "skipped" to skipped) + VaultStoreData.all(items))
            return
        }
        persist(updated, mapOf("added" to added, "skipped" to skipped))
    }

    private fun write(items: List<VaultItem>, request: Request.Create) {
        val (updated, item) = VaultStoreData.create(items, request.item, nowMs())
        persist(updated, mapOf("id" to item.id, "revision" to item.revision))
    }

    private fun write(items: List<VaultItem>, request: Request.Update) {
        val (updated, item) = VaultStoreData.update(items, request.item, request.expectedRevision, nowMs())
        persist(updated, mapOf("id" to item.id, "revision" to item.revision))
    }

    /// Seals [items] and answers with [response] plus the vault it just wrote.
    ///
    /// The listing rides along because the caller needs it and this side
    /// already has it. The key is auth-per-use, so a caller that asks for the
    /// list afterwards pays a whole extra biometric prompt -- a third one, on
    /// top of the decrypt and the encrypt a write already costs -- to be told
    /// something that was in hand here.
    private fun persist(items: List<VaultItem>, response: Map<String, Any>) {
        val answer = response + VaultStoreData.all(items)
        val plaintext = VaultStoreCodec.encode(items)
        try {
            requireCryptoReady()
            authenticate(keyStore.encryptCipher(), cleanup = { plaintext.fill(0) }) { cipher ->
                storage.write(VaultCiphertext.seal(cipher, plaintext))
                succeed(answer)
            }
        } catch (error: Throwable) {
            plaintext.fill(0)
            throw error
        }
    }

    private fun requireCryptoReady() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            throw VaultStoreFailure("unsupported_android", "Vault storage requires Android 11 or newer")
        }
        if (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) !=
            BiometricManager.BIOMETRIC_SUCCESS
        ) {
            throw VaultStoreFailure("biometric_unavailable", "Strong biometric enrollment is required")
        }
        keyStore.ensureKey()
    }

    private fun authenticate(
        cipher: Cipher,
        cleanup: (() -> Unit)? = null,
        operation: (Cipher) -> Unit,
    ) {
        val fragmentActivity = activity as? FragmentActivity
            ?: throw VaultStoreFailure("activity_unavailable", "A FragmentActivity is required for biometric authentication")
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                prompt = null
                val afterOperation = pendingCleanup
                pendingCleanup = null
                val authenticated = result.cryptoObject?.cipher
                if (authenticated == null) {
                    afterOperation?.invoke()
                    fail(VaultStoreFailure("crypto_unavailable", "Authenticated vault cipher is unavailable"))
                    return
                }
                try {
                    operation(authenticated)
                } catch (error: Throwable) {
                    fail(failureFor(error))
                } finally {
                    afterOperation?.invoke()
                }
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                cleanPending()
                val cancelled = errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
                    errorCode == BiometricPrompt.ERROR_USER_CANCELED
                fail(
                    VaultStoreFailure(
                        if (cancelled) "authentication_cancelled" else "authentication_failed",
                        "Biometric authentication did not complete",
                    ),
                )
            }
        }
        pendingCleanup = cleanup
        prompt = BiometricPrompt(fragmentActivity, callback).also {
            it.authenticate(
                BiometricPrompt.PromptInfo.Builder()
                    // In the app's language. This dialog is drawn by the
                    // system over a screen that is entirely in Portuguese, and
                    // a prompt the user cannot read is a prompt they answer by
                    // guessing which button dismisses it.
                    .setTitle("Desbloquear o cofre BioAuth")
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .setNegativeButtonText("Cancelar")
                    .build(),
                BiometricPrompt.CryptoObject(cipher),
            )
        }
    }

    private fun request(call: MethodCall): Request {
        val arguments = call.arguments as? Map<*, *> ?: emptyMap<Any, Any>()
        return when (call.method) {
            "list" -> Request.List(arguments.optionalStringOrNull("cursor"))
            "listAll" -> Request.ListAll
            "fetch" -> Request.Fetch(arguments.requiredString("id"))
            "create" -> Request.Create(VaultItemInput.from(arguments["item"], requireId = false))
            "update" -> Request.Update(
                VaultItemInput.from(arguments["item"], requireId = true),
                arguments.requiredRevision("expectedRevision"),
            )
            "delete" -> Request.Delete(
                arguments.requiredString("id"),
                arguments.requiredRevision("expectedRevision"),
            )
            "discard" -> Request.Discard
            "export" -> Request.Export
            "restore" -> Request.Restore(
                (arguments["items"] as? List<*> ?: throw VaultStoreFailure(
                    "invalid_arguments",
                    "items is required",
                )).also {
                    if (it.size > VaultStoreData.MAX_ITEMS) {
                        throw VaultStoreFailure("invalid_arguments", "too many items to restore")
                    }
                }.map { VaultItemInput.from(it, requireId = false) },
            )
            else -> throw VaultStoreFailure("not_implemented", "Unknown vault method")
        }
    }

    private fun succeed(value: Any?) {
        val result = pendingResult ?: return
        pendingResult = null
        prompt = null
        operationInProgress.set(false)
        result.success(value)
    }

    private fun fail(failure: VaultStoreFailure) {
        val result = pendingResult ?: return
        pendingResult = null
        prompt = null
        cleanPending()
        operationInProgress.set(false)
        respondError(result, failure)
    }

    private fun cleanPending() {
        pendingCleanup?.invoke()
        pendingCleanup = null
    }

    private fun respondError(result: MethodChannel.Result, failure: VaultStoreFailure) {
        if (failure.code == "not_implemented") result.notImplemented()
        else result.error(failure.code, failure.message, failure.details)
    }

    private fun failureFor(error: Throwable): VaultStoreFailure = when (error) {
        is VaultStoreFailure -> error
        is KeyPermanentlyInvalidatedException -> VaultStoreFailure(
            "key_invalidated",
            "Vault key was invalidated by biometric enrollment",
        )
        is UserNotAuthenticatedException -> VaultStoreFailure(
            "authentication_required",
            "Strong biometric authentication is required",
        )
        is AEADBadTagException -> VaultStoreFailure("store_corrupt", "Vault storage authentication failed")
        else -> VaultStoreFailure("vault_operation_failed", "Vault operation failed")
    }

    private sealed interface Request {
        data class List(val cursor: String?) : Request

        /**
         * Every item's metadata, for one unlock.
         *
         * Paging is what the desktop needs, because a frame has a size cap.
         * The phone's own screen has no such cap and does need every item, and
         * asking for them a page at a time cost one biometric prompt per page.
         */
        data object ListAll : Request
        data class Fetch(val id: String) : Request
        data class Create(val item: VaultItemInput) : Request
        data class Update(val item: VaultItemInput, val expectedRevision: Int) : Request
        data class Delete(val id: String, val expectedRevision: Int) : Request

        /** Every item, secrets included, for one encrypted backup file. */
        data object Export : Request

        /**
         * Throws the vault away: the file and the key.
         *
         * The way out of a vault nothing can open — a key a new biometric
         * enrolment invalidated, a file that fails its tag. Both are permanent,
         * so the alternative to this is an app with a tab that only ever shows
         * an error.
         *
         * Destroys data by design, and is the only operation here that does so
         * without an unlock, because an unlock is exactly what is unavailable.
         */
        data object Discard : Request

        /** Items read back out of a backup file, to be added to this vault. */
        data class Restore(val items: kotlin.collections.List<VaultItemInput>) : Request
    }

    companion object {
        private val operationInProgress = AtomicBoolean(false)
    }
}

private fun Map<*, *>.requiredString(key: String): String {
    val value = this[key] as? String ?: throw VaultStoreFailure("invalid_arguments", "$key is required")
    if (value.isEmpty() || value.length > 64) throw VaultStoreFailure("invalid_arguments", "$key is invalid")
    return value
}

private fun Map<*, *>.optionalStringOrNull(key: String): String? {
    val raw = this[key] ?: return null
    val value = raw as? String ?: throw VaultStoreFailure("invalid_arguments", "$key must be a string")
    if (value.length > 128) throw VaultStoreFailure("invalid_arguments", "$key is invalid")
    return value
}

private fun Map<*, *>.requiredRevision(key: String): Int {
    val value = this[key] as? Number ?: throw VaultStoreFailure("invalid_arguments", "$key is required")
    val long = value.exactLongOrNull()
    if (long == null || long !in 1..Int.MAX_VALUE) {
        throw VaultStoreFailure("invalid_arguments", "$key must be at least 1")
    }
    return long.toInt()
}

private fun Number.exactLongOrNull(): Long? = when (this) {
    is Byte, is Short, is Int, is Long -> toLong()
    else -> toString().toLongOrNull()
}
