package com.bioauth.phone_auth_native

import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.credentials.GetCredentialResponse
import androidx.credentials.PasswordCredential
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.PendingIntentHandler
import androidx.fragment.app.FragmentActivity
import javax.crypto.Cipher

/**
 * Releases one stored password to whatever asked for it.
 *
 * The provider service offers a single generic entry, because deciding *which*
 * accounts match would mean decrypting the vault — and therefore a biometric —
 * the moment a text field gained focus. Everything specific happens here,
 * after the user has tapped:
 *
 *   unlock → decode → match against the caller → release at most one
 *
 * Matching after the unlock rather than before is what keeps a bare focus
 * event from costing a prompt, and it costs nothing: the caller's identity is
 * in the provider request either way.
 */
@RequiresApi(34)
class VaultCredentialActivity : FragmentActivity() {
    private val keyStore by lazy { VaultKeyStore(this) }
    private val storage by lazy { VaultFileStorage(this) }
    private val validator by lazy { RpIdValidator.fromResources(this) }
    private var prompt: BiometricPrompt? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // A recreated activity has already asked, or was never asked. Starting
        // over would raise a second prompt for a request that is gone -- but
        // returning without finishing left this activity on screen, and it has
        // no content view at all: the vault prompt became a blank rectangle
        // that answers nothing and never goes away, while the app that asked
        // waits for a result that is never set. A configuration change with
        // the prompt up -- a rotation, dark mode, a font-size change -- is the
        // whole reproduction. `fail()` is the same answer every other dead end
        // here gives, and it releases the caller.
        if (savedInstanceState != null) {
            fail()
            return
        }

        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        val caller = request?.callingAppInfo
        if (caller == null || !storage.exists()) {
            fail()
            return
        }

        val cipher = runCatching {
            if (biometricUnavailable()) error("no strong biometric")
            keyStore.ensureKey()
            keyStore.decryptCipher(storage.read())
        }.getOrElse {
            fail()
            return
        }

        authenticate { authenticated -> release(authenticated, caller) }
        // Held so the prompt is not garbage collected before it is answered.
        if (prompt == null) fail()
        else prompt!!.authenticate(promptInfo(), BiometricPrompt.CryptoObject(cipher))
    }

    private fun biometricUnavailable() =
        BiometricManager.from(this)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) !=
            BiometricManager.BIOMETRIC_SUCCESS

    private fun release(cipher: Cipher, caller: CallingAppInfo) {
        val matches = runCatching {
            val items = VaultStoreCodec.decode(VaultCiphertext.open(cipher, storage.read()))
            val origin = validator.originOf(caller)
            val asking = AutofillCaller(
                origin = origin,
                packageName = if (origin == null) caller.packageName else null,
            )
            val candidates = items.map(AutofillCandidate::of)
            VaultAutofillMatcher.matches(candidates, asking) { host ->
                // The passkey path's check, and the relation it uses —
                // `common.get_login_creds` — is literally the one for
                // passwords.
                runCatching { validator.validate(host, caller) }.isSuccess
            }.mapNotNull { candidate -> items.firstOrNull { it.id == candidate.id } }
        }.getOrElse {
            fail()
            return
        }

        when (matches.size) {
            0 -> fail()
            1 -> respond(matches.single())
            // Two accounts on one site is ordinary. Choosing between them is
            // the user's; picking the most recent would silently sign somebody
            // into the wrong one of their own accounts.
            else -> choose(matches)
        }
    }

    private fun choose(matches: List<VaultItem>) {
        AlertDialog.Builder(this)
            .setTitle("Qual conta?")
            .setItems(
                matches.map { item -> item.username.ifEmpty { item.name } }.toTypedArray(),
            ) { _, index -> respond(matches[index]) }
            .setOnCancelListener { fail() }
            .show()
    }

    private fun respond(item: VaultItem) {
        val result = Intent()
        PendingIntentHandler.setGetCredentialResponse(
            result,
            GetCredentialResponse(PasswordCredential(item.username, item.secret)),
        )
        setResult(RESULT_OK, result)
        finish()
    }

    private fun authenticate(onSuccess: (Cipher) -> Unit) {
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                prompt = null
                val authenticated = result.cryptoObject?.cipher
                if (authenticated == null) fail() else onSuccess(authenticated)
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                prompt = null
                fail()
            }
        }
        prompt = BiometricPrompt(this, callback)
    }

    private fun promptInfo() = BiometricPrompt.PromptInfo.Builder()
        // Names the operation rather than the app. The user is being asked to
        // hand a password to whatever raised the field; a title reading
        // "Unlock" would not say that.
        .setTitle("Preencher senha do cofre")
        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        .setNegativeButtonText("Cancelar")
        .build()

    /**
     * Every failure reads the same to the caller.
     *
     * A vault with no match, a note, a refused biometric, an invalidated key
     * and a corrupt file are one outcome on purpose. Distinguishing them would
     * let any app able to raise an autofill prompt learn what the vault holds
     * without ever unlocking it.
     */
    private fun fail() {
        val result = Intent()
        PendingIntentHandler.setGetCredentialException(
            result,
            GetCredentialUnknownException("No vault credential is available"),
        )
        setResult(RESULT_OK, result)
        finish()
    }
}
