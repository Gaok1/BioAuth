package com.bioauth.phone_auth_native

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.domerrors.InvalidStateError
import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.PendingIntentHandler
import androidx.fragment.app.FragmentActivity
import java.util.concurrent.Executors

@RequiresApi(34)
class WebAuthnCredentialActivity : FragmentActivity() {
    private val executor = Executors.newSingleThreadExecutor()
    private val core by lazy { WebAuthnCore(PasskeyStore(this), WebAuthnKeyStore(this)) }
    private val validator by lazy { RpIdValidator.fromResources(this) }
    private var prompt: BiometricPrompt? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // A recreated activity has already asked, or was never asked: starting
        // over would raise a second prompt for a request that is gone. But
        // returning here left an activity that never called `finish()` and has
        // no content view of its own on screen -- a blank rectangle over the
        // browser that answers nothing, until Credential Manager gives up on
        // it. Rotating the phone, or toggling dark mode, while the passkey
        // prompt was up was enough to reach it. Cancel out instead, which is
        // what the unknown-action branch below already does.
        if (savedInstanceState != null) {
            finishCanceled()
            return
        }
        when (intent.action) {
            ACTION_CREATE -> beginCreate()
            ACTION_GET -> beginGet()
            else -> finishCanceled()
        }
    }

    private fun beginCreate() {
        val providerRequest = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
        val request = providerRequest?.callingRequest as? CreatePublicKeyCredentialRequest
        val caller = providerRequest?.callingAppInfo
        if (request == null || caller == null) {
            failCreate("Invalid passkey creation request")
            return
        }
        executor.execute {
            runCatching {
                val options = core.creationOptions(request.requestJson)
                val client = validatedClient(options.rpId, caller, request.clientDataHash)
                // Before the prompt, not after. A site that excludes a
                // credential it already has is saying "this device is already
                // registered", and the answer to that costs no fingerprint.
                if (core.isExcluded(options)) {
                    throw ExcludedCredentialException("A credential excluded by the relying party already exists")
                }
                options to client
            }.onSuccess { (options, client) ->
                runOnUiThread {
                    authenticate(
                        title = "Criar passkey",
                        subtitle = options.rpId,
                        description = getString(R.string.passkey_no_backup),
                        crypto = null,
                        onSuccess = { finishCreate(core.create(options, client)) },
                        onFailure = { failCreateWith(it) },
                    )
                }
            }.onFailure { failCreateWith(it) }
        }
    }

    private fun beginGet() {
        val providerRequest = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        val request = providerRequest?.credentialOptions?.firstOrNull() as? GetPublicKeyCredentialOption
        val caller = providerRequest?.callingAppInfo
        val credentialId = intent.getByteArrayExtra(EXTRA_CREDENTIAL_ID)
        if (request == null || caller == null || credentialId == null) {
            failGet("Invalid passkey assertion request")
            return
        }
        executor.execute {
            runCatching {
                val options = core.requestOptions(request.requestJson)
                val client = validatedClient(options.rpId, caller, request.clientDataHash)
                core.prepareAssertion(options, credentialId, client)
            }.onSuccess { prepared ->
                runOnUiThread {
                    authenticate(
                        title = "Usar passkey",
                        subtitle = prepared.credential.rpId,
                        description = null,
                        crypto = BiometricPrompt.CryptoObject(prepared.signature),
                        onSuccess = { result ->
                            val signature = result.cryptoObject?.signature
                            if (signature == null) {
                                failGet("Authenticated signature is unavailable")
                            } else {
                                finishGet(core.finishAssertion(prepared.copy(signature = signature)))
                            }
                        },
                        onFailure = {
                            failGet(
                                if (it == null) "Biometric verification failed"
                                else "The passkey could not be used",
                            )
                        },
                    )
                }
            }.onFailure { failGet("Relying party validation failed") }
        }
    }

    private fun authenticate(
        title: String,
        subtitle: String,
        description: String?,
        crypto: BiometricPrompt.CryptoObject?,
        onSuccess: (BiometricPrompt.AuthenticationResult) -> Unit,
        // Null means the prompt itself failed; anything else is what the work
        // after a successful prompt threw. They used to arrive the same way,
        // so a keystore that would not sign, a store that would not write and
        // a relying party exclusion were all reported as "biometric
        // verification failed" -- blaming the finger that had just worked.
        onFailure: (Throwable?) -> Unit,
    ) {
        // Logged and ignored rather than thrown: `authenticate` returns
        // without a prompt and without a callback once the fragment manager
        // has saved state, and both ways out of this activity are callbacks.
        // It would sit there answering nothing until Credential Manager gave
        // up on it. Reported as work that failed, not as a fingerprint that
        // did -- there was never a prompt to put one on.
        if (supportFragmentManager.isStateSaved) {
            onFailure(IllegalStateException("The screen cannot show a prompt right now"))
            return
        }
        var completed = false
        prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    if (!completed) {
                        completed = true
                        runCatching { onSuccess(result) }.onFailure { onFailure(it) }
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    if (!completed) {
                        completed = true
                        onFailure(null)
                    }
                }
            },
        )
        val info = webAuthnPromptInfo(this, title, subtitle, description)
        if (crypto == null) prompt?.authenticate(info) else prompt?.authenticate(info, crypto)
    }

    private fun validatedClient(
        rpId: String,
        caller: CallingAppInfo,
        clientDataHash: ByteArray?,
    ): WebAuthnClientData {
        val validated = validator.validate(rpId, caller)
        return if (validated.origin.startsWith("https://")) {
            require(clientDataHash?.size == 32) { "Privileged browser did not supply clientDataHash" }
            validated.copy(suppliedHash = clientDataHash)
        } else {
            require(clientDataHash == null) { "Native caller supplied a privileged clientDataHash" }
            validated
        }
    }

    private fun finishCreate(responseJson: String) {
        val result = Intent()
        PendingIntentHandler.setCreateCredentialResponse(
            result,
            CreatePublicKeyCredentialResponse(responseJson),
        )
        setResult(Activity.RESULT_OK, result)
        finish()
    }

    private fun finishGet(responseJson: String) {
        val result = Intent()
        PendingIntentHandler.setGetCredentialResponse(
            result,
            GetCredentialResponse(PublicKeyCredential(responseJson)),
        )
        setResult(Activity.RESULT_OK, result)
        finish()
    }

    /**
     * A creation that did not happen, named as precisely as WebAuthn allows.
     *
     * An excluded credential has its own name in the specification --
     * `InvalidStateError` -- and it is the one a relying party reads to say
     * "this device is already registered" rather than showing the same failure
     * it shows for everything else. Returned as a `DomException` so Credential
     * Manager hands the browser that name instead of an unknown error.
     *
     * A null error is the prompt itself failing. Anything else is the work
     * after a prompt that succeeded, which is not the finger's fault and no
     * longer says it was.
     */
    private fun failCreateWith(error: Throwable?) {
        if (error is ExcludedCredentialException) {
            runOnUiThread {
                val result = Intent()
                PendingIntentHandler.setCreateCredentialException(
                    result,
                    CreatePublicKeyCredentialDomException(InvalidStateError()),
                )
                setResult(Activity.RESULT_OK, result)
                finish()
            }
            return
        }
        failCreate(
            if (error == null) "Biometric verification failed"
            else "The passkey could not be created",
        )
    }

    private fun failCreate(message: String) {
        runOnUiThread {
            val result = Intent()
            PendingIntentHandler.setCreateCredentialException(result, CreateCredentialUnknownException(message))
            setResult(Activity.RESULT_OK, result)
            finish()
        }
    }

    private fun failGet(message: String) {
        runOnUiThread {
            val result = Intent()
            PendingIntentHandler.setGetCredentialException(result, GetCredentialUnknownException(message))
            setResult(Activity.RESULT_OK, result)
            finish()
        }
    }

    private fun finishCanceled() {
        setResult(Activity.RESULT_CANCELED)
        finish()
    }

    override fun onDestroy() {
        prompt?.cancelAuthentication()
        executor.shutdownNow()
        super.onDestroy()
    }

    companion object {
        const val ACTION_CREATE = "com.bioauth.phone_auth_native.WEBAUTHN_CREATE"
        const val ACTION_GET = "com.bioauth.phone_auth_native.WEBAUTHN_GET"
        const val EXTRA_CREDENTIAL_ID = "credential_id"
    }
}

internal fun webAuthnPromptInfo(
    context: Context,
    title: String,
    subtitle: String,
    description: String?,
): BiometricPrompt.PromptInfo = BiometricPrompt.PromptInfo.Builder()
    .setTitle(title)
    .setSubtitle(subtitle)
    .setDescription(description)
    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
    .setNegativeButtonText(context.getString(R.string.cancel))
    .setConfirmationRequired(true)
    .build()
