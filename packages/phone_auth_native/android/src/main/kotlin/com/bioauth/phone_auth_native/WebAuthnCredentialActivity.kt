package com.bioauth.phone_auth_native

import android.app.Activity
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
        if (savedInstanceState != null) return
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
                options to client
            }.onSuccess { (options, client) ->
                runOnUiThread {
                    authenticate(
                        title = "Criar passkey",
                        subtitle = options.rpId,
                        crypto = null,
                        onSuccess = { finishCreate(core.create(options, client)) },
                        onFailure = { failCreate("Biometric verification failed") },
                    )
                }
            }.onFailure { failCreate("Relying party validation failed") }
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
                        crypto = BiometricPrompt.CryptoObject(prepared.signature),
                        onSuccess = { result ->
                            val signature = result.cryptoObject?.signature
                            if (signature == null) {
                                failGet("Authenticated signature is unavailable")
                            } else {
                                finishGet(core.finishAssertion(prepared.copy(signature = signature)))
                            }
                        },
                        onFailure = { failGet("Biometric verification failed") },
                    )
                }
            }.onFailure { failGet("Relying party validation failed") }
        }
    }

    private fun authenticate(
        title: String,
        subtitle: String,
        crypto: BiometricPrompt.CryptoObject?,
        onSuccess: (BiometricPrompt.AuthenticationResult) -> Unit,
        onFailure: () -> Unit,
    ) {
        var completed = false
        prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    if (!completed) {
                        completed = true
                        runCatching { onSuccess(result) }.onFailure { onFailure() }
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    if (!completed) {
                        completed = true
                        onFailure()
                    }
                }
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButtonText("Cancelar")
            .setConfirmationRequired(true)
            .build()
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
