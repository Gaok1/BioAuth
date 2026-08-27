package com.bioauth.phone_auth_native

import android.app.NotificationManager
import android.os.Bundle
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.util.concurrent.Executors

class WebAuthnRelayActivity : FragmentActivity() {
    private val executor = Executors.newSingleThreadExecutor()
    private val core by lazy { WebAuthnCore(PasskeyStore(this), WebAuthnKeyStore(this)) }
    private var prompt: BiometricPrompt? = null
    private lateinit var requestId: String

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestId = intent.getStringExtra(EXTRA_REQUEST_ID).orEmpty()
        if (savedInstanceState != null || requestId.isEmpty()) {
            fail("Invalid desktop passkey request")
            return
        }
        val operation = intent.getStringExtra(EXTRA_OPERATION)
        val origin = intent.getStringExtra(EXTRA_ORIGIN).orEmpty()
        val optionsJson = intent.getStringExtra(EXTRA_OPTIONS).orEmpty()
        executor.execute {
            runCatching {
                when (operation) {
                    OP_CREATE -> prepareCreate(origin, optionsJson)
                    OP_GET -> prepareGet(origin, optionsJson)
                    else -> throw IllegalArgumentException("Unsupported WebAuthn operation")
                }
            }.onFailure { fail("Desktop passkey request was rejected") }
        }
    }

    private fun prepareCreate(origin: String, optionsJson: String) {
        val options = core.creationOptions(optionsJson)
        RpIdValidator.requireOriginMatchesRpId(origin, options.rpId)
        runOnUiThread {
            authenticate("Criar passkey", "${options.rpId} via $origin", null) {
                core.create(options, WebAuthnClientData(origin, null))
            }
        }
    }

    private fun prepareGet(origin: String, optionsJson: String) {
        val options = core.requestOptions(optionsJson)
        RpIdValidator.requireOriginMatchesRpId(origin, options.rpId)
        val matches = core.credentialsFor(options)
        require(matches.size == 1) { "The desktop request must select one passkey" }
        val prepared = core.prepareAssertion(
            options,
            matches.single().credentialId,
            WebAuthnClientData(origin, null),
        )
        runOnUiThread {
            authenticate(
                "Usar passkey",
                "${options.rpId} via $origin",
                BiometricPrompt.CryptoObject(prepared.signature),
            ) { result ->
                val signature = result.cryptoObject?.signature
                    ?: throw IllegalStateException("Authenticated signature is unavailable")
                core.finishAssertion(prepared.copy(signature = signature))
            }
        }
    }

    private fun authenticate(
        title: String,
        subtitle: String,
        crypto: BiometricPrompt.CryptoObject?,
        finishOperation: (BiometricPrompt.AuthenticationResult) -> String,
    ) {
        var completed = false
        prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    if (completed) return
                    completed = true
                    runCatching { finishOperation(result) }
                        .onSuccess(::succeed)
                        .onFailure { fail("Passkey operation failed") }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    if (completed) return
                    completed = true
                    fail("Biometric verification did not complete")
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

    private fun succeed(responseJson: String) {
        WebAuthnRelayCoordinator.complete(requestId, responseJson, null)
        finishRelay()
    }

    private fun fail(message: String) {
        runOnUiThread {
            if (::requestId.isInitialized) {
                WebAuthnRelayCoordinator.complete(requestId, null, message)
            }
            finishRelay()
        }
    }

    private fun finishRelay() {
        if (::requestId.isInitialized) {
            getSystemService(NotificationManager::class.java)
                .cancel(WebAuthnRelayCoordinator.notificationId(requestId))
        }
        finish()
    }

    override fun onDestroy() {
        prompt?.cancelAuthentication()
        executor.shutdownNow()
        super.onDestroy()
    }

    companion object {
        const val EXTRA_REQUEST_ID = "relay_request_id"
        const val EXTRA_OPERATION = "relay_operation"
        const val EXTRA_ORIGIN = "relay_origin"
        const val EXTRA_OPTIONS = "relay_options"
        const val OP_CREATE = "create"
        const val OP_GET = "get"
    }
}
