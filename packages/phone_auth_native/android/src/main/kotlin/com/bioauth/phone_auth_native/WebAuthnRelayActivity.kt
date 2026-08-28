package com.bioauth.phone_auth_native

import android.app.NotificationManager
import android.app.AlertDialog
import android.os.Bundle
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.util.concurrent.Executors

class WebAuthnRelayActivity : FragmentActivity() {
    private val executor = Executors.newSingleThreadExecutor()
    private val core by lazy { WebAuthnCore(PasskeyStore(this), WebAuthnKeyStore(this)) }
    private val publicSuffixes by lazy {
        resources.openRawResource(R.raw.public_suffix_list)
            .bufferedReader().use { PublicSuffixList(it.readLines().asSequence()) }
    }
    private var prompt: BiometricPrompt? = null
    @Volatile private var cancelled = false
    private lateinit var requestId: String

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestId = intent.getStringExtra(EXTRA_REQUEST_ID).orEmpty()
        if (savedInstanceState != null || requestId.isEmpty()) {
            fail("Invalid desktop passkey request")
            return
        }
        val attached = WebAuthnRelayCoordinator.attachCancellationListener(requestId) {
            runOnUiThread {
                cancelled = true
                prompt?.cancelAuthentication()
                finishRelay()
            }
        }
        if (!attached) {
            finishRelay()
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
        RpIdValidator.requireOriginMatchesRpId(origin, options.rpId, publicSuffixes)
        runOnUiThread {
            if (cancelled) return@runOnUiThread
            authenticate("Criar passkey", "${options.rpId} via $origin", NO_BACKUP_WARNING, null) {
                core.create(options, WebAuthnClientData(origin, null))
            }
        }
    }

    private fun prepareGet(origin: String, optionsJson: String) {
        val options = core.requestOptions(optionsJson)
        RpIdValidator.requireOriginMatchesRpId(origin, options.rpId, publicSuffixes)
        val matches = core.credentialsFor(options)
        require(matches.isNotEmpty()) { "No matching passkey" }
        runOnUiThread {
            if (cancelled) return@runOnUiThread
            if (matches.size == 1) {
                authenticateGet(options, matches.single(), origin)
            } else {
                AlertDialog.Builder(this)
                    .setTitle("Escolha uma conta")
                    .setItems(accountLabels(matches)) { _, index ->
                        authenticateGet(options, matches[index], origin)
                    }
                    .setNegativeButton("Cancelar") { _, _ -> fail("Passkey selection was cancelled") }
                    .setOnCancelListener { fail("Passkey selection was cancelled") }
                    .show()
            }
        }
    }

    private fun authenticateGet(
        options: WebAuthnRequestOptions,
        credential: PasskeyRecord,
        origin: String,
    ) {
        val prepared = runCatching {
            core.prepareAssertion(options, credential.credentialId, WebAuthnClientData(origin, null))
        }.getOrElse {
            fail("Passkey is no longer available")
            return
        }
        authenticate(
            "Usar passkey",
            "${options.rpId} via $origin",
            null,
            BiometricPrompt.CryptoObject(prepared.signature),
        ) { result ->
            val signature = result.cryptoObject?.signature
                ?: throw IllegalStateException("Authenticated signature is unavailable")
            core.finishAssertion(prepared.copy(signature = signature))
        }
    }

    private fun authenticate(
        title: String,
        subtitle: String,
        description: String?,
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
            .setDescription(description)
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
        if (::requestId.isInitialized) {
            WebAuthnRelayCoordinator.detachCancellationListener(requestId)
        }
        prompt?.cancelAuthentication()
        executor.shutdownNow()
        super.onDestroy()
    }

    companion object {
        private const val NO_BACKUP_WARNING =
            "Sem backup: continue somente se a conta tiver outro método de acesso"
        const val EXTRA_REQUEST_ID = "relay_request_id"
        const val EXTRA_OPERATION = "relay_operation"
        const val EXTRA_ORIGIN = "relay_origin"
        const val EXTRA_OPTIONS = "relay_options"
        const val OP_CREATE = "create"
        const val OP_GET = "get"
    }
}

internal fun accountLabels(matches: List<PasskeyRecord>): Array<String> =
    matches.map { "${it.userDisplayName} · ${it.userName}" }.toTypedArray()
