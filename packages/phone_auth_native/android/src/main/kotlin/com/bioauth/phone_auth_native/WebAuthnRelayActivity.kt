package com.bioauth.phone_auth_native

import android.app.NotificationManager
import android.app.AlertDialog
import android.os.Bundle
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import org.json.JSONObject
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
            }.onFailure { fail("Desktop passkey request was rejected: ${reasonOf(it)}") }
        }
    }

    private fun prepareCreate(origin: String, optionsJson: String) {
        val options = core.creationOptions(optionsJson)
        RpIdValidator.requireOriginMatchesRpId(origin, options.rpId, publicSuffixes)
        val client = relayClientData(origin, optionsJson)
        // Before the prompt. `core.create` checks too, but it runs from the
        // prompt's success callback -- so asking there meant the phone lit up,
        // the person authenticated, and the desktop then reported a refusal
        // that was knowable before any of it.
        if (core.isExcluded(options)) {
            throw ExcludedCredentialException("A credential excluded by the relying party already exists")
        }
        runOnUiThread {
            if (cancelled) return@runOnUiThread
            authenticate(
                getString(R.string.passkey_create_title),
                "${options.rpId} via $origin",
                getString(R.string.passkey_no_backup),
                null,
                claimBeforeOperation = true,
            ) { core.create(options, client) }
        }
    }

    private fun prepareGet(origin: String, optionsJson: String) {
        val options = core.requestOptions(optionsJson)
        RpIdValidator.requireOriginMatchesRpId(origin, options.rpId, publicSuffixes)
        val client = relayClientData(origin, optionsJson)
        val matches = core.credentialsFor(options)
        require(matches.isNotEmpty()) { "No matching passkey" }
        runOnUiThread {
            if (cancelled) return@runOnUiThread
            if (matches.size == 1) {
                authenticateGet(options, matches.single(), origin, client)
            } else {
                AlertDialog.Builder(this)
                    .setTitle(getString(R.string.passkey_choose_account))
                    .setItems(accountLabels(matches)) { _, index ->
                        authenticateGet(options, matches[index], origin, client)
                    }
                    .setNegativeButton(getString(R.string.cancel)) { _, _ ->
                        fail("Passkey selection was cancelled")
                    }
                    .setOnCancelListener { fail("Passkey selection was cancelled") }
                    .show()
            }
        }
    }

    private fun authenticateGet(
        options: WebAuthnRequestOptions,
        credential: PasskeyRecord,
        origin: String,
        client: WebAuthnClientData,
    ) {
        val prepared = runCatching {
            core.prepareAssertion(options, credential.credentialId, client)
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
        claimBeforeOperation: Boolean = false,
        finishOperation: (BiometricPrompt.AuthenticationResult) -> String,
    ) {
        // `authenticate` does not throw when it cannot start: it logs "Called
        // after onSaveInstanceState()" and returns, having raised no prompt
        // and scheduled no callback. Every path out of this activity runs from
        // one of those two callbacks, so nothing would finish it and nothing
        // would answer the desktop, which waits out its whole deadline. The
        // window is not small -- relying-party validation runs first and can
        // spend three seconds fetching `assetlinks.json` -- so putting the
        // phone down after starting the ceremony is enough to reach it.
        if (supportFragmentManager.isStateSaved) {
            fail("The screen cannot show a prompt right now")
            return
        }
        var completed = false
        prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    if (completed) return
                    completed = true
                    if (claimBeforeOperation) {
                        WebAuthnRelayCoordinator.completeWith(
                            requestId,
                            { "Passkey operation failed: ${reasonOf(it)}" },
                        ) { finishOperation(result) }
                        finishRelay()
                        return
                    }
                    runCatching { finishOperation(result) }
                        .onSuccess(::succeed)
                        .onFailure { fail("Passkey operation failed: ${reasonOf(it)}") }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    if (completed) return
                    completed = true
                    // The system's own words, which name the thing that
                    // happened: too many attempts, no hardware, the person
                    // pressed the negative button. Reduced to one sentence,
                    // a phone that cannot do biometrics at all and a person
                    // who changed their mind arrive looking identical.
                    fail(
                        "Biometric verification did not complete: " +
                            "${errString.toString().trim().take(120)} ($errorCode)",
                    )
                }
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setDescription(description)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButtonText(getString(R.string.cancel))
            .setConfirmationRequired(true)
            .build()
        if (crypto == null) prompt?.authenticate(info) else prompt?.authenticate(info, crypto)
    }

    private fun succeed(responseJson: String) {
        WebAuthnRelayCoordinator.complete(requestId, responseJson, null)
        finishRelay()
    }

    /// Why one of the checks above refused, in the words of the check itself.
    ///
    /// Everything reachable from there fails through `require`, and those
    /// messages are written here, one rule each: the challenge is the wrong
    /// size, ES256 is not among the algorithms offered, the browser origin is
    /// not authorized for this relying party. Collapsing a dozen of them into
    /// "the request was rejected" left the only readable account of what went
    /// wrong on the floor, while the person read on a website that their
    /// authenticator would not do it.
    private fun reasonOf(failure: Throwable): String =
        failure.message?.trim()?.take(120)?.takeIf { it.isNotEmpty() }
            ?: "no reason given"

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
        const val EXTRA_REQUEST_ID = "relay_request_id"
        const val EXTRA_OPERATION = "relay_operation"
        const val EXTRA_ORIGIN = "relay_origin"
        const val EXTRA_OPTIONS = "relay_options"
        const val OP_CREATE = "create"
        const val OP_GET = "get"
    }
}

/**
 * The client data for a ceremony driven from a paired computer.
 *
 * `cross-platform`, because that is what this is: the browser is on the
 * desktop and the authenticator is a phone on the other end of a link. The
 * parser already argues exactly this when it accepts a `cross-platform`
 * request -- "a security key, or a phone reached over a link, which is exactly
 * what the desktop relay is". The response has to agree with the request.
 */
internal fun relayClientData(origin: String, optionsJson: String): WebAuthnClientData {
    val root = JSONObject(optionsJson)
    if (!root.has("clientDataHash")) {
        return WebAuthnClientData(origin, null, attachment = ATTACHMENT_CROSS_PLATFORM)
    }
    val hash = WebAuthnRequestParser.decode(root.optString("clientDataHash"), "clientDataHash")
    require(hash.size == 32) { "clientDataHash must contain 32 bytes" }
    return WebAuthnClientData(origin, null, hash, ATTACHMENT_CROSS_PLATFORM)
}

internal fun accountLabels(matches: List<PasskeyRecord>): Array<String> =
    matches.map { "${it.userDisplayName} · ${it.userName}" }.toTypedArray()
