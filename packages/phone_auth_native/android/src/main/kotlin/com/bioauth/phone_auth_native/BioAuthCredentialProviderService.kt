package com.bioauth.phone_auth_native

import android.app.PendingIntent
import android.content.Intent
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPasswordOption
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.PasswordCredentialEntry
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import java.time.Instant
import java.util.concurrent.Executors

@RequiresApi(34)
class BioAuthCredentialProviderService : CredentialProviderService() {
    private val executor = Executors.newCachedThreadPool()
    private val core by lazy { WebAuthnCore(PasskeyStore(this), WebAuthnKeyStore(this)) }
    private val validator by lazy { RpIdValidator.fromResources(this) }

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        val publicKey = request as? BeginCreatePublicKeyCredentialRequest
        val caller = publicKey?.callingAppInfo
        if (publicKey == null || caller == null) {
            callback.onError(CreateCredentialUnknownException("Unsupported credential request"))
            return
        }
        executor.execute {
            runCatching {
                val options = core.creationOptions(publicKey.requestJson)
                validator.validate(options.rpId, caller)
                if (cancellationSignal.isCanceled) return@execute
                val entry = CreateEntry.Builder(
                    options.userName,
                    credentialEntryPendingIntent(this, WebAuthnCredentialActivity.ACTION_CREATE, null),
                ).setPublicKeyCredentialCount(core.credentialsFor(
                    WebAuthnRequestOptions(options.rpId, options.challenge, emptyList()),
                ).size).build()
                callback.onResult(BeginCreateCredentialResponse(listOf(entry)))
            }.onFailure {
                if (!cancellationSignal.isCanceled) {
                    callback.onError(CreateCredentialUnknownException("Relying party validation failed"))
                }
            }
        }
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        val caller = request.callingAppInfo
        if (caller == null) {
            callback.onError(GetCredentialUnknownException("Calling app identity is unavailable"))
            return
        }
        executor.execute {
            runCatching {
                val passwords: List<CredentialEntry> = request.beginGetCredentialOptions
                    .filterIsInstance<BeginGetPasswordOption>()
                    .flatMap { option -> passwordEntries(caller, option) }
                val entries: List<CredentialEntry> = passwords + request.beginGetCredentialOptions
                    .filterIsInstance<BeginGetPublicKeyCredentialOption>()
                    .flatMap { option ->
                        val options = core.requestOptions(option.requestJson)
                        validator.validate(options.rpId, caller)
                        core.credentialsFor(options).map { record ->
                            PublicKeyCredentialEntry.Builder(
                                this,
                                record.userName,
                                credentialEntryPendingIntent(
                                    this,
                                    WebAuthnCredentialActivity.ACTION_GET,
                                    record.credentialId,
                                ),
                                option,
                            ).setDisplayName(record.userDisplayName)
                                .setLastUsedTime(Instant.ofEpochMilli(record.createdAtMillis))
                                .build()
                        }
                    }
                if (!cancellationSignal.isCanceled) callback.onResult(BeginGetCredentialResponse(entries))
            }.onFailure {
                if (!cancellationSignal.isCanceled) {
                    callback.onError(GetCredentialUnknownException("Relying party validation failed"))
                }
            }
        }
    }

    /**
     * One entry, offered whenever a vault exists at all.
     *
     * Not a row per matching account, and that is forced rather than chosen.
     * Item names, usernames and sites are encrypted at rest under a key that
     * demands a biometric per use (`DEC-06`, `VLT-02`), so listing matches
     * here would mean raising a prompt because a text field gained focus —
     * before the user has expressed any intention at all.
     *
     * The alternative is a plaintext match index next to the vault, which is
     * how most password managers do it and is exactly the metadata `DEC-06`
     * says is encrypted. That is a product decision, not something to slip in
     * behind an autofill feature.
     *
     * So the entry is generic, and everything specific happens after the tap:
     * [VaultCredentialActivity] unlocks, matches against this same caller, and
     * releases at most one password. What this leaks is that the user has a
     * vault, which the presence of the app already says.
     */
    private fun passwordEntries(
        caller: CallingAppInfo,
        option: BeginGetPasswordOption,
    ): List<PasswordCredentialEntry> {
        if (!VaultFileStorage(this).exists()) return emptyList()
        return listOf(
            PasswordCredentialEntry.Builder(
                this,
                "Cofre BioAuth",
                vaultEntryPendingIntent(this),
                option,
            ).build(),
        )
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) {
        callback.onResult(null)
    }

    override fun onDestroy() {
        executor.shutdownNow()
        super.onDestroy()
    }
}

/** The tap that leads to a password. Mutable for the same reason as below. */
@RequiresApi(34)
internal fun vaultEntryPendingIntent(context: android.content.Context): PendingIntent =
    PendingIntent.getActivity(
        context,
        VAULT_REQUEST_CODE,
        Intent(context, VaultCredentialActivity::class.java),
        PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

private const val VAULT_REQUEST_CODE = 0x7A17

/** Mutable only because Credential Manager must fill its provider request into the explicit intent. */
@RequiresApi(34)
internal fun credentialEntryPendingIntent(
    context: android.content.Context,
    action: String,
    credentialId: ByteArray?,
): PendingIntent {
    val intent = Intent(context, WebAuthnCredentialActivity::class.java).setAction(action)
    credentialId?.let { intent.putExtra(WebAuthnCredentialActivity.EXTRA_CREDENTIAL_ID, it) }
    val requestCode = credentialId?.contentHashCode() ?: action.hashCode()
    return PendingIntent.getActivity(
        context,
        requestCode,
        intent,
        PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )
}
