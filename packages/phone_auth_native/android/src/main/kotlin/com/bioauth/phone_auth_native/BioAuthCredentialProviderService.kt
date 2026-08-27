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
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import java.time.Instant
import java.util.concurrent.Executors

@RequiresApi(34)
class BioAuthCredentialProviderService : CredentialProviderService() {
    private val executor = Executors.newCachedThreadPool()
    private val core by lazy { WebAuthnCore(PasskeyStore(this), WebAuthnKeyStore(this)) }
    private val validator by lazy {
        val allowlist = resources.openRawResource(R.raw.privileged_browsers).bufferedReader().use { it.readText() }
        RpIdValidator(allowlist)
    }

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
                    pendingIntent(WebAuthnCredentialActivity.ACTION_CREATE, null),
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
                val entries = request.beginGetCredentialOptions
                    .filterIsInstance<BeginGetPublicKeyCredentialOption>()
                    .flatMap { option ->
                        val options = core.requestOptions(option.requestJson)
                        validator.validate(options.rpId, caller)
                        core.credentialsFor(options).map { record ->
                            PublicKeyCredentialEntry.Builder(
                                this,
                                record.userName,
                                pendingIntent(WebAuthnCredentialActivity.ACTION_GET, record.credentialId),
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

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) {
        callback.onResult(null)
    }

    private fun pendingIntent(action: String, credentialId: ByteArray?): PendingIntent {
        val intent = Intent(this, WebAuthnCredentialActivity::class.java).setAction(action)
        credentialId?.let { intent.putExtra(WebAuthnCredentialActivity.EXTRA_CREDENTIAL_ID, it) }
        val requestCode = credentialId?.contentHashCode() ?: action.hashCode()
        return PendingIntent.getActivity(
            this,
            requestCode,
            intent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
    }

    override fun onDestroy() {
        executor.shutdownNow()
        super.onDestroy()
    }
}
