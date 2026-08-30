package com.bioauth.phone_auth_native

import io.flutter.plugin.common.MethodChannel
import java.util.concurrent.ConcurrentHashMap

internal object WebAuthnRelayCoordinator {
    private val pending = ConcurrentHashMap<String, MethodChannel.Result>()
    private val cancellationListeners = ConcurrentHashMap<String, () -> Unit>()

    fun add(requestId: String, result: MethodChannel.Result): Boolean =
        pending.putIfAbsent(requestId, result) == null

    fun complete(requestId: String, responseJson: String?, error: String?) {
        val result = pending.remove(requestId) ?: return
        cancellationListeners.remove(requestId)
        if (responseJson != null) {
            result.success(mapOf("responseJson" to responseJson))
        } else {
            result.error("webauthn_failed", error ?: "Passkey operation failed", null)
        }
    }

    /**
     * Claims a request before an irreversible operation, then publishes its result.
     *
     * Cancellation and this claim race on the same `pending.remove`: if cancel
     * wins, [operation] never runs; if this wins, a later cancel cannot turn a
     * committed passkey into one the relying party never received.
     */
    fun completeWith(
        requestId: String,
        describeFailure: (Throwable) -> String,
        operation: () -> String,
    ): Boolean {
        val result = pending.remove(requestId) ?: return false
        cancellationListeners.remove(requestId)
        runCatching(operation).fold(
            onSuccess = { result.success(mapOf("responseJson" to it)) },
            // Asked for, rather than written here, because this object has
            // nothing to say about why creating a credential failed and the
            // caller does. A single sentence standing in for every way it can
            // go wrong is the one thing this path cannot afford to lose: what
            // reaches the website is deliberately undifferentiated either way,
            // so this sentence is the only account anyone ever gets, and it is
            // read from the desktop's audit log by someone trying to find out
            // why a passkey will not work.
            onFailure = { result.error("webauthn_failed", describeFailure(it), null) },
        )
        return true
    }

    fun attachCancellationListener(requestId: String, listener: () -> Unit): Boolean {
        if (!pending.containsKey(requestId)) return false
        cancellationListeners[requestId] = listener
        if (!pending.containsKey(requestId)) {
            cancellationListeners.remove(requestId)
            return false
        }
        return true
    }

    fun detachCancellationListener(requestId: String) {
        cancellationListeners.remove(requestId)
    }

    fun cancel(requestId: String, error: String): Boolean {
        val result = pending.remove(requestId) ?: return false
        cancellationListeners.remove(requestId)?.invoke()
        result.error("webauthn_cancelled", error, null)
        return true
    }

    fun notificationId(requestId: String): Int =
        (requestId.hashCode() and Int.MAX_VALUE).coerceAtLeast(1)
}
