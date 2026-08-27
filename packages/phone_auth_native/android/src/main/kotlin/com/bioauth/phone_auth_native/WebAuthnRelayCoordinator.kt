package com.bioauth.phone_auth_native

import io.flutter.plugin.common.MethodChannel
import java.util.concurrent.ConcurrentHashMap

internal object WebAuthnRelayCoordinator {
    private val pending = ConcurrentHashMap<String, MethodChannel.Result>()

    fun add(requestId: String, result: MethodChannel.Result): Boolean =
        pending.putIfAbsent(requestId, result) == null

    fun complete(requestId: String, responseJson: String?, error: String?) {
        val result = pending.remove(requestId) ?: return
        if (responseJson != null) {
            result.success(mapOf("responseJson" to responseJson))
        } else {
            result.error("webauthn_failed", error ?: "Passkey operation failed", null)
        }
    }

    fun notificationId(requestId: String): Int =
        (requestId.hashCode() and Int.MAX_VALUE).coerceAtLeast(1)
}
