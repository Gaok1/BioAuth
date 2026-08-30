package com.bioauth.phone_auth_native

import io.flutter.plugin.common.MethodChannel

/**
 * One outstanding GATT operation, and the deadline that makes it settle.
 *
 * Android reports a write or an MTU negotiation through a callback, and keeps
 * one such operation in flight at a time. A callback that never arrives -- a
 * wedged stack, a peer that stops answering on a link that still looks up --
 * therefore fails nothing: the reply to Dart is simply never sent, and every
 * later operation queues behind one the stack still believes is running.
 *
 * From the outside that is not a slow link. It is a phone whose Bluetooth has
 * stopped working until the app is restarted, with nothing raised and nothing
 * logged: the Dart side is awaiting a write that will never complete, so the
 * session never closes, so the one native GATT client is never given back, so
 * the next connection waits on it too. Connecting has had a deadline since it
 * was written. The operations that run after it had none.
 *
 * Settles exactly once, because settling a [MethodChannel.Result] twice throws
 * -- and a callback arriving after its own deadline is exactly the case that
 * would do it.
 *
 * The deadline is scheduled through the owner's handler rather than a timer of
 * its own, so it runs where that handler runs: the main looper, for the
 * controller that owns these.
 */
internal class PendingGattOp(
    private val errorCode: String,
    private val timeoutMs: Long,
    private val schedule: (Runnable, Long) -> Unit,
    private val unschedule: (Runnable) -> Unit,
    private val onExpired: () -> Unit = {},
) {
    private var pending: MethodChannel.Result? = null

    private val expiry = Runnable {
        val expired = take() ?: return@Runnable
        expired.error(errorCode, "BLE operation timed out", null)
        onExpired()
    }

    val isActive: Boolean
        get() = pending != null

    /** Takes ownership of [result]. False if one is already in flight. */
    fun arm(result: MethodChannel.Result): Boolean {
        if (pending != null) return false
        pending = result
        schedule(expiry, timeoutMs)
        return true
    }

    /**
     * Hands the pending result to [reply] and stands the deadline down.
     *
     * False when there is nothing pending, which is what a callback arriving
     * after its deadline sees. Reporting it rather than settling again is the
     * point: the caller has already been told the operation failed.
     */
    fun settle(reply: (MethodChannel.Result) -> Unit): Boolean {
        val result = take() ?: return false
        reply(result)
        return true
    }

    /** Settles with an error, for a failure the owner detected itself. */
    fun fail(message: String, code: String = errorCode): Boolean =
        settle { it.error(code, message, null) }

    private fun take(): MethodChannel.Result? {
        val result = pending ?: return null
        pending = null
        unschedule(expiry)
        return result
    }
}
