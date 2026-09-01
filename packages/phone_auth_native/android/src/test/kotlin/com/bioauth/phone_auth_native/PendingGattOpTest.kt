package com.bioauth.phone_auth_native

import io.flutter.plugin.common.MethodChannel
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.mockito.ArgumentMatchers.any
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito.mock
import org.mockito.Mockito.never
import org.mockito.Mockito.times
import org.mockito.Mockito.verify

internal class PendingGattOpTest {
    /**
     * Stands in for the main looper, so the deadline can be reached without
     * waiting for it.
     */
    private class FakeHandler {
        private var scheduled: Runnable? = null
        var delayMs: Long? = null
            private set

        val isArmed: Boolean
            get() = scheduled != null

        fun schedule(runnable: Runnable, delay: Long) {
            scheduled = runnable
            delayMs = delay
        }

        fun unschedule(runnable: Runnable) {
            if (scheduled === runnable) {
                scheduled = null
                delayMs = null
            }
        }

        /** Runs whatever is due, the way the looper would when the time comes. */
        fun elapse() {
            val due = scheduled
            scheduled = null
            delayMs = null
            due?.run()
        }
    }

    private val handler = FakeHandler()
    private var teardowns = 0

    private fun op(code: String = "write_failed") = PendingGattOp(
        errorCode = code,
        timeoutMs = 10_000L,
        schedule = handler::schedule,
        unschedule = handler::unschedule,
        onExpired = { teardowns++ },
    )

    @Test
    fun aCallbackThatNeverComesFailsTheCallInsteadOfHangingIt() {
        // The whole point. Android settles a write from a callback, and a
        // callback that never arrives used to mean the reply to Dart was never
        // sent: the session awaiting that write never closed, so the phone's one
        // GATT client was never given back and every later connection waited on
        // it. A deadline turns that into one failed write.
        val operation = op()
        val result = mock(MethodChannel.Result::class.java)

        assertTrue(operation.arm(result))
        assertEquals(10_000L, handler.delayMs)
        handler.elapse()

        verify(result).error("write_failed", "BLE operation timed out", null)
        assertFalse(operation.isActive)
        assertEquals(1, teardowns, "an operation the stack lost takes the link with it")
    }

    @Test
    fun theDeadlineStandsDownWhenTheCallbackArrives() {
        val operation = op()
        val result = mock(MethodChannel.Result::class.java)

        operation.arm(result)
        assertTrue(operation.settle { it.success(null) })

        assertFalse(handler.isArmed, "a settled operation must not still be on a clock")
        handler.elapse()
        verify(result, times(1)).success(null)
        verify(result, never()).error(anyString(), anyString(), any())
        assertEquals(0, teardowns)
    }

    @Test
    fun aCallbackArrivingAfterItsDeadlineIsDropped() {
        // The crash this class exists to make impossible. The deadline has
        // already told Dart the write failed; the late callback settling the
        // same reply a second time throws inside the Flutter engine.
        val operation = op()
        val result = mock(MethodChannel.Result::class.java)

        operation.arm(result)
        handler.elapse()

        assertFalse(operation.settle { it.success(null) })
        verify(result, never()).success(null)
        verify(result, times(1)).error("write_failed", "BLE operation timed out", null)
    }

    @Test
    fun anExpiredOperationLetsTheNextOneThrough() {
        // Recovery, not just reporting: the slot has to be free afterwards, or
        // the deadline would have swapped a hang for a permanent refusal.
        val operation = op()
        operation.arm(mock(MethodChannel.Result::class.java))
        handler.elapse()

        assertTrue(operation.arm(mock(MethodChannel.Result::class.java)))
    }

    @Test
    fun aSecondOperationIsRefusedWhileOneIsStillInFlight() {
        // The stack holds one at a time, so this has to stay refused -- and the
        // first one's deadline must survive the second one being turned away.
        val operation = op()
        val first = mock(MethodChannel.Result::class.java)

        operation.arm(first)
        assertFalse(operation.arm(mock(MethodChannel.Result::class.java)))

        assertTrue(handler.isArmed)
        handler.elapse()
        verify(first).error("write_failed", "BLE operation timed out", null)
    }

    @Test
    fun theOwnerCanFailOneUnderACodeOfItsOwn() {
        // Losing the link reports `disconnected`, not the operation's own code.
        val operation = op()
        val result = mock(MethodChannel.Result::class.java)

        operation.arm(result)
        assertTrue(operation.fail("BLE disconnected", code = "disconnected"))

        verify(result).error("disconnected", "BLE disconnected", null)
        assertFalse(handler.isArmed)
    }

    @Test
    fun twoThreadsSettlingTogetherStillSettleOnce() {
        // The real pairing: Android delivers the GATT callback on a binder
        // thread while the deadline runs on the main looper, and the moment
        // they collide is a slow link answering just as its time runs out.
        // Finding the field set and then clearing it was three steps, so both
        // could find it set, both could reply, and replying twice to one
        // `MethodChannel` request throws. Run enough times to catch a window
        // that is only a few instructions wide.
        val threads = java.util.concurrent.Executors.newFixedThreadPool(2)
        try {
            repeat(2000) {
                val operation = PendingGattOp(
                    errorCode = "write_failed",
                    timeoutMs = 1,
                    schedule = { _, _ -> },
                    unschedule = { },
                )
                val settled = java.util.concurrent.atomic.AtomicInteger()
                operation.arm(mock(MethodChannel.Result::class.java))

                val gate = java.util.concurrent.CountDownLatch(1)
                val done = java.util.concurrent.CountDownLatch(2)
                repeat(2) {
                    threads.execute {
                        gate.await()
                        if (operation.settle { settled.incrementAndGet() }) Unit
                        done.countDown()
                    }
                }
                gate.countDown()
                assertTrue(done.await(10, java.util.concurrent.TimeUnit.SECONDS))
                assertEquals(1, settled.get())
            }
        } finally {
            threads.shutdownNow()
        }
    }
}
