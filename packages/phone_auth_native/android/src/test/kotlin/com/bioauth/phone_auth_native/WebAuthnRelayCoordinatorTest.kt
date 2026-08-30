package com.bioauth.phone_auth_native

import io.flutter.plugin.common.MethodChannel
import org.mockito.Mockito.mock
import org.mockito.Mockito.verify
import org.mockito.Mockito.verifyNoMoreInteractions
import kotlin.test.assertEquals
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class WebAuthnRelayCoordinatorTest {
    @Test
    fun cancellationCompletesOnceAndDismissesTheVisibleCeremony() {
        val result = mock(MethodChannel.Result::class.java)
        var dismissed = false
        val requestId = "cancel-test-${System.nanoTime()}"

        assertTrue(WebAuthnRelayCoordinator.add(requestId, result))
        assertTrue(WebAuthnRelayCoordinator.attachCancellationListener(requestId) { dismissed = true })
        assertTrue(WebAuthnRelayCoordinator.cancel(requestId, "cancelled"))
        assertTrue(dismissed)
        assertFalse(WebAuthnRelayCoordinator.cancel(requestId, "cancelled again"))
        verify(result).error("webauthn_cancelled", "cancelled", null)
    }

    @Test
    fun cancellationWinningTheRacePreventsTheIrreversibleOperation() {
        val result = mock(MethodChannel.Result::class.java)
        val requestId = "cancel-wins-${System.nanoTime()}"
        var commits = 0

        assertTrue(WebAuthnRelayCoordinator.add(requestId, result))
        assertTrue(WebAuthnRelayCoordinator.cancel(requestId, "cancelled"))
        assertFalse(WebAuthnRelayCoordinator.completeWith(requestId) {
            commits += 1
            "created"
        })

        assertEquals(0, commits)
        verify(result).error("webauthn_cancelled", "cancelled", null)
        verifyNoMoreInteractions(result)
    }

    @Test
    fun commitWinningTheRaceCannotBeReclassifiedAsCancelled() {
        val result = mock(MethodChannel.Result::class.java)
        val requestId = "commit-wins-${System.nanoTime()}"
        var commits = 0

        assertTrue(WebAuthnRelayCoordinator.add(requestId, result))
        assertTrue(WebAuthnRelayCoordinator.completeWith(requestId) {
            commits += 1
            "created"
        })
        assertFalse(WebAuthnRelayCoordinator.cancel(requestId, "too late"))

        assertEquals(1, commits)
        verify(result).success(mapOf("responseJson" to "created"))
        verifyNoMoreInteractions(result)
    }
}
