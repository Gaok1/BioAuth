package com.bioauth.phone_auth_native

import io.flutter.plugin.common.MethodChannel
import org.mockito.Mockito.mock
import org.mockito.Mockito.verify
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
}
