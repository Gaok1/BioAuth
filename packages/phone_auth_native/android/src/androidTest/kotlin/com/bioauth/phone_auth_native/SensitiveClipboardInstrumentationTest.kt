package com.bioauth.phone_auth_native

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The flag that decides whether a copied password is shown to the room.
 *
 * Instrumented rather than a JVM test because this is a real `ClipData` built
 * by the real platform, and the mistake it guards against is a clip that
 * carries the text and not the flag — which is exactly what a stubbed
 * `ClipData` also looks like.
 *
 * Only the clip is built here, never written. Writing the clipboard is
 * restricted to the app that has focus, and an instrumentation with no
 * activity in front does not, so a test that copied would be testing the
 * platform's mood rather than this flag.
 */
@RunWith(AndroidJUnit4::class)
class SensitiveClipboardInstrumentationTest {
    @Test
    fun aCopiedSecretIsMarkedSensitiveAndCarriesNoLabel() {
        val clip = SensitiveClipboard.clipFor("hunter2")

        val extras = clip.description.extras
        assertNotNull(extras)
        assertTrue(extras!!.getBoolean(SensitiveClipboard.EXTRA_IS_SENSITIVE))
        assertEquals("hunter2", clip.getItemAt(0).text)
        // Shown beside the preview, so it must not name what was copied.
        assertEquals("", clip.description.label)
    }
}
