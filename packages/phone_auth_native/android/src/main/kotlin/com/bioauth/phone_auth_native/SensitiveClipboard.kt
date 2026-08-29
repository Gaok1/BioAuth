package com.bioauth.phone_auth_native

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.PersistableBundle

/**
 * Copies a secret without Android showing it to whoever is looking.
 *
 * Since Android 13 every copy raises a preview that renders what was copied,
 * so copying a password out of a password manager displayed it in plain text
 * to the room. The same flag is what keeps a value out of clipboard history
 * and out of a keyboard's suggestion strip, which is the half that outlives
 * the paste.
 *
 * It lives on the `ClipData`, which is why this exists at all: Flutter's
 * `Clipboard.setData` builds its own and has no way to say this.
 */
internal object SensitiveClipboard {
    /**
     * `ClipDescription.EXTRA_IS_SENSITIVE`, spelled out.
     *
     * The constant is API 33 and this package runs from 24. The value is the
     * same string on every version, and the clipboards and keyboards that
     * honoured it before the platform did read it by name — so writing it
     * always is strictly better than writing it only where it compiles.
     */
    const val EXTRA_IS_SENSITIVE = "android.content.extra.IS_SENSITIVE"

    /**
     * The clip, flagged.
     *
     * The label is empty on purpose: it is shown, and naming the thing copied
     * is as much as anyone watching over a shoulder needs to be told.
     */
    fun clipFor(text: String): ClipData = ClipData.newPlainText("", text).apply {
        description.extras = PersistableBundle().apply {
            putBoolean(EXTRA_IS_SENSITIVE, true)
        }
    }

    /** Returns false when the device has no clipboard to copy to. */
    fun copy(context: Context, text: String): Boolean {
        val clipboard = context.getSystemService(ClipboardManager::class.java) ?: return false
        clipboard.setPrimaryClip(clipFor(text))
        return true
    }
}
