package org.simulationrift.bridge

import android.app.Activity
import android.os.Build
import android.view.View

/**
 * What both apps do to each of their windows before showing anything
 * (§10.7), against other apps on the same device:
 *
 * - other apps' overlays are hidden while the window is shown (API 31+),
 *   so nothing can be drawn over Rift's trusted controls to mislabel
 *   them; on API 30, a touch that passed through another app's window is
 *   dropped instead;
 * - the window's views are excluded from autofill; Compose's text
 *   fields and WebView report to autofill themselves, so each app also
 *   excludes those (`noAutofill`, the WebView's own setting), and no
 *   autofill service sees pages, addresses or passphrases, or fills them;
 * - its content is shown only to accessibility services that declare
 *   themselves tools for users with disabilities (API 34+), not to the
 *   others, which are how most Android malware reads the screen;
 * - no recents snapshot of it is stored on disk (API 33+).
 *
 * None of these is a boundary against code running as Rift itself, and
 * an accessibility tool still sees everything.
 */
object WindowGuard {
    fun apply(activity: Activity) {
        val window = activity.window
        val root = window.decorView
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            // Needs HIDE_OVERLAY_WINDOWS, a normal permission both apps declare.
            window.setHideOverlayWindows(true)
        } else {
            // Only where overlays cannot be hidden: it would also drop
            // touches near the system bars.
            root.filterTouchesWhenObscured = true
        }
        root.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            root.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)
        }
        // The recents thumbnail is a screenshot the system keeps on disk,
        // outside the app's data and so outside the browser's wipe.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) activity.setRecentsScreenshotEnabled(false)
    }
}
