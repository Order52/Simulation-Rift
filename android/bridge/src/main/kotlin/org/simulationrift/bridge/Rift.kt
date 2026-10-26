package org.simulationrift.bridge

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.os.Binder
import android.os.Process

/**
 * The two apps (§8.2, ADR-04). The controller holds everything trusted; the
 * browser holds only the WebView host and its session service, under its
 * own UID. Both are signed with the same key and define [PERMISSION].
 */
object Rift {
    const val CONTROLLER_PACKAGE = "org.simulationrift.app"
    const val BROWSER_PACKAGE = "org.simulationrift.browser"

    /** A `signature` permission: only apps signed with Rift's key can hold it. */
    const val PERMISSION = "org.simulationrift.permission.RIFT"

    val BROWSER_ACTIVITY = ComponentName(BROWSER_PACKAGE, "$BROWSER_PACKAGE.BrowserActivity")
    val SESSION_SERVICE = ComponentName(BROWSER_PACKAGE, "$BROWSER_PACKAGE.SessionService")
    /** Starts the browser's default process where the system will not start it for a binding. */
    val WAKE_ACTIVITY = ComponentName(BROWSER_PACKAGE, "$BROWSER_PACKAGE.WakeActivity")
    val CORE_SERVICE = ComponentName(CONTROLLER_PACKAGE, "$CONTROLLER_PACKAGE.CoreService")

    /** The browser's WebView process: the one an engine escape reaches (§8.3). */
    const val WEB_PROCESS = "$BROWSER_PACKAGE:web"

    const val EXTRA_GENERATION = "org.simulationrift.GENERATION"
    const val EXTRA_URL = "org.simulationrift.URL"
    /** The window test-opens its link (§10.11): the page is covered until the user chooses to see it. */
    const val EXTRA_TEST_OPEN = "org.simulationrift.TEST_OPEN"

    /** The egress proxy listens here (§8.8); only this host's challenge is answered. */
    const val PROXY_HOST = "127.0.0.1"
    const val PROXY_USER = "rift"

    /**
     * Throws unless the current Binder caller is [expectedPackage] and is
     * signed with this app's key. The services also require [PERMISSION];
     * this repeats the check on every call, by identity rather than by
     * permission, so that a component exported by mistake still refuses
     * every other app.
     */
    /** Callers [requireCallerFast] has verified, by UID, with the time (elapsedRealtime) their check holds until. */
    private val verifiedCallers = java.util.concurrent.ConcurrentHashMap<Int, Long>()

    /**
     * [requireCaller] for calls that come hundreds of times for a page (the content filters'): two
     * PackageManager round trips per call cost more than the answer. A caller that passed is
     * accepted again for [FAST_CHECK_MS] without them; a failure is never kept, and the UID the
     * call comes from is the kernel's, so only a reinstall of the browser app inside that window
     * could differ (the control calls still check every time).
     */
    fun requireCallerFast(context: Context, expectedPackage: String) {
        val caller = Binder.getCallingUid()
        val now = android.os.SystemClock.elapsedRealtime()
        if ((verifiedCallers[caller] ?: 0L) > now) return
        requireCaller(context, expectedPackage)
        verifiedCallers[caller] = now + FAST_CHECK_MS
    }

    private const val FAST_CHECK_MS = 5_000L

    fun requireCaller(context: Context, expectedPackage: String) {
        val caller = Binder.getCallingUid()
        val packages = context.packageManager
        val expected = try {
            packages.getPackageUid(expectedPackage, 0)
        } catch (e: PackageManager.NameNotFoundException) {
            throw SecurityException("$expectedPackage is not installed")
        }
        if (caller != expected) throw SecurityException("caller $caller is not $expectedPackage")
        if (packages.checkSignatures(Process.myUid(), caller) != PackageManager.SIGNATURE_MATCH) {
            throw SecurityException("caller $caller is not signed with this app's key")
        }
    }
}
