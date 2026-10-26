package org.simulationrift.browser

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** S15: every refusal path of the renderer-sandbox precondition (INV-7). */
class WebViewSandboxTest {
    private val good = WebViewSandbox.Facts("com.google.android.webview", KnownExploited.bugs.last().fixedIn, true, true)

    @Test
    fun aCurrentMultiProcessWebViewIsAccepted() {
        assertTrue(WebViewSandbox.evaluate(good).verified)
        assertTrue(WebViewSandbox.evaluate(good.copy(versionName = "999.0.1.0")).verified)
    }

    @Test
    fun everythingElseIsRefused() {
        for (bad in listOf(
            good.copy(multiProcessEnabled = false),
            good.copy(multiProcessSupported = false, multiProcessEnabled = false),
            good.copy(versionName = "91.0.4472.114"),
            good.copy(versionName = "garbage"),
            good.copy(versionName = "153"),
            good.copy(packageName = null, versionName = null),
        )) {
            assertFalse("$bad", WebViewSandbox.evaluate(bad).verified)
        }
    }

    /** S15b: a WebView without the fix for a bug exploited in the wild is refused, and the refusal names the newest one. */
    @Test
    fun aWebViewMissingAnExploitedFixIsRefused() {
        for (version in listOf("113.0.5672.136", "114.0.5735.196", "152.0.7977.140", "153.0.8010.35")) {
            val report = WebViewSandbox.evaluate(good.copy(versionName = version))
            assertFalse(version, report.verified)
            assertTrue(report.detail, report.detail.contains("CVE-2026-87491") && report.detail.contains("exploited in the wild"))
        }
    }

    /** The debug allowance relaxes only the exploited-fix check, and says so. */
    @Test
    fun aDebugBuildMayBrowseInAnOutdatedWebViewButNothingElse() {
        val outdated = good.copy(versionName = "113.0.5672.136")
        val allowed = WebViewSandbox.evaluate(outdated, allowOutdated = true)
        assertTrue(allowed.verified)
        assertTrue(allowed.detail, allowed.detail.contains("debug build") && allowed.detail.contains("CVE-2026-87491"))
        assertFalse(WebViewSandbox.evaluate(outdated.copy(multiProcessEnabled = false), allowOutdated = true).verified)
        assertFalse(WebViewSandbox.evaluate(good.copy(versionName = "91.0.4472.114"), allowOutdated = true).verified)
        assertFalse(WebViewSandbox.evaluate(good.copy(versionName = "garbage"), allowOutdated = true).verified)
    }

    @Test
    fun versionsCompareByNumberNotText() {
        assertEquals(listOf("CVE-2026-87491"), KnownExploited.missing("152.0.7977.82")?.map { it.cve })
        assertEquals(emptyList<KnownExploited.Bug>(), KnownExploited.missing("153.0.8010.36"))
        assertEquals(emptyList<KnownExploited.Bug>(), KnownExploited.missing("153.0.8010.100-huawei"))
        assertEquals(KnownExploited.bugs.size, KnownExploited.missing("99.0.9999.9999")?.size)
        assertNull(KnownExploited.missing("153.0.8010"))
    }
}
