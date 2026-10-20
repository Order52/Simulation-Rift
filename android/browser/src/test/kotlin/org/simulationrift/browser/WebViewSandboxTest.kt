package org.simulationrift.browser

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** S15: every refusal path of the renderer-sandbox precondition (INV-7). */
class WebViewSandboxTest {
    private val good = WebViewSandbox.Facts("com.google.android.webview", "133.0.6943.137", true, true)

    @Test
    fun aCurrentMultiProcessWebViewIsAccepted() {
        assertTrue(WebViewSandbox.evaluate(good).verified)
    }

    @Test
    fun everythingElseIsRefused() {
        for (bad in listOf(
            good.copy(multiProcessEnabled = false),
            good.copy(multiProcessSupported = false, multiProcessEnabled = false),
            good.copy(versionName = "91.0.4472.114"),
            good.copy(versionName = "garbage"),
            good.copy(packageName = null, versionName = null),
        )) {
            assertFalse("$bad", WebViewSandbox.evaluate(bad).verified)
        }
    }
}
