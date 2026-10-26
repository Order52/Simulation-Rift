package org.simulationrift.browser

import android.content.Context
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature

/** Whether browsing may start in this process, and the facts behind the answer. */
data class SandboxReport(val verified: Boolean, val detail: String)

/**
 * The renderer-sandbox precondition (§8.4, INV-7), evaluated in `:web`
 * after the data-directory suffix is set: loading the WebView provider any
 * earlier would make the suffix impossible to set.
 */
object WebViewSandbox {
    /**
     * Chromium 100 (March 2022). Below it a device has missed years of
     * renderer fixes. This floor is a release parameter: the release process
     * must raise it as WebView moves on.
     */
    const val MIN_WEBVIEW_MAJOR = 100

    data class Facts(val packageName: String?, val versionName: String?, val multiProcessSupported: Boolean, val multiProcessEnabled: Boolean)

    fun facts(context: Context): Facts {
        val pkg = WebViewCompat.getCurrentWebViewPackage(context)
        val supported = WebViewFeature.isFeatureSupported(WebViewFeature.MULTI_PROCESS)
        return Facts(pkg?.packageName, pkg?.versionName, supported, supported && WebViewCompat.isMultiProcessEnabled())
    }

    /**
     * Why a WebView that lacks fixes for bugs exploited in the wild is
     * refused, or null. An engine bug that attackers already use is the
     * likeliest way out of a page, so Rift does not open links in one.
     */
    private fun exploited(versionName: String): String? {
        val missing = KnownExploited.missing(versionName) ?: return "the WebView version cannot be determined"
        val newest = missing.lastOrNull() ?: return null
        val bugs = if (missing.size == 1) "a bug" else "${missing.size} bugs"
        return "this WebView lacks the fix for $bugs exploited in the wild (newest ${newest.cve}, fixed in ${newest.fixedIn}): " +
            "update Android System WebView (on Huawei phones, Huawei WebView) and open the link again"
    }

    /**
     * Pure, so every refusal path can be tested without a special device.
     * `allowOutdated` (debug builds only) lets a WebView that lacks exploited
     * fixes through, saying so in the detail; nothing else is relaxed.
     */
    fun evaluate(facts: Facts, allowOutdated: Boolean = false): SandboxReport {
        val major = facts.versionName?.substringBefore('.')?.toIntOrNull()
        val exploited = facts.versionName?.let(::exploited)
        val provider = "${facts.packageName ?: "unknown provider"} ${facts.versionName ?: "unknown version"}"
        val problem = when {
            facts.packageName == null || major == null -> "the WebView version cannot be determined"
            major < MIN_WEBVIEW_MAJOR -> "WebView $major is older than the minimum, $MIN_WEBVIEW_MAJOR"
            exploited != null && !allowOutdated -> exploited
            !facts.multiProcessSupported -> "this WebView cannot report whether its renderer is sandboxed"
            !facts.multiProcessEnabled -> "the WebView renderer is not running in a separate sandboxed process"
            else -> null
        }
        return if (problem == null) {
            val outdated = exploited?.let { "; debug build, allowed although $it" } ?: ""
            SandboxReport(true, "$provider; renderer in a separate process$outdated")
        } else {
            SandboxReport(false, "$provider; $problem")
        }
    }
}
