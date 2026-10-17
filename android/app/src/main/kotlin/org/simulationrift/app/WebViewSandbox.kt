package org.simulationrift.app

import android.content.Context
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature

/** Whether browsing may start in this process, and the facts behind the answer. */
data class SandboxReport(val verified: Boolean, val detail: String)

/**
 * The renderer-sandbox precondition (§8.4, INV-7), evaluated in `:browser`
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

    /** Pure, so every refusal path can be tested without a special device. */
    fun evaluate(facts: Facts): SandboxReport {
        val major = facts.versionName?.substringBefore('.')?.toIntOrNull()
        val provider = "${facts.packageName ?: "unknown provider"} ${facts.versionName ?: "unknown version"}"
        val problem = when {
            facts.packageName == null || major == null -> "the WebView version cannot be determined"
            major < MIN_WEBVIEW_MAJOR -> "WebView $major is older than the minimum, $MIN_WEBVIEW_MAJOR"
            !facts.multiProcessSupported -> "this WebView cannot report whether its renderer is sandboxed"
            !facts.multiProcessEnabled -> "the WebView renderer is not running in a separate sandboxed process"
            else -> null
        }
        return if (problem == null) {
            SandboxReport(true, "$provider; renderer in a separate process")
        } else {
            SandboxReport(false, "$provider; $problem")
        }
    }
}
