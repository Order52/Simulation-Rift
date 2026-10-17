package org.simulationrift.poc

import android.app.Activity
import android.app.Application
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.webkit.ConsoleMessage
import android.webkit.CookieManager
import android.webkit.GeolocationPermissions
import android.webkit.PermissionRequest
import android.webkit.RenderProcessGoneDetail
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.webkit.WebSettingsCompat
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.concurrent.Executors

/**
 * Hosts WebView in the `:browser` process with the hardening from
 * docs/architecture.md §8.4. Test pages report through `console.log`
 * ("RIFTPOC:key=value"), so no JavaScript bridge is ever needed.
 */
class BrowserActivity : Activity() {

    private lateinit var webView: WebView
    private val log = StringBuilder()
    private val main = Handler(Looper.getMainLooper())
    private val io = Executors.newSingleThreadExecutor()
    private var resultName = "browser"
    private var finished = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val test = intent.getStringExtra("test") ?: "a1"
        resultName = test + (intent.getStringExtra("label")?.let { "-$it" } ?: "")

        webView = WebView(this)
        setContentView(webView)
        harden(webView.settings)
        recordEnvironment()
        webView.webViewClient = Client()
        webView.webChromeClient = Chrome()
        webView.setDownloadListener { url, userAgent, disposition, mime, length ->
            onDownload(url, userAgent, disposition, mime, length)
        }

        when (test) {
            "a1" -> webView.loadUrl("$FIXTURE_ORIGIN/a1.html")
            "a2-seed" -> webView.loadUrl("$FIXTURE_ORIGIN/a2-seed.html")
            "a2-probe" -> webView.loadUrl("$FIXTURE_ORIGIN/a2-probe.html")
            "a3" -> DownloadCases().start()
            else -> finishTest("error=unknown test $test")
        }
        // Hard deadline so a hung page never blocks the host script.
        main.postDelayed({ finishTest("error=deadline reached") }, 45_000)
    }

    private fun harden(settings: WebSettings) {
        settings.javaScriptEnabled = true
        settings.domStorageEnabled = true
        settings.allowFileAccess = false
        settings.allowContentAccess = false
        settings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
        settings.setSupportMultipleWindows(false)
        settings.javaScriptCanOpenWindowsAutomatically = false
        settings.setGeolocationEnabled(false)
    }

    private fun recordEnvironment() {
        val pkg = WebViewCompat.getCurrentWebViewPackage(this)
        record("webview.package=${pkg?.packageName} ${pkg?.versionName}")
        val multiProcess = if (WebViewFeature.isFeatureSupported(WebViewFeature.MULTI_PROCESS)) {
            WebViewCompat.isMultiProcessEnabled().toString()
        } else {
            "feature-unsupported"
        }
        record("webview.multiprocess=$multiProcess")
        if (WebViewFeature.isFeatureSupported(WebViewFeature.SAFE_BROWSING_ENABLE)) {
            record("webview.safe_browsing=${WebSettingsCompat.getSafeBrowsingEnabled(webView.settings)}")
        }
        record("webview.multi_profile_feature=${WebViewFeature.isFeatureSupported(WebViewFeature.MULTI_PROFILE)}")
        record("webview.proxy_override_feature=${WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)}")
        record("host.process=${Application.getProcessName()} uid=${Process.myUid()} pid=${Process.myPid()}")
        record("host.generation=${Generation.read(this)}")
        main.postDelayed({
            val renderer = WebViewCompat.getWebViewRenderProcess(webView)
            record("webview.renderer_handle=${if (renderer != null) "present" else "absent"}")
        }, 1500)
    }

    @Synchronized
    private fun record(line: String) {
        log.appendLine(line)
    }

    private fun finishTest(extra: String? = null) {
        if (finished) return
        finished = true
        extra?.let(::record)
        Results.write(this, resultName, log.toString())
        CookieManager.getInstance().flush()
        finish()
    }

    private inner class Client : WebViewClient() {
        override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
            val scheme = request.url.scheme
            val blocked = scheme != "http" && scheme != "https"
            if (blocked) record("navigation.blocked=${request.url}")
            return blocked
        }

        override fun onRenderProcessGone(view: WebView, detail: RenderProcessGoneDetail): Boolean {
            record("renderer.gone crashed=${detail.didCrash()}")
            finishTest()
            return true // the app survives; the session ends (INV-7)
        }
    }

    private inner class Chrome : WebChromeClient() {
        override fun onPermissionRequest(request: PermissionRequest) {
            record("permission.requested=${request.resources.joinToString(",")}")
            request.deny()
        }

        override fun onGeolocationPermissionsShowPrompt(origin: String, callback: GeolocationPermissions.Callback) {
            record("geolocation.prompt=$origin")
            callback.invoke(origin, false, false)
        }

        override fun onConsoleMessage(message: ConsoleMessage): Boolean {
            val text = message.message()
            if (!text.startsWith("RIFTPOC:")) return true
            val body = text.removePrefix("RIFTPOC:")
            if (body == "DONE") main.post { finishTest() } else record("page.$body")
            return true
        }
    }

    // ---- A3: download capture -------------------------------------------------

    private var onDownloadObserved: ((String) -> Unit)? = null

    private fun onDownload(url: String, userAgent: String, disposition: String?, mime: String?, length: Long) {
        val observer = onDownloadObserved
        io.execute {
            val outcome = refetch(url, userAgent)
            val line = "listener url=${url.take(80)} mime=$mime length=$length disposition=$disposition " +
                "display_name=${displayName(disposition, url)} refetch=$outcome"
            main.post { observer?.invoke(line) }
        }
    }

    /** Re-fetches with only this URL's cookies, as the core would (§8.5). */
    private fun refetch(url: String, userAgent: String): String {
        if (!url.startsWith("http://") && !url.startsWith("https://")) return "UNSUPPORTED scheme"
        return try {
            val connection = URL(url).openConnection() as HttpURLConnection
            connection.instanceFollowRedirects = true
            connection.setRequestProperty("User-Agent", userAgent)
            CookieManager.getInstance().getCookie(url)?.let { connection.setRequestProperty("Cookie", it) }
            val code = connection.responseCode
            if (code != 200) return "HTTP $code"
            val digest = MessageDigest.getInstance("SHA-256")
            connection.inputStream.use { stream ->
                val buffer = ByteArray(8192)
                while (true) {
                    val n = stream.read(buffer)
                    if (n < 0) break
                    digest.update(buffer, 0, n)
                }
            }
            "OK sha256=" + digest.digest().joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            "FAILED ${e.javaClass.simpleName}: ${e.message}"
        }
    }

    /** Server-supplied names are display metadata only: strip paths and controls. */
    private fun displayName(disposition: String?, url: String): String {
        val raw = disposition?.substringAfter("filename=", "")?.trim('"', ' ')?.takeIf { it.isNotEmpty() }
            ?: url.substringAfterLast('/').substringBefore('?')
        return raw.substringAfterLast('/').substringAfterLast('\\')
            .filter { !it.isISOControl() && it !in "‪‫‬‭‮" }
            .take(120)
            .ifEmpty { "download" }
    }

    /** Navigates through each case and records what the listener saw. */
    private inner class DownloadCases {
        private val cases = listOf(
            "plain_get" to "$FIXTURE_ORIGIN/files/plain.bin",
            "content_disposition" to "$FIXTURE_ORIGIN/files/disposition",
            "redirect" to "$FIXTURE_ORIGIN/redirect",
            "cookie_gated" to "$FIXTURE_ORIGIN/login?next=/files/private.bin",
            "post_form" to "$FIXTURE_ORIGIN/a3-post.html",
            "blob" to "$FIXTURE_ORIGIN/a3-blob.html",
            "data_url" to "$FIXTURE_ORIGIN/a3-data.html",
        )
        private var index = 0

        fun start() = next()

        private fun next() {
            if (index >= cases.size) {
                finishTest()
                return
            }
            val (name, url) = cases[index++]
            var done = false
            onDownloadObserved = { line ->
                if (!done) {
                    done = true
                    record("case.$name $line")
                    main.postDelayed(::next, 300)
                }
            }
            main.postDelayed({
                if (!done) {
                    done = true
                    record("case.$name listener=NOT_CALLED")
                    next()
                }
            }, 5_000)
            webView.loadUrl(url)
        }
    }
}
