package org.simulationrift.app

import android.annotation.SuppressLint
import android.app.Application
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.graphics.Bitmap
import android.net.http.SslError
import android.os.Bundle
import android.os.IBinder
import android.os.Process
import android.os.RemoteException
import android.util.Log
import android.view.View
import android.webkit.CookieManager
import android.webkit.GeolocationPermissions
import android.webkit.PermissionRequest
import android.webkit.RenderProcessGoneDetail
import android.webkit.SslErrorHandler
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.webkit.WebSettingsCompat
import androidx.webkit.WebViewFeature
import androidx.webkit.WebViewMediaIntegrityApiStatusConfig
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * The browser host in the `:browser` process (§8.3, §8.4, §10). It never
 * loads the Rust library and holds no keys: decisions come from the core
 * over [ICore], tagged with this window's session generation.
 */
class BrowserActivity : ComponentActivity() {

    private sealed interface Screen {
        data object Connecting : Screen
        data class Unsupported(val detail: String) : Screen
        data object Page : Screen
        data class Interstitial(val url: String, val displayUrl: String, val reasons: List<Fact>) : Screen
        data class Blocked(val displayUrl: String, val reason: Fact) : Screen
        data class Ended(val message: String) : Screen
    }

    private var generation = 0L
    private var core: ICore? = null
    private var webView: WebView? = null
    private var bound = false
    private var shuttingDown = false

    private var screen by mutableStateOf<Screen>(Screen.Connecting)
    private var address by mutableStateOf("")
    private var notes by mutableStateOf<List<Fact>>(emptyList())
    private var canGoBack by mutableStateOf(false)
    private var canGoForward by mutableStateOf(false)
    private var status by mutableStateOf<String?>(null)

    private val browserBinder = object : IBrowser.Stub() {
        /** Returns once finish() has run, so the activity is not restored after the kill. */
        override fun shutdown() {
            val finished = CountDownLatch(1)
            runOnUiThread {
                shuttingDown = true
                finish()
                finished.countDown()
            }
            finished.await(SHUTDOWN_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        }
    }

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, service: IBinder) = onCoreConnected(service)

        // Without the core nothing can be decided: fail closed by exiting.
        override fun onServiceDisconnected(name: ComponentName) = exitProcess("core disconnected")
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        check(Application.getProcessName().endsWith(AndroidBrowserDisposal.BROWSER_PROCESS_SUFFIX)) {
            "BrowserActivity must run in the :browser process"
        }
        generation = intent.getLongExtra(EXTRA_GENERATION, 0)
        val processGen = processGeneration
        if (generation <= 0 || (processGen != null && processGen != generation)) {
            // This process's WebView already uses another generation's directory.
            Log.w(TAG, "refusing generation $generation in a process bound to $processGen")
            finish()
            if (processGen != null) exitProcess("stale browser process")
            return
        }
        setContent { MaterialTheme { BrowserScreen() } }
        bound = bindService(Intent(this, CoreService::class.java), connection, Context.BIND_AUTO_CREATE)
        if (!bound) screen = Screen.Ended("The protection core is unavailable.")
    }

    /** A link for this window: same generation only (a new one gets a new process). */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (intent.getLongExtra(EXTRA_GENERATION, 0) != generation) {
            finish()
            return
        }
        val url = intent.getStringExtra(EXTRA_URL) ?: return
        if (webView != null) openTyped(url) else setIntent(intent)
    }

    private fun onCoreConnected(service: IBinder) {
        val connected = ICore.Stub.asInterface(service)
        val accepted = try {
            service.linkToDeath({ exitProcess("core died") }, 0)
            connected.register(generation, browserBinder)
        } catch (e: RemoteException) {
            Log.w(TAG, "core unreachable", e)
            false
        }
        if (!accepted) {
            // Not the current session: leave without touching WebView, so a
            // disposed generation's data directory is never recreated.
            finish()
            return
        }
        core = connected
        startEngine(connected)
    }

    private fun startEngine(connected: ICore) {
        if (processGeneration == null) {
            // Before any other WebView call in this process (§8.4).
            WebView.setDataDirectorySuffix("s$generation")
            processGeneration = generation
        }
        val report = WebViewSandbox.evaluate(WebViewSandbox.facts(this))
        try {
            connected.reportSandbox(generation, report.verified, report.detail)
        } catch (e: RemoteException) {
            exitProcess("core unreachable")
            return
        }
        if (!report.verified) {
            screen = Screen.Unsupported(report.detail)
            return
        }
        webView = createWebView()
        screen = Screen.Page
        intent.getStringExtra(EXTRA_URL)?.let(::openTyped)
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun createWebView(): WebView = WebView(this).apply {
        settings.apply {
            javaScriptEnabled = true // sites need it; no bridge is ever added (INV-6)
            domStorageEnabled = true
            allowFileAccess = false
            allowContentAccess = false
            mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
            setSupportMultipleWindows(false)
            javaScriptCanOpenWindowsAutomatically = false
            setGeolocationEnabled(false)
        }
        // WebView gives every page window.android.webview, a Media Integrity
        // API that asks Google Play for a device attestation (found by S1).
        // Pages get no device identity from Rift.
        if (WebViewFeature.isFeatureSupported(WebViewFeature.WEBVIEW_MEDIA_INTEGRITY_API_STATUS)) {
            WebSettingsCompat.setWebViewMediaIntegrityApiStatus(
                settings,
                WebViewMediaIntegrityApiStatusConfig.Builder(WebViewMediaIntegrityApiStatusConfig.WEBVIEW_MEDIA_INTEGRITY_API_DISABLED).build(),
            )
        }
        webViewClient = Client()
        webChromeClient = Chrome()
        // The engine only reports the download; the core fetches it again
        // into encrypted quarantine (§8.5). Downloads generated inside the
        // page (blob:, data:) never reach this listener (PoC A3).
        setDownloadListener { url, userAgent, contentDisposition, _, _ ->
            submitDownload(url, userAgent, contentDisposition)
        }
    }

    private fun submitDownload(url: String, userAgent: String, contentDisposition: String?) {
        val cookie = CookieManager.getInstance().getCookie(url)
        try {
            core?.submitDownload(generation, url, cookie, userAgent, webView?.url, contentDisposition)
            status = "Download sent to Rift's quarantine; see the home screen."
        } catch (e: RemoteException) {
            exitProcess("core unreachable")
        }
    }

    // ---- Navigation ------------------------------------------------------------

    private fun decide(url: String): NavigationDecision = NavigationDecision.fromBundle(
        try {
            core?.decide(generation, url)
        } catch (e: RemoteException) {
            null // decodes as a block
        },
    )

    private fun openTyped(input: String) {
        val url = try {
            core?.typedAddress(input)
        } catch (e: RemoteException) {
            null
        } ?: return
        when (val d = decide(url)) {
            is NavigationDecision.Proceed -> load(url, d.notes)
            else -> show(url, d)
        }
    }

    private fun load(url: String, decisionNotes: List<Fact>) {
        notes = decisionNotes
        screen = Screen.Page
        webView?.loadUrl(url)
    }

    private fun show(url: String, decision: NavigationDecision) {
        address = url
        screen = when (decision) {
            is NavigationDecision.Proceed -> Screen.Page
            is NavigationDecision.Confirm -> Screen.Interstitial(url, decision.displayUrl, decision.reasons)
            is NavigationDecision.Block -> Screen.Blocked(decision.displayUrl, decision.reason)
        }
    }

    private inner class Client : WebViewClient() {
        override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
            // Subframes and subresources are not checked (§10.3).
            if (!request.isForMainFrame) return false
            val url = request.url.toString()
            return when (val d = decide(url)) {
                is NavigationDecision.Proceed -> {
                    notes = d.notes
                    false
                }
                else -> {
                    show(url, d)
                    true
                }
            }
        }

        override fun onPageStarted(view: WebView, url: String, favicon: Bitmap?) {
            address = url
        }

        override fun doUpdateVisitedHistory(view: WebView, url: String, isReload: Boolean) {
            address = url
            canGoBack = view.canGoBack()
            canGoForward = view.canGoForward()
        }

        // No click-through for certificate errors in V1 (§10.2).
        override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) = handler.cancel()

        override fun onRenderProcessGone(view: WebView, detail: RenderProcessGoneDetail): Boolean {
            // The app survives; the session ends (INV-7).
            webView = null
            view.destroy()
            screen = Screen.Ended("The page's renderer stopped, so this session has ended.")
            try {
                core?.rendererGone(generation, detail.didCrash())
            } catch (e: RemoteException) {
                exitProcess("core unreachable")
            }
            return true
        }
    }

    private class Chrome : WebChromeClient() {
        // Camera, microphone, MIDI, protected media: always denied (B4).
        override fun onPermissionRequest(request: PermissionRequest) = request.deny()

        override fun onGeolocationPermissionsShowPrompt(origin: String, callback: GeolocationPermissions.Callback) =
            callback.invoke(origin, false, false)

        // The per-session file-chooser toggle is not built yet, so uploads are denied.
        override fun onShowFileChooser(
            webView: WebView,
            filePathCallback: ValueCallback<Array<android.net.Uri>>,
            fileChooserParams: FileChooserParams,
        ): Boolean = false

        // Fullscreen would cover the trusted indicator (INV-6), so it is refused.
        override fun onShowCustomView(view: View, callback: CustomViewCallback) = callback.onCustomViewHidden()
    }

    // ---- Lifecycle -------------------------------------------------------------

    private fun requestReset() {
        try {
            core?.requestReset(generation)
        } catch (e: RemoteException) {
            exitProcess("core unreachable")
        }
    }

    override fun onDestroy() {
        webView?.destroy()
        webView = null
        if (bound) unbindService(connection)
        bound = false
        super.onDestroy()
        if (shuttingDown) exitProcess("session ended")
    }

    private fun exitProcess(why: String) {
        Log.i(TAG, "browser process exiting: $why")
        Process.killProcess(Process.myPid())
    }

    // ---- Trusted UI ------------------------------------------------------------

    @Composable
    private fun BrowserScreen() {
        BackHandler(enabled = screen is Screen.Page && canGoBack) { webView?.goBack() }
        // Test tags double as resource ids so UI tests can find trusted controls.
        Surface(Modifier.fillMaxSize().semantics { testTagsAsResourceId = true }) {
            Column(Modifier.fillMaxSize().safeDrawingPadding()) {
                TrustedBar()
                Box(Modifier.fillMaxWidth().weight(1f)) {
                    webView?.let { view -> AndroidView(factory = { view }, modifier = Modifier.fillMaxSize()) }
                    when (val s = screen) {
                        Screen.Page -> {}
                        Screen.Connecting -> Message("Connecting to the protection core…")
                        is Screen.Unsupported -> Message(
                            "Unsupported device configuration",
                            "Browsing is refused because the browser engine's sandbox could not be confirmed: ${s.detail}.",
                        )
                        is Screen.Interstitial -> Interstitial(s)
                        is Screen.Blocked -> Message("Page blocked", s.reason.text, s.displayUrl)
                        is Screen.Ended -> Message("Session ended", s.message)
                    }
                }
            }
        }
    }

    @Composable
    private fun TrustedBar() {
        var typed by androidx.compose.runtime.remember { mutableStateOf("") }
        Column(Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surfaceVariant).padding(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AssistChip(onClick = {}, label = { Text("Session $generation") }, modifier = Modifier.testTag("session-chip"))
                Text(protectionSummary(), style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f).testTag("protection"))
                TextButton(onClick = ::requestReset, modifier = Modifier.testTag("reset")) { Text("Reset") }
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                TextButton(onClick = { webView?.goBack() }, enabled = canGoBack) { Text("◀") }
                TextButton(onClick = { webView?.goForward() }, enabled = canGoForward) { Text("▶") }
                TextButton(onClick = { webView?.reload() }, enabled = webView != null) { Text("↻") }
                OutlinedTextField(
                    value = typed,
                    onValueChange = { typed = it },
                    placeholder = { Text(address.ifEmpty { "Address" }, maxLines = 1) },
                    singleLine = true,
                    enabled = webView != null,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, imeAction = ImeAction.Go),
                    keyboardActions = KeyboardActions(onGo = {
                        openTyped(typed)
                        typed = ""
                    }),
                    modifier = Modifier.weight(1f).testTag("address"),
                )
            }
            status?.let { Text(it, style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("status")) }
        }
    }

    private fun protectionSummary(): String {
        val warnings = notes.filter { it.code != "intel-missing" && it.code != "intel-stale" }
        val intel = when {
            notes.any { it.code == "intel-missing" } -> "no threat database"
            notes.any { it.code == "intel-stale" } -> "threat database out of date"
            else -> "threat database current"
        }
        // Never a green "safe": at most "not flagged" (§10.4).
        return if (warnings.isEmpty()) "Not flagged · $intel" else warnings.joinToString(" ") { it.text } + " · $intel"
    }

    @Composable
    private fun Interstitial(s: Screen.Interstitial) {
        Surface(Modifier.fillMaxSize().testTag("interstitial"), color = MaterialTheme.colorScheme.errorContainer) {
            Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("This address may not be what it seems", style = MaterialTheme.typography.headlineSmall)
                Text(s.displayUrl, style = MaterialTheme.typography.bodySmall)
                s.reasons.forEach { Text("• ${it.text}") }
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Button(onClick = { screen = Screen.Page }, modifier = Modifier.testTag("go-back")) { Text("Go back") }
                    OutlinedButton(onClick = { load(s.url, emptyList()) }, modifier = Modifier.testTag("continue")) {
                        Text("Continue anyway")
                    }
                }
            }
        }
    }

    @Composable
    private fun Message(title: String, body: String? = null, url: String? = null) {
        Surface(Modifier.fillMaxSize().testTag("message"), color = MaterialTheme.colorScheme.surface) {
            Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(title, style = MaterialTheme.typography.headlineSmall)
                body?.let { Text(it) }
                url?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            }
        }
    }

    companion object {
        const val EXTRA_GENERATION = "org.simulationrift.app.GENERATION"
        const val EXTRA_URL = "org.simulationrift.app.URL"
        private const val SHUTDOWN_TIMEOUT_MS = 1_000L

        /** The generation whose WebView data directory this process uses; fixed once set. */
        @Volatile private var processGeneration: Long? = null
    }
}
