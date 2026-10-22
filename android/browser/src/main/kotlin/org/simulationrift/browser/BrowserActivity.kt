package org.simulationrift.browser

import android.annotation.SuppressLint
import android.app.Application
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.graphics.Bitmap
import android.net.ConnectivityManager
import android.net.http.SslError
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Process
import android.os.SystemClock
import android.os.RemoteException
import android.util.Log
import android.util.SparseArray
import android.view.View
import android.view.ViewGroup
import android.view.ViewStructure
import android.view.autofill.AutofillValue
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import android.webkit.CookieManager
import android.webkit.GeolocationPermissions
import android.webkit.HttpAuthHandler
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
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.verticalScroll
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
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.zIndex
import androidx.compose.ui.viewinterop.AndroidView
import androidx.webkit.WebSettingsCompat
import androidx.webkit.WebViewFeature
import androidx.webkit.WebViewMediaIntegrityApiStatusConfig
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.simulationrift.bridge.Fact
import org.simulationrift.bridge.IBrowser
import org.simulationrift.bridge.ICore
import org.simulationrift.bridge.NavigationDecision
import org.simulationrift.bridge.NetworkMode
import org.simulationrift.bridge.PageWatch
import org.simulationrift.bridge.Rift
import org.simulationrift.bridge.SessionGrant
import org.simulationrift.bridge.WindowGuard

/**
 * The browser host in the browser app's `:web` process (§8.3, §8.4, §10).
 * It runs under a UID that owns nothing of Rift's, never loads the Rust
 * library and holds no keys: decisions come from the controller's core over
 * [ICore], tagged with this window's session generation, and every request
 * the engine makes goes to the controller's egress proxy (§8.8).
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
    private var grant: SessionGrant.Granted? = null
    private var lockWatch: ConnectivityManager.NetworkCallback? = null
    private var webView: WebView? = null
    private var bound = false
    private var shuttingDown = false

    private var screen by mutableStateOf<Screen>(Screen.Connecting)
    private var address by mutableStateOf("")
    /** The core's notes for the page shown; null until the core has decided on one. */
    private var notes by mutableStateOf<List<Fact>?>(null)
    private var canGoBack by mutableStateOf(false)
    private var canGoForward by mutableStateOf(false)
    private var status by mutableStateOf<String?>(null)
    /** The core's live watch of this session (§10.5); null until it answers, or if it cannot. */
    private var watch by mutableStateOf<PageWatch?>(null)
    private var watchAnswered by mutableStateOf(false)
    private var watchOpen by mutableStateOf(false)
    private val polling = Handler(Looper.getMainLooper())
    // Off the UI thread: a reset holds the session while it shuts this window down.
    private val watchReader = Executors.newSingleThreadExecutor { Thread(it, "rift-watch") }
    private val poll = object : Runnable {
        override fun run() {
            core?.let { connected -> watchReader.execute { refreshWatch(connected) } }
            polling.postDelayed(this, WATCH_POLL_MS)
        }
    }
    /** When each kind of attempt from each origin was last reported, so a page cannot flood the core. */
    private val reported = HashMap<String, Long>()
    private val decoys by lazy { Decoys(this, ::reportDecoy) }

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
        check(Application.getProcessName() == Rift.WEB_PROCESS) { "BrowserActivity must run in ${Rift.WEB_PROCESS}" }
        // No overlays, autofill, non-tool accessibility services or recents snapshot.
        WindowGuard.apply(this)
        generation = intent.getLongExtra(Rift.EXTRA_GENERATION, 0)
        val processGen = processGeneration
        if (generation <= 0 || (processGen != null && processGen != generation)) {
            // This process's WebView already uses another generation's directory.
            Log.w(TAG, "refusing generation $generation in a process bound to $processGen")
            finish()
            if (processGen != null) exitProcess("stale browser process")
            return
        }
        setContent { RiftTheme { NoPersonalizedLearning { BrowserScreen() } } }
        bound = bindService(Intent().setComponent(Rift.CORE_SERVICE), connection, Context.BIND_AUTO_CREATE)
        if (!bound) screen = Screen.Ended("The protection core is unavailable.")
    }

    /** A link for this window: same generation only (a new one gets a new process). */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (intent.getLongExtra(Rift.EXTRA_GENERATION, 0) != generation) {
            finish()
            return
        }
        val url = intent.getStringExtra(Rift.EXTRA_URL) ?: return
        // No address in the log: it is browsing data.
        Log.i(TAG, "new link in generation $generation (engine ${if (webView != null) "running" else "starting"})")
        if (webView != null) openTyped(url) else setIntent(intent)
    }

    private fun onCoreConnected(service: IBinder) {
        val connected = ICore.Stub.asInterface(service)
        val answer = try {
            service.linkToDeath({ exitProcess("core died") }, 0)
            SessionGrant.fromBundle(connected.register(generation, browserBinder))
        } catch (e: RemoteException) {
            Log.w(TAG, "core unreachable", e)
            SessionGrant.Refused("The protection core is unavailable.")
        }
        when (answer) {
            // No browsing in this window. WebView is never touched, so a
            // disposed generation's data directory is never recreated.
            is SessionGrant.Refused -> screen = Screen.Ended(answer.reason)
            is SessionGrant.Granted -> {
                core = connected
                grant = answer
                startEngine(connected, answer)
            }
        }
    }

    private fun startEngine(connected: ICore, granted: SessionGrant.Granted) {
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
            screen = Screen.Unsupported("the browser engine's sandbox could not be confirmed (${report.detail})")
            return
        }
        // Before any WebView exists, so that no request leaves without the proxy (§8.8).
        NetworkLock.applyProxy(granted.proxyPort, mainExecutor) { problem -> onProxyApplied(connected, granted, problem) }
    }

    private fun onProxyApplied(connected: ICore, granted: SessionGrant.Granted, problem: String?) {
        if (isFinishing || isDestroyed) return
        val locked = NetworkLock.defaultIsVpn(this)
        val refusal = problem ?: "the network lock is not in effect for the browser".takeIf { granted.mode == NetworkMode.LOCKED && !locked }
        val detail = refusal ?: if (locked) "every request goes to Rift's proxy; the default network is the lock" else "every request goes to Rift's proxy; no network lock (reduced isolation)"
        try {
            connected.reportNetwork(generation, problem == null, locked, detail)
        } catch (e: RemoteException) {
            exitProcess("core unreachable")
            return
        }
        if (refusal != null) {
            screen = Screen.Unsupported(refusal)
            return
        }
        if (granted.mode == NetworkMode.LOCKED) {
            // The controller ends the session when it loses the lock (S28);
            // this stops the engine sooner, before any request goes direct.
            lockWatch = NetworkLock.watch(this) { exitProcess("network lock lost") }
        }
        webView = createWebView()
        screen = Screen.Page
        polling.removeCallbacks(poll)
        polling.post(poll)
        intent.getStringExtra(Rift.EXTRA_URL)?.let(::openTyped)
    }

    // ---- Live page watch (§10.5) --------------------------------------------------

    /** On [watchReader]; the answer is shown on the UI thread. */
    private fun refreshWatch(connected: ICore) {
        val answer = try {
            connected.pageWatch(generation)
        } catch (e: RemoteException) {
            exitProcess("core unreachable")
            return
        }
        val decoded = PageWatch.fromBundle(answer)
        runOnUiThread {
            watch = decoded
            watchAnswered = true
        }
    }

    /** Reports a refused attempt (one of [PageWatch.Attempt]); at most once per [ATTEMPT_REPORT_MS] per kind and origin. */
    private fun reportAttempt(kind: String, origin: String?) {
        val key = "$kind ${origin.orEmpty()}"
        val now = SystemClock.elapsedRealtime()
        if (reported[key]?.let { now - it < ATTEMPT_REPORT_MS } == true) return
        if (reported.size >= MAX_REPORTED) reported.clear()
        reported[key] = now
        try {
            core?.reportAttempt(generation, kind, origin.orEmpty())
        } catch (e: RemoteException) {
            exitProcess("core unreachable")
        }
    }

    /**
     * Reports a decoy given to a page (one of [PageWatch.Decoy]); throttled
     * like [reportAttempt], except the browser's own once-a-session reports.
     */
    private fun reportDecoy(kind: String, origin: String, detail: String) {
        if (kind != PageWatch.Decoy.ACTIVE && kind != PageWatch.Decoy.UNAVAILABLE) {
            val key = "$kind $origin"
            val now = SystemClock.elapsedRealtime()
            if (reported[key]?.let { now - it < ATTEMPT_REPORT_MS } == true) return
            if (reported.size >= MAX_REPORTED) reported.clear()
            reported[key] = now
        }
        try {
            core?.reportDecoy(generation, kind, origin, detail)
        } catch (e: RemoteException) {
            exitProcess("core unreachable")
        }
    }

    /**
     * Asks keyboards not to learn from what is typed into pages
     * (`IME_FLAG_NO_PERSONALIZED_LEARNING`), and keeps pages from autofill
     * services (§10.7): the engine still tells the system that a field was
     * focused, but describes no page to it and accepts no fill.
     */
    private class PrivateWebView(context: Context) : WebView(context) {
        override fun onCreateInputConnection(outAttrs: EditorInfo): InputConnection? =
            super.onCreateInputConnection(outAttrs).also {
                outAttrs.imeOptions = outAttrs.imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
            }

        override fun onProvideAutofillVirtualStructure(structure: ViewStructure, flags: Int) = Unit

        override fun autofill(values: SparseArray<AutofillValue>) = Unit
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun createWebView(): WebView = PrivateWebView(this).apply {
        // Without layout parameters AndroidView gives the view WRAP_CONTENT,
        // and in that mode WebView lays pages out at zero height: every
        // viewport unit (100vh) was 0 px, so pages sized by them collapsed
        // (found by H1).
        layoutParams = ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
        // Pages' forms go to no autofill service (§10.7): WindowGuard's
        // setting on the window does not reach the engine's virtual views.
        importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        settings.apply {
            // Sites need it. No Java object is ever exposed to pages (INV-6);
            // the decoys' report channel takes strings only (Decoys).
            javaScriptEnabled = true
            domStorageEnabled = true
            allowFileAccess = false
            allowContentAccess = false
            mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
            setSupportMultipleWindows(false)
            javaScriptCanOpenWindowsAutomatically = false
            // Only so that the engine asks Chrome below, which always says no
            // and reports the attempt (§10.5). The browser app holds no
            // location permission, so the OS refuses a location in any case.
            setGeolocationEnabled(true)
            // No form data kept or offered by the engine, and (with the
            // view's own setting above) no page form handed to autofill.
            @Suppress("DEPRECATION")
            saveFormData = false
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
        // Pages cannot register ad attribution with the system's Measurement
        // API, which keeps it outside the browser app's data, past the wipe.
        if (WebViewFeature.isFeatureSupported(WebViewFeature.ATTRIBUTION_REGISTRATION_BEHAVIOR)) {
            WebSettingsCompat.setAttributionRegistrationBehavior(settings, WebSettingsCompat.ATTRIBUTION_BEHAVIOR_DISABLED)
        }
        // A device policy could otherwise let sign-in links open another app,
        // past the core's block on automatic external-app links (§10.3).
        if (WebViewFeature.isFeatureSupported(WebViewFeature.ENTERPRISE_AUTHENTICATION_APP_LINK_POLICY)) {
            WebSettingsCompat.setEnterpriseAuthenticationAppLinkPolicyEnabled(settings, false)
        }
        webViewClient = Client()
        webChromeClient = Chrome()
        // Before any page loads: decoys for what pages ask for (§10.5).
        reportDecoy(if (decoys.install(this)) PageWatch.Decoy.ACTIVE else PageWatch.Decoy.UNAVAILABLE, "", "")
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
            Log.i(TAG, "download handed to the core in generation $generation")
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
        // A new address is for seeing its page: the live check folds back to its bar.
        watchOpen = false
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

        // Only the egress proxy's own challenge is answered (§8.4), so the
        // token never goes to a site; every site's credential request is refused.
        override fun onReceivedHttpAuthRequest(view: WebView, handler: HttpAuthHandler, host: String, realm: String) {
            val granted = grant
            if (granted != null && host == Rift.PROXY_HOST && realm == granted.proxyRealm) {
                handler.proceed(Rift.PROXY_USER, granted.proxyToken)
            } else {
                handler.cancel()
            }
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

    // Every refusal is reported to the core's page watch (§10.5).
    private inner class Chrome : WebChromeClient() {
        // Camera, microphone, MIDI, protected media: always denied (B4).
        override fun onPermissionRequest(request: PermissionRequest) {
            request.deny()
            for (resource in request.resources) {
                val kind = when (resource) {
                    PermissionRequest.RESOURCE_VIDEO_CAPTURE -> PageWatch.Attempt.CAMERA
                    PermissionRequest.RESOURCE_AUDIO_CAPTURE -> PageWatch.Attempt.MICROPHONE
                    PermissionRequest.RESOURCE_MIDI_SYSEX -> PageWatch.Attempt.MIDI
                    PermissionRequest.RESOURCE_PROTECTED_MEDIA_ID -> PageWatch.Attempt.PROTECTED_MEDIA
                    else -> null
                }
                kind?.let { reportAttempt(it, request.origin.toString()) }
            }
        }

        override fun onGeolocationPermissionsShowPrompt(origin: String, callback: GeolocationPermissions.Callback) {
            callback.invoke(origin, false, false)
            reportAttempt(PageWatch.Attempt.LOCATION, origin)
        }

        // A made-up file, never one of the user's: the browser app cannot
        // read the user's files, and no picker is shown.
        override fun onShowFileChooser(
            webView: WebView,
            filePathCallback: ValueCallback<Array<android.net.Uri>>,
            fileChooserParams: FileChooserParams,
        ): Boolean {
            val accepts = fileChooserParams.acceptTypes.filter { it.isNotBlank() }
            val file = try {
                decoys.file(fileChooserParams.acceptTypes)
            } catch (e: java.io.IOException) {
                Log.w(TAG, "decoy file not written: $e")
                reportAttempt(PageWatch.Attempt.FILES, webView.url)
                return false
            }
            filePathCallback.onReceiveValue(arrayOf(android.net.Uri.fromFile(file)))
            reportDecoy(PageWatch.Decoy.FILES, webView.url.orEmpty(), if (accepts.isEmpty()) "any file" else "accepts ${accepts.joinToString(", ")}")
            return true
        }

        // Fullscreen would cover the trusted indicator (INV-6), so it is refused.
        override fun onShowCustomView(view: View, callback: CustomViewCallback) {
            callback.onCustomViewHidden()
            reportAttempt(PageWatch.Attempt.FULLSCREEN, webView?.url)
        }
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
        polling.removeCallbacks(poll)
        watchReader.shutdownNow()
        lockWatch?.let { NetworkLock.unwatch(this, it) }
        lockWatch = null
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
                // Nothing from the engine is drawn over the trusted bar
                // (INV-6): the bar is drawn last, and the engine's area is
                // clipped to its bounds. A WebView that has not drawn a page
                // yet fills its whole clip with its background, which Compose
                // does not limit to the view, and it covered the bar and the
                // system bars until a page loaded (found by n5).
                Box(Modifier.zIndex(1f)) { TrustedBar() }
                Box(Modifier.fillMaxWidth().weight(1f).clipToBounds()) {
                    webView?.let { view -> AndroidView(factory = { view }, modifier = Modifier.fillMaxSize()) }
                    when (val s = screen) {
                        Screen.Page -> {}
                        Screen.Connecting -> Message("Connecting to the protection core…")
                        is Screen.Unsupported -> Message("Unsupported device configuration", "Browsing is refused: ${s.detail}.")
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
        Column(Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surfaceVariant).padding(8.dp).testTag("trusted-bar")) {
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
                    modifier = Modifier.noAutofill().weight(1f).testTag("address"),
                )
            }
            if (grant?.mode == NetworkMode.REDUCED) {
                Text(
                    "Reduced isolation: no network lock in this session. Pages can reach your local network through WebRTC, " +
                        "and a compromised browser is not limited to Rift's proxy.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.testTag("reduced"),
                )
            }
            status?.let { Text(it, style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("status")) }
            if (webView != null) WatchPanel()
        }
    }

    /**
     * The session's live status, from the core (§10.5). Never "safe": the
     * best it says is that nothing suspicious has been seen, with what is
     * watched. Tapping it lists what was seen.
     */
    @Composable
    private fun WatchPanel() {
        val current = watch
        val level = current?.level
        val (summary, color) = when {
            current == null -> (if (watchAnswered) "Live check unavailable" else "Live check starting…") to MaterialTheme.colorScheme.errorContainer
            level == PageWatch.Level.DANGER -> "Danger: ${current.events.first().text}" to MaterialTheme.colorScheme.error
            level == PageWatch.Level.WARNING -> "Warning: ${current.events.first().text}" to MaterialTheme.colorScheme.errorContainer
            else -> "Nothing suspicious seen so far" + (if (current.events.isEmpty()) "" else " (${current.events.size} notes)") to
                MaterialTheme.colorScheme.secondaryContainer
        }
        val onColor = if (level == PageWatch.Level.DANGER) MaterialTheme.colorScheme.onError else MaterialTheme.colorScheme.onSurface
        Column(Modifier.fillMaxWidth().padding(top = 4.dp).background(color).clickable { watchOpen = !watchOpen }.padding(6.dp)) {
            Text(
                summary,
                color = onColor,
                style = MaterialTheme.typography.bodySmall,
                maxLines = if (watchOpen) Int.MAX_VALUE else 2,
                modifier = Modifier.testTag("watch-status"),
            )
            if (watchOpen && current != null) {
                // At most a third of the window, so the page keeps most of a small screen.
                val most = (LocalConfiguration.current.screenHeightDp / 3).coerceAtMost(260).dp
                Column(Modifier.heightIn(max = most).verticalScroll(rememberScrollState()).testTag("watch-list")) {
                    val now = SystemClock.elapsedRealtime()
                    current.events.forEach { event ->
                        val times = if (event.count > 1) " ×${event.count}" else ""
                        val ago = ((now - event.lastSeen) / 1000).coerceAtLeast(0)
                        Text(
                            "${event.level.label()}$times, ${ago}s ago: ${event.text}",
                            color = onColor,
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.padding(top = 4.dp).testTag("watch-event"),
                        )
                    }
                    current.coverage.forEach {
                        Text(it, color = onColor, style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(top = 4.dp))
                    }
                }
            }
        }
    }

    private fun PageWatch.Level.label() = when (this) {
        PageWatch.Level.DANGER -> "Danger"
        PageWatch.Level.WARNING -> "Warning"
        PageWatch.Level.NOTE -> "Note"
    }

    private fun protectionSummary(): String {
        // Only a decision by the core may be summarized; anything else says so.
        if (screen is Screen.Unsupported) return "Browsing refused on this device"
        val notes = notes ?: return "No page checked yet"
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
        private const val SHUTDOWN_TIMEOUT_MS = 1_000L
        private const val WATCH_POLL_MS = 1_000L
        private const val ATTEMPT_REPORT_MS = 1_000L
        private const val MAX_REPORTED = 256

        /** The generation whose WebView data directory this process uses; fixed once set. */
        @Volatile private var processGeneration: Long? = null
    }
}
