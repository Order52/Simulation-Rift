package org.simulationrift.browser

import android.annotation.SuppressLint
import android.app.Application
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.ApplicationInfo
import android.content.res.Configuration
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
import android.view.ContextThemeWrapper
import android.view.View
import android.view.ViewGroup
import android.view.ViewStructure
import android.view.autofill.AutofillValue
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import android.webkit.CookieManager
import android.webkit.GeolocationPermissions
import android.webkit.HttpAuthHandler
import android.webkit.JsPromptResult
import android.webkit.JsResult
import android.webkit.PermissionRequest
import android.webkit.RenderProcessGoneDetail
import android.webkit.SslErrorHandler
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
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
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
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
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.unit.dp
import androidx.compose.ui.zIndex
import androidx.compose.ui.viewinterop.AndroidView
import androidx.webkit.UserAgentMetadata
import androidx.webkit.WebSettingsCompat
import androidx.webkit.WebViewFeature
import androidx.webkit.WebViewMediaIntegrityApiStatusConfig
import java.io.ByteArrayInputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.simulationrift.bridge.Appearance
import org.simulationrift.bridge.Fact
import org.simulationrift.bridge.IBrowser
import org.simulationrift.bridge.ICore
import org.simulationrift.bridge.NavigationDecision
import org.simulationrift.bridge.NetworkMode
import org.simulationrift.bridge.PageHiding
import org.simulationrift.bridge.PageWatch
import org.simulationrift.bridge.Rift
import org.simulationrift.bridge.SessionGrant
import org.simulationrift.bridge.TestReport
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
        data class Blocked(val url: String, val displayUrl: String, val reason: Fact, val inspectAnyway: Boolean) : Screen
        data class Ended(val message: String) : Screen
    }

    private var generation = 0L
    private var core: ICore? = null
    private var grant: SessionGrant.Granted? = null
    private var appearance by mutableStateOf(Appearance.SYSTEM)
    private var lockWatch: ConnectivityManager.NetworkCallback? = null
    private var webView: WebView? = null
    private var bound = false
    private var shuttingDown = false

    private var screen by mutableStateOf<Screen>(Screen.Connecting)

    /** Over the page during a test-open (§10.11): running, then the core's report. */
    private sealed interface Cover {
        data object Testing : Cover
        data class Report(val report: TestReport?) : Cover
    }

    /** Whether this window test-opens its link; while [cover] is up, downloads are reported, not fetched, and warnings do not wait. */
    private var testOpen = false
    private var cover by mutableStateOf<Cover?>(null)

    /** For the timing logs (no addresses): when the window was made, and when the current page started. */
    private val created = SystemClock.elapsedRealtime()
    private var pageStarted = 0L
    private var address by mutableStateOf("")
    /** The core's notes for the page shown; null until the core has decided on one. */
    private var notes by mutableStateOf<List<Fact>?>(null)
    private var canGoBack by mutableStateOf(false)
    private var canGoForward by mutableStateOf(false)
    private var status by mutableStateOf<String?>(null)
    /** The engine's progress on the page, 0–100. */
    private var loading by mutableStateOf(100)
    /** The core's live watch of this session (§10.5); null until it answers, or if it cannot. */
    private var watch by mutableStateOf<PageWatch?>(null)
    private var watchAnswered by mutableStateOf(false)
    private var watchOpen by mutableStateOf(false)
    /**
     * The content filters (§10.9): whether the core has them on, asked for each
     * page; the address of the page being shown, for the filters' third-party
     * rules; and how many requests were blocked in this window.
     */
    @Volatile private var filtering = false
    /** Whether pages' dialog boxes are dismissed unseen ("Skip sign-ins and pop-ups"), asked with [filtering]. */
    @Volatile private var quietDialogs = false
    @Volatile private var pageUrl = ""
    private val blockedCount = AtomicInteger()
    /** Requests asked about and the time the answers took, for the log: how much the filters cost a page. */
    private val askedCount = AtomicInteger()
    private val askedNanos = java.util.concurrent.atomic.AtomicLong()
    private var blocked by mutableStateOf(0)
    private var filtersShown by mutableStateOf(false)
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
        testOpen = intent.getBooleanExtra(Rift.EXTRA_TEST_OPEN, false)
        if (testOpen) cover = Cover.Testing
        setContent { RiftTheme(appearance) { NoPersonalizedLearning { BrowserScreen() } } }
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
        // A link opened directly is shown and its downloads fetched: a test-open ends here.
        testOpen = false
        cover = null
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
                appearance = answer.appearance
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
        // A release browser never browses in an outdated WebView, whatever the grant says.
        val debuggable = (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        val report = WebViewSandbox.evaluate(WebViewSandbox.facts(this), allowOutdated = debuggable && granted.outdatedWebView)
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
        // The device's time zone names where it is. Chromium reads the process's default
        // (Java's) and tells its renderers, so every page sees UTC.
        java.util.TimeZone.setDefault(java.util.TimeZone.getTimeZone("UTC"))
        webView = createWebView()
        refreshFiltering()
        screen = Screen.Page
        polling.removeCallbacks(poll)
        polling.post(poll)
        if (testOpen) polling.postDelayed(::showTestReport, TEST_OPEN_MS)
        intent.getStringExtra(Rift.EXTRA_URL)?.let(::openTyped)
    }

    // ---- Content filters (§10.9) -----------------------------------------------------

    /** Whether the core has the filters on, asked for each page. */
    private fun refreshFiltering() {
        val connected = core ?: return
        filtering = try {
            connected.filtersOn(generation)
        } catch (e: RemoteException) {
            false
        }
        quietDialogs = try {
            connected.quietDialogs(generation)
        } catch (e: RemoteException) {
            false
        }
        filtersShown = filtering
    }

    /**
     * Hides what the lists say to hide on the page at `url`: the core builds
     * the style rules from selectors it has checked, and they are injected
     * as a style element. `generic` also asks for the rules that go with the
     * class names and ids the page uses. Nothing flows from the page to the
     * core except those names, read here with a script's return value (the
     * page has no way to call anything: INV-6).
     */
    private fun hideElements(view: WebView, url: String, generic: Boolean) {
        val connected = core ?: return
        watchReader.execute {
            try {
                val hiding = PageHiding.fromBundle(connected.hidingFor(generation, url))
                runOnUiThread {
                    if (view.url != url) return@runOnUiThread
                    injectStyle(view, hiding.css, "rift-hide")
                    if (hiding.actions.isNotEmpty()) {
                        view.evaluateJavascript("$PAGE_ACTIONS_SCRIPT(${org.json.JSONObject.quote(hiding.actions)})", null)
                    }
                }
                if (!generic || hiding.genericHidden) return@execute
                runOnUiThread {
                    if (view.url != url) return@runOnUiThread
                    view.evaluateJavascript(PAGE_NAMES_SCRIPT) { value ->
                        val (classes, ids) = pageNames(value)
                        if (classes.isEmpty() && ids.isEmpty()) return@evaluateJavascript
                        watchReader.execute {
                            try {
                                val css = connected.genericHiding(generation, classes, ids, hiding.exceptions)
                                if (css.length <= MAX_GENERIC_CSS_CHARS) runOnUiThread { if (view.url == url) injectStyle(view, css, "rift-hide-generic") }
                            } catch (e: RemoteException) {
                                exitProcess("core unreachable")
                            }
                        }
                    }
                }
            } catch (e: RemoteException) {
                exitProcess("core unreachable")
            }
        }
    }

    private fun injectStyle(view: WebView, css: String, id: String) {
        if (css.isEmpty()) return
        view.evaluateJavascript(
            "(function(){var s=document.getElementById('$id');if(!s){s=document.createElement('style');s.id='$id';" +
                "(document.head||document.documentElement).appendChild(s)}s.textContent=${org.json.JSONObject.quote(css)}})()",
            null,
        )
    }

    /** The class names and ids the script returned, bounded; nothing else of the page is read. */
    private fun pageNames(value: String?): Pair<List<String>, List<String>> {
        if (value == null || value == "null" || value.length > MAX_NAMES_REPLY_CHARS) return emptyList<String>() to emptyList()
        return try {
            val text = org.json.JSONTokener(value).nextValue() as? String ?: return emptyList<String>() to emptyList()
            val parsed = org.json.JSONObject(text)
            val read = { key: String ->
                val array = parsed.optJSONArray(key)
                (0 until (array?.length() ?: 0).coerceAtMost(MAX_NAMES)).mapNotNull { array?.optString(it)?.takeIf { n -> n.isNotEmpty() && n.length <= MAX_NAME_CHARS } }
            }
            read("c") to read("i")
        } catch (e: org.json.JSONException) {
            emptyList<String>() to emptyList()
        } catch (e: ClassCastException) {
            emptyList<String>() to emptyList()
        }
    }

    // ---- Live page watch (§10.5) --------------------------------------------------

    /** The core's report on the test-open, over the page until the user chooses (§10.11). */
    private fun showTestReport() {
        val connected = core ?: return
        watchReader.execute {
            val report = try {
                TestReport.fromBundle(connected.testOpenReport(generation))
            } catch (e: RemoteException) {
                exitProcess("core unreachable")
                return@execute
            }
            runOnUiThread { if (cover != null) cover = Cover.Report(report) }
        }
    }

    /**
     * What the page asks for and calls itself, for the core's look-alike
     * check (§10.5). The page can change what this script reads, so it can
     * add warnings, never clear one.
     */
    private fun reportPage(view: WebView, url: String) {
        view.evaluateJavascript(PAGE_FACTS_SCRIPT) { value ->
            if (value == null || value.length > MAX_FACTS_REPLY_CHARS || view.url != url) return@evaluateJavascript
            val facts = try {
                val text = org.json.JSONTokener(value).nextValue() as? String ?: return@evaluateJavascript
                org.json.JSONObject(text)
            } catch (e: org.json.JSONException) {
                return@evaluateJavascript
            }
            val connected = core ?: return@evaluateJavascript
            watchReader.execute {
                try {
                    val counts = facts.optJSONObject("k")?.toString().orEmpty()
                    connected.reportPage(generation, url, facts.optString("n").take(MAX_FACT_NAMES), facts.optBoolean("p"), facts.optBoolean("c"), counts)
                } catch (e: RemoteException) {
                    exitProcess("core unreachable")
                }
                refreshWatch(connected)
            }
        }
    }

    /** A check of the watch now, not at the next poll: a warning shows as soon as the core has it. */
    private fun refreshWatchSoon() {
        core?.let { connected -> if (!watchReader.isShutdown) watchReader.execute { refreshWatch(connected) } }
    }

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
        refreshWatchSoon()
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
        refreshWatchSoon()
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
    /**
     * Light or dark as chosen in Rift. Pages see it as `prefers-color-scheme`
     * through the view's own night mode, so the activity is never recreated;
     * in dark, pages without a dark style are darkened by the engine.
     */
    private fun themedContext(): Context {
        val dark = when (appearance) {
            Appearance.SYSTEM -> return this
            Appearance.LIGHT -> Configuration.UI_MODE_NIGHT_NO
            Appearance.DARK -> Configuration.UI_MODE_NIGHT_YES
        }
        val config = Configuration().apply { uiMode = (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK.inv()) or dark }
        return ContextThemeWrapper(this, org.simulationrift.bridge.R.style.Theme_Rift).apply { applyOverrideConfiguration(config) }
    }

    private fun darkPages(): Boolean = when (appearance) {
        Appearance.SYSTEM -> (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES
        Appearance.LIGHT -> false
        Appearance.DARK -> true
    }

    private fun createWebView(): WebView = PrivateWebView(themedContext()).apply {
        // Without layout parameters AndroidView gives the view WRAP_CONTENT,
        // and in that mode WebView lays pages out at zero height: every
        // viewport unit (100vh) was 0 px, so pages sized by them collapsed
        // (found by H1).
        layoutParams = ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
        // Pages' forms go to no autofill service (§10.7): WindowGuard's
        // setting on the window does not reach the engine's virtual views.
        importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        settings.apply {
            // The default user agent names the phone's model, its build and its Android
            // version. Pages get the one every Chrome on Android sends (its reduced form).
            userAgentString = genericUserAgent()
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
        // Dark mode for pages that have no dark style of their own.
        if (WebViewFeature.isFeatureSupported(WebViewFeature.ALGORITHMIC_DARKENING)) {
            WebSettingsCompat.setAlgorithmicDarkeningAllowed(settings, darkPages())
        }
        // A device policy could otherwise let sign-in links open another app,
        // past the core's block on automatic external-app links (§10.3).
        if (WebViewFeature.isFeatureSupported(WebViewFeature.ENTERPRISE_AUTHENTICATION_APP_LINK_POLICY)) {
            WebSettingsCompat.setEnterpriseAuthenticationAppLinkPolicyEnabled(settings, false)
        }
        // The same for the client hints (Sec-CH-UA): no model, no "Android WebView" brand.
        if (WebViewFeature.isFeatureSupported(WebViewFeature.USER_AGENT_METADATA)) {
            val major = chromeMajor()
            val brand = { name: String, version: String -> UserAgentMetadata.BrandVersion.Builder().setBrand(name).setMajorVersion(version).setFullVersion("$version.0.0.0").build() }
            WebSettingsCompat.setUserAgentMetadata(
                settings,
                UserAgentMetadata.Builder()
                    .setBrandVersionList(listOf(brand("Chromium", "$major"), brand("Google Chrome", "$major"), brand("Not-A.Brand", "99")))
                    .setFullVersion("$major.0.0.0")
                    .setPlatform("Android")
                    .setPlatformVersion("10.0.0")
                    .setMobile(true)
                    .setModel("")
                    .setArchitecture("")
                    .build(),
            )
        }
        // Every request carries this app's package name in X-Requested-With. WebView has a control
        // for it (an empty allow list); on WebView 124 it was set and the header was still sent (I1),
        // so it is asked for where it exists and the header is reported, not claimed gone.
        val dropsHeader = WebViewFeature.isFeatureSupported(WebViewFeature.REQUESTED_WITH_HEADER_ALLOW_LIST)
        Log.i(TAG, "X-Requested-With control: ${if (dropsHeader) "available" else "not available in this WebView"}")
        if (dropsHeader) WebSettingsCompat.setRequestedWithHeaderOriginAllowList(settings, emptySet())
        webViewClient = Client()
        webChromeClient = Chrome()
        // Before any page loads: decoys for what pages ask for (§10.5).
        reportDecoy(if (decoys.install(this)) PageWatch.Decoy.ACTIVE else PageWatch.Decoy.UNAVAILABLE, "", "")
        // The engine only reports the download; the core fetches it again
        // into encrypted quarantine (§8.5). Downloads generated inside the
        // page (blob:, data:) never reach this listener (PoC A3).
        setDownloadListener { url, userAgent, contentDisposition, _, _ ->
            // Nothing is fetched while the user has not seen the page (§10.11).
            if (cover != null) reportAttempt(PageWatch.Attempt.DOWNLOAD, url) else submitDownload(url, userAgent, contentDisposition)
        }
    }

    /** Chrome's reduced user agent for the engine's major version: no model, no build, no "wv". */
    private fun chromeMajor(): Int = WebView.getCurrentWebViewPackage()?.versionName?.substringBefore('.')?.toIntOrNull() ?: FALLBACK_CHROME_MAJOR

    private fun genericUserAgent(): String {
        val major = chromeMajor()
        return "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/$major.0.0.0 Mobile Safari/537.36"
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
    ).also { refreshWatchSoon() }

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
            // Hidden from the user, a test-open loads past the warning; its report lists it (§10.11).
            is NavigationDecision.Confirm -> if (cover != null) load(url, d.notes + d.reasons) else show(url, d)
            else -> show(url, d)
        }
    }

    private fun load(url: String, decisionNotes: List<Fact>) {
        notes = decisionNotes
        // Shown while the page loads, not only once the engine starts it.
        address = url
        // Before the engine starts the page: onPageStarted comes after its first subresources (found by F1).
        pageUrl = url
        refreshFiltering()
        screen = Screen.Page
        webView?.loadUrl(url)
    }

    private fun show(url: String, decision: NavigationDecision) {
        address = url
        screen = when (decision) {
            is NavigationDecision.Proceed -> Screen.Page
            is NavigationDecision.Confirm -> Screen.Interstitial(url, decision.displayUrl, decision.reasons)
            is NavigationDecision.Block -> Screen.Blocked(url, decision.displayUrl, decision.reason, decision.inspectAnyway)
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
                    pageUrl = url
                    refreshFiltering()
                    false
                }
                is NavigationDecision.Confirm -> if (cover != null) {
                    notes = d.notes + d.reasons
                    pageUrl = url
                    refreshFiltering()
                    false
                } else {
                    show(url, d)
                    true
                }
                else -> {
                    show(url, d)
                    true
                }
            }
        }

        override fun onPageStarted(view: WebView, url: String, favicon: Bitmap?) {
            if (pageStarted == 0L) Log.i(TAG, "first page started ${SystemClock.elapsedRealtime() - created} ms after the window was made")
            pageStarted = SystemClock.elapsedRealtime()
            address = url
            pageUrl = url
            refreshFiltering()
        }

        override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse? {
            // Pages are the core's to judge (decide); the filters take away what a page loads.
            if (!filtering || request.isForMainFrame) return null
            val connected = core ?: return null
            val started = System.nanoTime()
            val isBlocked = try {
                connected.blockRequest(generation, request.url.toString(), pageUrl, ContentKind.of(request))
            } catch (e: RemoteException) {
                return null
            } finally {
                askedCount.incrementAndGet()
                askedNanos.addAndGet(System.nanoTime() - started)
            }
            if (!isBlocked) return null
            blocked = blockedCount.incrementAndGet()
            return WebResourceResponse("text/plain", "utf-8", 403, "Blocked by Rift", emptyMap(), ByteArrayInputStream(ByteArray(0)))
        }

        override fun onPageCommitVisible(view: WebView, url: String) {
            if (filtering) hideElements(view, url, generic = false)
        }

        override fun onPageFinished(view: WebView, url: String) {
            Log.i(TAG, "page finished ${SystemClock.elapsedRealtime() - pageStarted} ms after it started")
            reportPage(view, url)
            val asked = askedCount.get()
            if (filtering && asked > 0) {
                Log.i(TAG, "content filters: $asked requests asked about, ${askedNanos.get() / 1_000_000} ms in all (${askedNanos.get() / 1_000 / asked} us each), ${blockedCount.get()} blocked")
            }
            if (filtering) {
                hideElements(view, url, generic = true)
                // Content added after the load.
                polling.postDelayed({ if (filtering && view.url == url) hideElements(view, url, generic = true) }, LATE_HIDING_MS)
            }
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
        override fun onProgressChanged(view: WebView, newProgress: Int) {
            loading = newProgress
        }

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

        // With "Skip sign-ins and pop-ups" on, a page's dialog boxes are
        // answered as if dismissed, unseen: an alert is closed, a question
        // gets "no" (and a prompt nothing), and "Leave this page?" lets you
        // leave. Scam pages use these to keep you on them.
        override fun onJsAlert(view: WebView, url: String, message: String, result: JsResult): Boolean =
            dismissed(url) { result.cancel() }

        override fun onJsConfirm(view: WebView, url: String, message: String, result: JsResult): Boolean =
            dismissed(url) { result.cancel() }

        override fun onJsPrompt(view: WebView, url: String, message: String, defaultValue: String?, result: JsPromptResult): Boolean =
            dismissed(url) { result.cancel() }

        override fun onJsBeforeUnload(view: WebView, url: String, message: String, result: JsResult): Boolean =
            dismissed(url) { result.confirm() }

        private fun dismissed(url: String, answer: () -> Unit): Boolean {
            if (!quietDialogs) return false
            answer()
            reportAttempt(PageWatch.Attempt.DIALOG, url)
            return true
        }

        // Fullscreen would cover the trusted indicator (INV-6), so it is refused.
        override fun onShowCustomView(view: View, callback: CustomViewCallback) {
            callback.onCustomViewHidden()
            reportAttempt(PageWatch.Attempt.FULLSCREEN, webView?.url)
        }
    }

    // ---- Lifecycle -------------------------------------------------------------

    /**
     * Asks the core to open a link it blocked as listed in a new session
     * (§10.4). The core decides it again, and resets: this window closes.
     */
    private fun inspectAnyway(url: String) {
        screen = Screen.Ended("Opening the link in a new sealed session…")
        Log.i(TAG, "asking the core to open a listed link in a new session")
        try {
            core?.inspectAnyway(generation, url)
        } catch (e: RemoteException) {
            exitProcess("core unreachable")
        }
    }

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
                        Screen.Page -> cover?.let { TestCover(it) }
                        Screen.Connecting -> Message("Connecting to the protection core…")
                        is Screen.Unsupported -> Message("Unsupported device configuration", "Browsing is refused: ${s.detail}.")
                        is Screen.Interstitial -> Interstitial(s)
                        is Screen.Blocked -> Blocked(s)
                        is Screen.Ended -> Message("Session ended", s.message)
                    }
                }
            }
        }
    }

    @Composable
    private fun TrustedBar() {
        val colors = LocalStatusColors.current
        val focus = LocalFocusManager.current
        // While the field has focus it holds what is typed, starting from the page's address.
        var typed by androidx.compose.runtime.remember { mutableStateOf(TextFieldValue("")) }
        var editing by androidx.compose.runtime.remember { mutableStateOf(false) }
        val opened = notes?.any { it.code == NavigationDecision.OPENED_LISTED } == true
        Column(Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surfaceContainer).padding(horizontal = 4.dp, vertical = 4.dp).testTag("trusted-bar")) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                BarButton(R.drawable.ic_back, "Back", screen is Screen.Page && canGoBack, "back") { webView?.goBack() }
                BarButton(R.drawable.ic_forward, "Forward", screen is Screen.Page && canGoForward, "forward") { webView?.goForward() }
                BarButton(R.drawable.ic_reload, "Reload", webView != null, "reload") {
                    screen = Screen.Page
                    webView?.reload()
                }
                OutlinedTextField(
                    value = if (editing) typed else TextFieldValue(shownAddress()),
                    onValueChange = { typed = it },
                    placeholder = { Text("Address", maxLines = 1) },
                    singleLine = true,
                    enabled = webView != null,
                    textStyle = MaterialTheme.typography.bodyMedium,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, imeAction = ImeAction.Go),
                    keyboardActions = KeyboardActions(onGo = {
                        val text = typed.text
                        focus.clearFocus()
                        if (text.isNotBlank()) openTyped(text)
                    }),
                    modifier = Modifier.noAutofill().weight(1f).padding(end = 4.dp).testTag("address").onFocusChanged { state ->
                        if (state.isFocused && !editing) {
                            typed = TextFieldValue(address, TextRange(0, address.length))
                            editing = true
                        } else if (!state.isFocused) {
                            editing = false
                        }
                    },
                )
            }
            if (loading < 100 && screen is Screen.Page) {
                LinearProgressIndicator(progress = { loading / 100f }, modifier = Modifier.fillMaxWidth().height(2.dp).testTag("progress"))
            }
            Row(Modifier.padding(top = 4.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(
                    "Session $generation",
                    style = MaterialTheme.typography.labelSmall,
                    modifier = Modifier.background(MaterialTheme.colorScheme.secondaryContainer, RoundedCornerShape(50)).padding(horizontal = 8.dp, vertical = 4.dp).testTag("session-chip"),
                )
                // The core's verdict on the page shown; never a green "safe" (§10.4).
                val warned = notes?.any { !it.code.startsWith("intel-") } == true
                val (back, fore) = when {
                    opened || screen is Screen.Blocked -> MaterialTheme.colorScheme.error to MaterialTheme.colorScheme.onError
                    warned -> colors.warningContainer to colors.onWarningContainer
                    else -> MaterialTheme.colorScheme.surfaceVariant to MaterialTheme.colorScheme.onSurfaceVariant
                }
                Text(
                    protectionSummary(),
                    color = fore,
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 2,
                    modifier = Modifier.weight(1f).background(back, RoundedCornerShape(8.dp)).padding(horizontal = 8.dp, vertical = 4.dp).testTag("protection"),
                )
                TextButton(onClick = ::requestReset, modifier = Modifier.testTag("reset")) { Text("Reset") }
            }
            if (opened) {
                Text(
                    "Known malicious page, opened on purpose. Do not sign in, pay or type anything here. Reset ends the session and wipes what it stored.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onError,
                    modifier = Modifier.fillMaxWidth().padding(top = 4.dp).background(MaterialTheme.colorScheme.error, RoundedCornerShape(8.dp)).padding(8.dp).testTag("opened-listed"),
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
            if (filtersShown) {
                Text(
                    if (blocked == 0) "Content filters on" else "Content filters: $blocked ${if (blocked == 1) "request" else "requests"} blocked",
                    style = MaterialTheme.typography.labelSmall,
                    modifier = Modifier.padding(top = 4.dp).testTag("filter-count"),
                )
            }
            if (webView != null) WatchPanel()
        }
    }

    @Composable
    private fun BarButton(icon: Int, label: String, enabled: Boolean, tag: String, onClick: () -> Unit) {
        IconButton(onClick = onClick, enabled = enabled, modifier = Modifier.testTag(tag)) {
            Icon(painterResource(icon), contentDescription = label)
        }
    }

    /** The page's address without "https://", so the site name leads; "http://" stays, as it means no encryption. */
    private fun shownAddress(): String = address.removePrefix("https://").removeSuffix("/")

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
        if (screen is Screen.Blocked) return "Blocked by Rift: not loaded"
        val notes = notes ?: return "No page checked yet"
        if (notes.any { it.code == NavigationDecision.OPENED_LISTED }) return "Known malicious · opened on purpose"
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

    /** Over the page during a test-open (§10.11): a notice while it runs, then the core's report and the choice. */
    @Composable
    private fun TestCover(c: Cover) {
        Surface(Modifier.fillMaxSize().testTag("test-open"), color = MaterialTheme.colorScheme.surface) {
            Column(Modifier.verticalScroll(rememberScrollState()).padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                when (c) {
                    // Fixed text, no countdown: a screen reader (or UiAutomator) is not sent a change every second.
                    is Cover.Testing -> {
                        Text("Test-opening the link", style = MaterialTheme.typography.headlineSmall)
                        Text(
                            "The page is running in this sealed session, out of sight, for about ${TEST_OPEN_MS / 1000} seconds. " +
                                "Rift is watching where it goes, what it asks for and which sites it reaches.",
                            modifier = Modifier.testTag("test-open-running"),
                        )
                        LinearProgressIndicator(Modifier.fillMaxWidth())
                    }
                    is Cover.Report -> TestReportView(c.report)
                }
            }
        }
    }

    @Composable
    private fun TestReportView(report: TestReport?) {
        Text("What the link did", style = MaterialTheme.typography.headlineSmall)
        if (report == null) {
            Text("Rift could not get the report, so it cannot say what the page did. Treat it as unknown.", modifier = Modifier.testTag("test-report-summary"))
        } else {
            val colors = LocalStatusColors.current
            val (back, fore) = when (report.level) {
                PageWatch.Level.DANGER -> MaterialTheme.colorScheme.error to MaterialTheme.colorScheme.onError
                PageWatch.Level.WARNING -> colors.warningContainer to colors.onWarningContainer
                else -> MaterialTheme.colorScheme.surfaceVariant to MaterialTheme.colorScheme.onSurfaceVariant
            }
            Text(
                report.summary,
                color = fore,
                modifier = Modifier.fillMaxWidth().background(back, RoundedCornerShape(12.dp)).padding(12.dp).testTag("test-report-summary"),
            )
            report.sections.forEach { section ->
                Text(section.title, style = MaterialTheme.typography.titleSmall)
                section.items.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(onClick = ::requestReset, modifier = Modifier.testTag("test-close")) { Text("Close and wipe") }
            OutlinedButton(onClick = { cover = null }, modifier = Modifier.testTag("test-show")) { Text("Show the page") }
        }
    }

    /**
     * A blocked page. For a link the threat database lists, the user may
     * still open it (§10.4), in a new session; what that does and does not
     * protect is said before the button, not after.
     */
    @Composable
    private fun Blocked(s: Screen.Blocked) {
        val color = if (s.inspectAnyway) MaterialTheme.colorScheme.errorContainer else MaterialTheme.colorScheme.surface
        Surface(Modifier.fillMaxSize().testTag("message"), color = color) {
            Column(Modifier.verticalScroll(rememberScrollState()).padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Page blocked", style = MaterialTheme.typography.headlineSmall)
                Text(s.reason.text)
                Text(s.displayUrl, style = MaterialTheme.typography.bodySmall)
                Button(onClick = { screen = Screen.Page }, modifier = Modifier.testTag("blocked-back")) { Text("Go back") }
                if (s.inspectAnyway) {
                    Text("You can still open it, to see what it does:", style = MaterialTheme.typography.titleSmall)
                    listOf(
                        "It opens in a new session with nothing else in it; this session is wiped first.",
                        "Its own site is let through Rift's proxy. Other listed sites and your local network stay blocked.",
                        "Camera, microphone, location and files get made-up answers or a refusal. Downloads go to quarantine.",
                        "Reset ends the session and wipes everything it stored.",
                        "This lowers the risk; it does not remove it. A page that attacks a flaw in the browser engine could still affect that session, and Rift cannot stop what you type into the page.",
                    ).forEach { Text("• $it", style = MaterialTheme.typography.bodyMedium) }
                    // After what it means, so it is read first.
                    OutlinedButton(onClick = { inspectAnyway(s.url) }, modifier = Modifier.testTag("inspect-anyway")) {
                        Text("Open in a new session")
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
        private const val LATE_HIDING_MS = 2_500L
        private const val FALLBACK_CHROME_MAJOR = 120
        private const val MAX_NAMES = 1_500
        private const val MAX_NAME_CHARS = 100
        private const val MAX_NAMES_REPLY_CHARS = 300_000
        private const val MAX_GENERIC_CSS_CHARS = 250_000
        private const val TEST_OPEN_MS = 10_000L
        private const val MAX_FACTS_REPLY_CHARS = 24_576
        private const val MAX_FACT_NAMES = 512

        /**
         * What the page is made of, for Rift AI's page model (§16.1): counts,
         * the title and the start of the visible text. Each count is defined
         * in rift_core::pagemodel::PageCounts; tools/rift-train counts the same
         * in saved pages. "Another site" is site_key's rule, written again here.
         */
        private const val PAGE_COUNTS = """(function(){
var all=function(s){return document.querySelectorAll(s)};
var key=function(h){h=(h||'').toLowerCase().replace(/\.$/,'');var l=h.split('.'),n=l.length,k=(n>=3&&l[n-1].length==2&&l[n-2].length<=3)?3:2;return l.slice(Math.max(0,n-k)).join('.')};
var me=key(location.hostname);
var other=function(v){if(!v)return false;try{var u=new URL(v,location.href);return(u.protocol=='http:'||u.protocol=='https:')&&key(u.hostname)!=me}catch(e){return false}};
var nowhere=function(v){v=(v||'').trim().toLowerCase();return v==''||v.charAt(0)=='#'||v.indexOf('javascript:')==0||v=='about:blank'};
var k={pw:all('input[type=password]').length,fm:0,fx:0,fnull:0,fmail:0,fphp:0,hi:all('input[type=hidden]').length,a:0,ax:0,an:0,r:0,rx:0,fv:0,ifr:0,ih:0,sc:0,sx:0,ob:0,
mr:document.querySelector('meta[http-equiv=refresh i]')?1:0,rc:document.querySelector('[oncontextmenu]')?1:0,hb:0,el:document.getElementsByTagName('*').length,cp:0};
all('form').forEach(function(f){k.fm++;var v=f.getAttribute('action');if(v===null)return;if(nowhere(v)){k.fnull++;return}v=v.trim().toLowerCase();
if(v.indexOf('mailto:')==0)k.fmail++;else if(other(v))k.fx++;if(/\.php([?#]|$)/.test(v))k.fphp++});
all('a[href]').forEach(function(a){k.a++;var v=a.getAttribute('href');if(nowhere(v))k.an++;else if(other(v))k.ax++});
all('img[src],script[src],iframe[src],link[href]').forEach(function(e){k.r++;if(other(e.getAttribute(e.tagName=='LINK'?'href':'src')))k.rx++});
all('link[rel~=icon i]').forEach(function(e){if(other(e.getAttribute('href')))k.fv=1});
all('iframe,frame').forEach(function(f){k.ifr++;var st=f.getAttribute('style')||'';
if(f.getAttribute('width')=='0'||f.getAttribute('height')=='0'||f.hasAttribute('hidden')||/display:\s*none|visibility:\s*hidden/i.test(st))k.ih++});
all('script').forEach(function(s){k.sc++;var v=s.getAttribute('src');if(v!==null){if(other(v))k.sx++;return}var t=(s.textContent||'').slice(0,200000);
k.ob+=(t.match(/eval\(|atob\(|unescape\(|fromCharCode|document\.write\(/g)||[]).length;if(/event\.button ?== ?2/.test(t))k.rc=1});
k.ob=Math.min(k.ob,100000);k.hb=Math.min(document.documentElement.outerHTML.length,10000000);
var text=((document.body&&document.body.innerText)||'').replace(/\s+/g,' ');
k.cp=/[©®™]/.test(text)?1:0;k.title=(document.title||'').slice(0,256);k.text=text.trim().slice(0,2000);
return k})()"""

        /** What the page calls itself (title, site name, first heading) and whether it asks for a password or a card. */
        private const val PAGE_FACTS_SCRIPT = "(function(){var q=function(s){return document.querySelector(s)};" +
            "var m=q('meta[property=\"og:site_name\"]'),h=q('h1');" +
            "var n=[document.title,m&&m.content,h&&h.textContent].filter(Boolean).join(' \u00b7 ').replace(/\\s+/g,' ').slice(0,512);" +
            "var c=!!q('input[autocomplete^=\"cc-\"]')||Array.prototype.some.call(document.querySelectorAll('input'),function(i){" +
            "return /card.?num|cc.?num|cvv|cvc|csc/i.test((i.name||'')+' '+(i.id||'')+' '+(i.placeholder||''))});" +
            "return JSON.stringify({n:n,p:!!q('input[type=password]'),c:c,k:" + PAGE_COUNTS + "})})()"


        /** The class names and ids in the page, as JSON; the only thing read back from it. */
        private const val PAGE_NAMES_SCRIPT = "(function(){var c={},i={},nc=0,ni=0;" +
            "document.querySelectorAll('[class]').forEach(function(e){if(typeof e.className!=='string')return;" +
            "e.className.split(/\\s+/).forEach(function(n){if(n&&!c[n]&&nc<1500){c[n]=1;nc++}})});" +
            "document.querySelectorAll('[id]').forEach(function(e){var n=e.id;if(n&&!i[n]&&ni<1500){i[n]=1;ni++}});" +
            "return JSON.stringify({c:Object.keys(c),i:Object.keys(i)})})()"

        /**
         * Applies the changes the core checked (§10.9; their form is in
         * rift_core::filters::Cosmetic): it finds elements by the steps and
         * hides, removes, restyles or strips a class or attribute, nothing
         * else. It reads its input as JSON data, never as code, and reapplies
         * for 20 s as the page changes, since sign-in walls appear late.
         */
        private const val PAGE_ACTIONS_SCRIPT = "(function(t){var list;try{list=JSON.parse(t)}catch(e){return}" +
            "if(!Array.isArray(list))return;var done=new WeakMap();" +
            "function all(r,s){try{return Array.prototype.slice.call(r.querySelectorAll(s),0,2000)}catch(e){return[]}}" +
            "function find(steps){var els=null;for(var i=0;i<steps.length;i++){var k=steps[i][0],a=String(steps[i][1]),n=[];" +
            "if(k==='css'){if(els===null)n=all(document,a);else els.forEach(function(e){all(e,':scope '+a).forEach(function(f){if(n.indexOf(f)<0)n.push(f)})})}" +
            "else if(k==='text'){var m=/^\\/(.*)\\/([imsu]*)$/.exec(a),re=null;if(m){try{re=new RegExp(m[1],m[2])}catch(e){return[]}}" +
            "n=(els||[]).filter(function(e){var x=e.textContent||'';return re?re.test(x):x.indexOf(a)>=0})}" +
            "else if(k==='up'){var c=/^[0-9]+$/.test(a)?parseInt(a,10):0;(els||[]).forEach(function(e){var p=e;" +
            "if(c>0){for(var j=0;j<c&&p;j++)p=p.parentElement}else{try{p=e.parentElement?e.parentElement.closest(a):null}catch(x){p=null}}" +
            "if(p&&n.indexOf(p)<0)n.push(p)})}else return[];els=n.slice(0,2000);if(!els.length)return[]}return els||[]}" +
            "function apply(e,a,key){var seen=done.get(e)||{};if(seen[key])return;" +
            "if(a[0]==='hide')e.style.setProperty('display','none','important');" +
            "else if(a[0]==='remove'){e.remove();return}" +
            "else if(a[0]==='style')e.setAttribute('style',(e.getAttribute('style')||'')+';'+a[1]);" +
            "else if(a[0]==='remove-class'){if(!e.classList.contains(a[1]))return;e.classList.remove(a[1])}" +
            "else if(a[0]==='remove-attr'){if(!e.hasAttribute(a[1]))return;e.removeAttribute(a[1])}" +
            "else return;if(a[0]==='hide'||a[0]==='style'){seen[key]=1;done.set(e,seen)}}" +
            "function run(){list.forEach(function(x,i){if(!x||!Array.isArray(x.s)||!Array.isArray(x.a))return;" +
            "find(x.s).forEach(function(e){apply(e,x.a,i)})})}" +
            "run();var wait=false,until=Date.now()+20000;var o=new MutationObserver(function(){" +
            "if(Date.now()>until){o.disconnect();return}if(wait)return;wait=true;setTimeout(function(){wait=false;run()},300)});" +
            "o.observe(document.documentElement,{childList:true,subtree:true,attributes:true,attributeFilter:['class','style','inert']})})"

        /** The generation whose WebView data directory this process uses; fixed once set. */
        @Volatile private var processGeneration: Long? = null
    }
}
