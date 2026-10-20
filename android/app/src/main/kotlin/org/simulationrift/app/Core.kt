package org.simulationrift.app

import android.app.Application
import android.app.Service
import android.content.Context
import android.graphics.Bitmap
import android.util.Log
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.flow.update
import org.simulationrift.bridge.Fact
import org.simulationrift.bridge.IBrowser
import org.simulationrift.bridge.NavigationDecision
import org.simulationrift.bridge.NetworkMode
import org.simulationrift.bridge.SessionGrant
import org.simulationrift.core.DisposalException
import org.simulationrift.core.DownloadFailure
import org.simulationrift.core.EgressFailure
import org.simulationrift.core.EgressStats
import org.simulationrift.core.DownloadInfo
import org.simulationrift.core.Intel
import org.simulationrift.core.IntelFailure
import org.simulationrift.core.IntelStatus
import org.simulationrift.core.ScanFailure
import org.simulationrift.core.ScanStart
import org.simulationrift.core.Verdict
import org.simulationrift.core.Navigation
import org.simulationrift.core.QuarantinedFile
import org.simulationrift.core.Navigator
import org.simulationrift.core.PreviewFailure
import org.simulationrift.core.Preview as CorePreview
import org.simulationrift.core.SessionFailure
import org.simulationrift.core.Sessions
import org.simulationrift.core.displaySafe
import org.simulationrift.core.typedAddress
import org.simulationrift.core.Fact as CoreFact

const val TAG = "Rift"

/** Whether browsing may start in the browser, and the facts behind the answer (§8.4, INV-7). */
data class SandboxReport(val verified: Boolean, val detail: String)

/** The browser's report on its network (§8.8): the proxy override, and whether its default network is the lock. */
data class NetworkReport(val proxied: Boolean, val locked: Boolean, val detail: String)

/**
 * The trusted controller (main process only). rift-core makes every decision;
 * this object sequences it for Android and tracks which browser window
 * belongs to which generation.
 */
object Core {
    sealed interface State {
        data object Opening : State

        /** `recovered`: a previous session was interrupted and has now been cleaned up. */
        data class Active(val generation: Long, val recovered: Long?) : State

        data class Resetting(val generation: Long) : State

        /** Nothing is presented as fresh until [retry] succeeds (INV-8). */
        data class Failed(val message: String) : State
    }

    private class RegisteredBrowser(val generation: Long, val binder: IBrowser, val mode: NetworkMode) {
        @Volatile var sandbox: SandboxReport? = null
        @Volatile var network: NetworkReport? = null
    }

    /** One download of the current session, as the home screen shows it. */
    data class Download(val key: Long, val url: String, val file: QuarantinedFile? = null, val failure: String? = null) {
        val running get() = file == null && failure == null
    }

    private val _state = MutableStateFlow<State>(State.Opening)
    val state: StateFlow<State> = _state

    /** Last renderer-sandbox report, for the diagnostics screen. */
    private val _sandbox = MutableStateFlow<SandboxReport?>(null)
    val sandbox: StateFlow<SandboxReport?> = _sandbox

    /** Last network report from the browser, for the diagnostics screen. */
    private val _network = MutableStateFlow<NetworkReport?>(null)
    val network: StateFlow<NetworkReport?> = _network

    /** Why the last session ended on its own (the lock was lost), until the next one starts. */
    private val _notice = MutableStateFlow<String?>(null)
    val notice: StateFlow<String?> = _notice

    /** The generation the user chose to run without the network lock, if any (§8.8). */
    private val _reduced = MutableStateFlow<Long?>(null)
    val reduced: StateFlow<Long?> = _reduced

    private val _downloads = MutableStateFlow<List<Download>>(emptyList())
    val downloads: StateFlow<List<Download>> = _downloads

    private val _localHosts = MutableStateFlow<List<String>>(emptyList())
    val localHosts: StateFlow<List<String>> = _localHosts

    /**
     * A preview of one quarantined file: pixels from the isolated worker,
     * escaped plain text with a note on what is shown, or why there is none.
     */
    data class Preview(
        val fileId: String,
        val bitmap: Bitmap? = null,
        val text: String? = null,
        val note: String? = null,
        val failure: String? = null,
    ) {
        val running get() = bitmap == null && text == null && failure == null
    }

    private val _previews = MutableStateFlow<Map<String, Preview>>(emptyMap())
    val previews: StateFlow<Map<String, Preview>> = _previews

    /** The installed threat database, or null while it is being opened. */
    private val _intel = MutableStateFlow<IntelStatus?>(null)
    val intel: StateFlow<IntelStatus?> = _intel

    /** The outcome of the last database install, for the home screen. */
    private val _intelMessage = MutableStateFlow<String?>(null)
    val intelMessage: StateFlow<String?> = _intelMessage

    /** Scan verdicts of this session's files; a key with null means "checking". */
    private val _verdicts = MutableStateFlow<Map<String, Verdict?>>(emptyMap())
    val verdicts: StateFlow<Map<String, Verdict?>> = _verdicts

    // Scans and database checks, one worker at a time (each holds the file or
    // the rules in memory until its worker is retired).
    private val scanning = Executors.newSingleThreadExecutor { Thread(it, "rift-scan") }
    @Volatile private var database: Intel? = null

    /** The worker component for the scan after each download; tests substitute misbehaving ones. */
    @Volatile internal var scanWorker: Class<out Service> = PreviewService::class.java

    // One worker at a time: previews are user-initiated, and each holds its
    // decrypted input in memory until the worker is retired.
    private val previewing = Executors.newSingleThreadExecutor { Thread(it, "rift-preview") }

    // Transfers run here, never on the session worker, so a slow download
    // cannot delay a reset (which cancels it instead).
    private val transfers = Executors.newFixedThreadPool(2) { Thread(it, "rift-transfer") }
    private val downloadKeys = AtomicLong()

    // Session work is serialized here. Disposal blocks until :browser is gone,
    // so it never runs on the UI thread or on a Binder thread.
    private val worker = Executors.newSingleThreadExecutor { Thread(it, "rift-core") }
    private val started = AtomicBoolean(false)
    private lateinit var app: Context
    private lateinit var disposal: AndroidBrowserDisposal

    // Written only on [worker]; read by transfers (the Rust object is thread-safe).
    @Volatile private var sessions: Sessions? = null

    // Read on Binder threads, so that a decision never waits for a reset that
    // holds the session lock. Written only on [worker].
    @Volatile private var currentGeneration: Long? = null
    @Volatile private var browser: RegisteredBrowser? = null

    /**
     * Until the signed intelligence pack carries these lists (Phase 3), the
     * lookalike and shortener checks use this short built-in set.
     */
    private val protectedDomains = listOf(
        "paypal.com", "google.com", "apple.com", "microsoft.com", "amazon.com",
        "facebook.com", "instagram.com", "whatsapp.com", "netflix.com", "github.com",
    )
    private val shorteners = listOf("bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly")
    private val navigator by lazy { Navigator(protectedDomains, shorteners) }

    fun ensureStarted(context: Context) {
        check(Application.getProcessName() == context.packageName) { "rift-core runs in the main process only" }
        if (started.compareAndSet(false, true)) {
            app = context.applicationContext
            disposal = AndroidBrowserDisposal(app)
            worker.execute(::openAndStart)
        }
    }

    /** After a failure: reopen, which repeats any unfinished cleanup first. */
    fun retry() = worker.execute {
        if (_state.value is State.Failed) openAndStart()
    }

    /** Resets the active session; `generation` guards against stale requests. */
    fun reset(generation: Long? = null) = worker.execute {
        val current = currentGeneration ?: return@execute
        if (generation != null && generation != current) return@execute
        val opened = sessions ?: return@execute
        _state.value = State.Resetting(current)
        currentGeneration = null // decisions for the old generation now block
        _downloads.value = emptyList()
        _localHosts.value = emptyList()
        _previews.value = emptyMap()
        _verdicts.value = emptyMap()
        try {
            opened.reset()
        } catch (e: SessionFailure) {
            fail(opened, e)
            return@execute
        }
        start(opened, recovered = null)
    }

    private fun openAndStart() {
        _state.value = State.Opening
        if (database == null) openIntel()
        val opened = try {
            Sessions.open(File(app.filesDir, "rift").path, disposal)
        } catch (e: SessionFailure) {
            fail(null, e)
            return
        }
        try {
            // Recovery has already wiped the browser if a session was interrupted.
            disposal.wipeOnceThisLaunch()
        } catch (e: DisposalException) {
            fail(opened, "The browser app could not be wiped before the first session: ${e.message}")
            return
        }
        sessions = opened
        start(opened, opened.recovery().interruptedGeneration?.toLong())
    }

    /** files/rift/intel is Rift's own state (on the disposal allowlist), kept across sessions. */
    private fun openIntel() {
        try {
            database = Intel.open(File(app.filesDir, "rift/intel").path)
            _intel.value = database?.status(nowUnix())
        } catch (e: IntelFailure) {
            Log.e(TAG, "threat database unavailable", e)
            _intelMessage.value = "The threat database could not be opened: ${Scanner.describe(e)}"
        }
    }

    private fun nowUnix(): ULong = (System.currentTimeMillis() / 1000).toULong()

    private fun start(opened: Sessions, recovered: Long?) {
        try {
            val generation = opened.start().toLong()
            currentGeneration = generation
            _state.value = State.Active(generation, recovered)
            Log.i(TAG, "session $generation active" + (recovered?.let { "; recovered interrupted session $it" } ?: ""))
        } catch (e: SessionFailure) {
            fail(opened, e)
        }
    }

    private fun fail(opened: Sessions?, e: SessionFailure) {
        Log.e(TAG, "session failure", e)
        fail(opened, describe(e))
    }

    private fun fail(opened: Sessions?, message: String) {
        Log.e(TAG, "session failure: $message")
        currentGeneration = null
        // Recovery happens only through a fresh open, which repeats cleanup.
        opened?.close()
        sessions = null
        _state.value = State.Failed(message)
    }

    // UniFFI renders errors as field lists, so the sentences are written here.
    private fun describe(e: SessionFailure): String = when (e) {
        is SessionFailure.CleanupFailed -> "Cleanup of session ${e.generation} failed: ${e.reason}"
        is SessionFailure.Storage -> "Session storage failed: ${e.detail}"
        is SessionFailure.NoActiveSession -> "No session is active."
        is SessionFailure.AlreadyActive -> "A session is already active."
        is SessionFailure.Poisoned -> "Session state is unusable after an internal error."
    }

    private fun describe(e: DownloadFailure): String = when (e) {
        is DownloadFailure.NotCaptured -> e.reason
        is DownloadFailure.QuotaExceeded -> "this session's download quota (${e.limit} bytes) is used up"
        is DownloadFailure.SessionEnded -> "the session this download belonged to has ended"
        is DownloadFailure.Poisoned -> "session state is unusable after an internal error"
    }

    // ---- Network lock (§8.8) ------------------------------------------------------

    /**
     * The user's explicit choice to run the current session without the
     * network lock, when it cannot run. It lasts for this generation only,
     * and the browser labels the session for its whole life.
     */
    fun useReducedIsolation(generation: Long) {
        if (generation == currentGeneration) _reduced.value = generation
    }

    /** The lock was taken away: a session that relied on it ends, and the browser is wiped (S28). */
    fun networkLockLost() {
        val generation = currentGeneration ?: return
        if (_reduced.value == generation) return
        _notice.value = "Session $generation ended because the network lock stopped. Turn the lock on again to keep browsing isolated."
        reset(generation)
    }

    fun dismissNotice() {
        _notice.value = null
    }

    /** What the current session's egress proxy did, or null before the browser first used it. */
    fun egressStats(): EgressStats? {
        val generation = currentGeneration ?: return null
        return sessions?.egressStats(generation.toULong())
    }

    /**
     * The current session's proxy port, if it has started (diagnostics and
     * S24). The port is not a secret: the proxy refuses requests without the
     * session's token.
     */
    fun egressPort(): Int? {
        val generation = currentGeneration ?: return null
        if (sessions?.egressStats(generation.toULong()) == null) return null
        return try {
            sessions?.egress(generation.toULong())?.port?.toInt()
        } catch (e: EgressFailure) {
            null
        }
    }

    // ---- Interface for the browser app (via CoreService) -----------------------------

    /**
     * Registers the browser window of `generation` and hands it this
     * session's proxy. Without the lock (and without the user's choice of
     * reduced isolation for this session) browsing is refused.
     */
    fun registerBrowser(generation: Long, binder: IBrowser): SessionGrant {
        if (generation != currentGeneration) return SessionGrant.Refused("This browser window belongs to a session that has ended.")
        val opened = sessions ?: return SessionGrant.Refused("No session is active.")
        val mode = when {
            _reduced.value == generation -> NetworkMode.REDUCED
            NetworkLock.active -> NetworkMode.LOCKED
            else -> return SessionGrant.Refused(
                "The network lock is off, so the browser may not load pages. Open Rift to turn it on, or to choose reduced isolation for this session.",
            )
        }
        val endpoint = try {
            opened.egress(generation.toULong())
        } catch (e: EgressFailure) {
            Log.e(TAG, "egress proxy unavailable", e)
            return SessionGrant.Refused("Rift's network proxy could not start, so the browser may not load pages.")
        }
        browser = RegisteredBrowser(generation, binder, mode)
        _network.value = null
        Log.i(TAG, "browser registered for generation $generation, network $mode")
        return SessionGrant.Granted(endpoint.port.toInt(), endpoint.token, endpoint.realm, mode)
    }

    fun reportSandbox(generation: Long, report: SandboxReport) {
        val registered = browser?.takeIf { it.generation == generation } ?: return
        registered.sandbox = report
        _sandbox.value = report
    }

    fun reportNetwork(generation: Long, report: NetworkReport) {
        val registered = browser?.takeIf { it.generation == generation } ?: return
        registered.network = report
        _network.value = report
        Log.i(TAG, "browser network in generation $generation: proxied=${report.proxied} locked=${report.locked}")
    }

    fun decide(generation: Long, url: String): NavigationDecision {
        if (generation != currentGeneration) {
            return NavigationDecision.Block(Fact("stale-session", "This browser window belongs to a session that has ended."), false, displaySafe(url))
        }
        val registered = browser?.takeIf { it.generation == generation }
        val sandboxVerified = registered?.sandbox?.verified == true
        val decision = when (val d = navigator.decide(url, sandboxVerified)) {
            is Navigation.Proceed -> NavigationDecision.Proceed(d.notes.map(::fact))
            is Navigation.Confirm -> NavigationDecision.Confirm(d.reasons.map(::fact), d.notes.map(::fact), displaySafe(url))
            is Navigation.Block -> return NavigationDecision.Block(fact(d.reason), d.inspectAnyway, displaySafe(url))
        }
        // INV-14: nothing loads unless every request goes through the proxy,
        // behind the lock unless the user chose reduced isolation.
        val network = registered?.network
        val bounded = network != null && network.proxied &&
            (registered.mode == NetworkMode.REDUCED || (network.locked && NetworkLock.active))
        if (!bounded) {
            return NavigationDecision.Block(
                Fact("network-unbounded", "Rift could not confirm that this browser reaches the network only through its proxy, so the page was not loaded."),
                false,
                displaySafe(url),
            )
        }
        return decision
    }

    fun typed(input: String): String = typedAddress(input)

    fun submitDownload(generation: Long, info: DownloadInfo) {
        val opened = sessions ?: return
        if (generation != currentGeneration) return
        val key = downloadKeys.incrementAndGet()
        _downloads.update { it + Download(key, displaySafe(info.url)) }
        transfers.execute {
            val outcome = try {
                Download(key, displaySafe(info.url), file = opened.download(generation.toULong(), info))
            } catch (e: DownloadFailure) {
                Download(key, displaySafe(info.url), failure = describe(e))
            }
            Log.i(TAG, "download $key in generation $generation: " + (outcome.file?.let { "stored ${it.size} bytes" } ?: "not captured: ${outcome.failure}"))
            if (generation == currentGeneration) {
                _downloads.update { list -> list.map { if (it.key == key) outcome else it } }
                outcome.file?.let { scan(it.id, scanWorker) }
            }
        }
    }

    /**
     * Scans quarantined file `fileId` (§12.1): the core's hash check, then
     * the rules in a fresh isolated worker. `service` is the worker
     * component; tests substitute misbehaving ones.
     */
    fun scan(fileId: String, service: Class<out Service> = PreviewService::class.java) {
        val generation = currentGeneration ?: return
        val opened = sessions ?: return
        val intel = database ?: return
        _verdicts.update { it + (fileId to null) }
        scanning.execute {
            val started = android.os.SystemClock.elapsedRealtime()
            val verdict = try {
                when (val start = opened.scan(generation.toULong(), fileId, intel)) {
                    is ScanStart.Done -> start.verdict
                    is ScanStart.Run -> start.job.use { job -> Scanner.scan(app, job, service) }
                }
            } catch (e: ScanFailure) {
                // Only when the file or session is gone; worker failures become verdicts.
                Log.w(TAG, "scan of $fileId not run: $e")
                null
            }
            Log.i(TAG, "scan of $fileId in generation $generation after ${android.os.SystemClock.elapsedRealtime() - started} ms: " +
                (verdict?.let { v -> "${v.label}; findings ${v.findings.map { "${it.check}:${it.id}" }}; gaps ${v.gaps}" } ?: "not run"))
            if (generation == currentGeneration) {
                _verdicts.update { if (verdict == null) it - fileId else it + (fileId to verdict) }
            }
        }
    }

    /**
     * Installs the TUF repository in `repository`, verified against
     * `trustedRoot` (§13.2), after a fresh worker has compiled its rules.
     * On any failure the current database stays.
     */
    fun installIntel(trustedRoot: ByteArray, repository: File, service: Class<out Service> = PreviewService::class.java) {
        val intel = database ?: return
        _intelMessage.value = "Checking the update…"
        scanning.execute {
            _intelMessage.value = try {
                intel.verifyOffline(trustedRoot, repository.path).use { pending ->
                    Scanner.check(app, pending, service)
                    _intel.value = pending.install(nowUnix())
                    "Installed ${pending.snapshot()}."
                }
            } catch (e: IntelFailure) {
                Log.w(TAG, "intel update not installed", e)
                Scanner.describe(e)
            } catch (e: IsolatedWorker.Failed) {
                "the update's rules could not be checked: ${e.message}"
            }
            Log.i(TAG, "intel install: ${_intelMessage.value}")
        }
    }

    /** Debug builds carry a signed demo database (`android/build.sh`); release builds do not. */
    fun demoIntelAvailable(): Boolean = try {
        app.assets.list(DEMO_INTEL)?.contains("root.json") == true
    } catch (e: java.io.IOException) {
        false
    }

    fun installDemoIntel(service: Class<out Service> = PreviewService::class.java) {
        scanning.execute {
            val copy = File(app.cacheDir, "intel-import")
            try {
                copy.deleteRecursively()
                copyAssets("$DEMO_INTEL/repo", File(copy, "repo"))
                val root = app.assets.open("$DEMO_INTEL/root.json").use { it.readBytes() }
                installIntel(root, File(copy, "repo"), service)
                // Runs after the install on the same executor; the copy is not needed after.
                scanning.execute { copy.deleteRecursively() }
            } catch (e: java.io.IOException) {
                _intelMessage.value = "the demo database is not available in this build: ${e.message}"
            }
        }
    }

    private fun copyAssets(path: String, target: File) {
        val children = app.assets.list(path).orEmpty()
        if (children.isEmpty()) {
            target.parentFile?.mkdirs()
            app.assets.open(path).use { input -> target.outputStream().use { input.copyTo(it) } }
        } else {
            target.mkdirs()
            for (child in children) copyAssets("$path/$child", File(target, child))
        }
    }

    private const val DEMO_INTEL = "intel-demo"

    /** The user's per-session exception for one local host name (INV-13). */
    fun allowLocalHost(host: String) = worker.execute {
        val generation = currentGeneration ?: return@execute
        val opened = sessions ?: return@execute
        if (opened.allowLocalHost(generation.toULong(), host)) {
            _localHosts.value = opened.localHosts(generation.toULong())
        }
    }

    /**
     * Previews quarantined file `fileId` in a fresh isolated worker (§8.6).
     * `service` is the worker component; tests substitute misbehaving ones.
     */
    fun preview(fileId: String, service: Class<out Service> = PreviewService::class.java) {
        val generation = currentGeneration ?: return
        val opened = sessions ?: return
        _previews.update { it + (fileId to Preview(fileId)) }
        previewing.execute {
            val started = android.os.SystemClock.elapsedRealtime()
            val outcome = try {
                when (val prepared = opened.preview(generation.toULong(), fileId, Previewer.MAX_SIDE.toUInt(), Previewer.MAX_SIDE.toUInt())) {
                    is CorePreview.Rendered -> prepared.job.use { job -> Preview(fileId, bitmap = Previewer.render(app, job, service)) }
                    is CorePreview.Text -> Preview(fileId, text = prepared.text, note = textNote(prepared))
                }
            } catch (e: PreviewFailure) {
                Preview(fileId, failure = describe(e))
            } catch (e: IsolatedWorker.Failed) {
                Preview(fileId, failure = e.message)
            } catch (e: Exception) {
                Log.e(TAG, "preview failed", e)
                Preview(fileId, failure = "the preview failed: ${e.javaClass.simpleName}")
            }
            Log.i(TAG, "preview of $fileId in generation $generation after ${android.os.SystemClock.elapsedRealtime() - started} ms: " +
                (outcome.bitmap?.let { "${it.width}x${it.height}" } ?: outcome.text?.let { "text, ${it.length} chars" } ?: "failed: ${outcome.failure}"))
            if (generation == currentGeneration) _previews.update { it + (fileId to outcome) }
        }
    }

    private fun textNote(t: CorePreview.Text) = listOfNotNull(
        "Plain text, not interpreted. Control and direction-changing characters are shown as \\u{…}.",
        "Only the first 64 KiB is shown.".takeIf { t.truncated },
        "Bytes that are not valid UTF-8 are shown as \uFFFD.".takeIf { t.replaced },
    ).joinToString(" ")

    private fun describe(e: PreviewFailure): String = when (e) {
        is PreviewFailure.SessionEnded -> "the session this file belonged to has ended"
        is PreviewFailure.NotFound -> "the file is not in this session's quarantine"
        is PreviewFailure.Unsupported -> "Rift previews PNG, JPEG, WebP, PDF and plain-text content only"
        is PreviewFailure.TooLarge -> "files larger than ${e.limit} bytes are not previewed"
        is PreviewFailure.Storage -> "the quarantined copy could not be read: ${e.detail}"
        is PreviewFailure.Unconfined -> "the preview worker is not confined (${e.detail}), so previews are disabled"
        is PreviewFailure.BadReply -> "the preview worker sent an invalid reply (${e.detail}) and was stopped"
        is PreviewFailure.Worker -> "the file could not be previewed: ${e.detail}"
        is PreviewFailure.Poisoned -> "session state is unusable after an internal error"
    }

    fun rendererGone(generation: Long, crashed: Boolean) {
        Log.w(TAG, "renderer gone (crashed=$crashed) in generation $generation; ending the session")
        reset(generation)
    }

    /** The browser registered for disposal, detached so no further calls reach it. */
    internal fun detachBrowser(): IBrowser? = browser?.binder.also { browser = null }

    private fun fact(f: CoreFact) = Fact(f.code, f.text)
}
