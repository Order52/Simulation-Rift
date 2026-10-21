package org.simulationrift.app

import android.app.Application
import android.app.Service
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.net.Uri
import android.provider.OpenableColumns
import android.os.Handler
import android.os.Looper
import android.util.Log
import java.io.File
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.flow.update
import org.simulationrift.bridge.Fact
import org.simulationrift.bridge.IBrowser
import org.simulationrift.bridge.NavigationDecision
import org.simulationrift.bridge.NetworkMode
import org.simulationrift.bridge.PageWatch
import org.simulationrift.bridge.Rift
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
import org.simulationrift.core.PendingIntel
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

    /** A file another app just handed over and Rift took in, for the home screen to open; cleared once opened. */
    private val _handedOver = MutableStateFlow<String?>(null)
    val handedOver: StateFlow<String?> = _handedOver

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

    // Scans, a bounded number at a time: each holds its file (up to 32 MiB)
    // and the rules in memory, and has its own fresh worker, until the worker
    // is retired. A hung worker costs its own job up to the 17 s deadline,
    // not the files queued behind it, unless every slot is hung at once.
    private val scanning = Executors.newFixedThreadPool(SCAN_WORKERS) { Thread(it, "rift-scan") }

    // Database updates, one at a time and in order.
    private val updating = Executors.newSingleThreadExecutor { Thread(it, "rift-intel") }
    @Volatile private var database: Intel? = null
    /** Counted down once the first attempt to open [database] is over, whatever its outcome. */
    private val intelOpened = CountDownLatch(1)

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

    /** The current session's page watch (§10.5), with its generation. */
    private class Watch(val generation: Long, val watcher: PageWatcher)
    @Volatile private var watch: Watch? = null

    private fun watcher(generation: Long): PageWatcher? = watch?.takeIf { it.generation == generation }?.watcher

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
            WeeklyStats.open(app)
            updating.execute {
                // An update's working copy left by a kill during an install (found by
                // F4). First on the update executor, so before any new install.
                File(app.filesDir, "rift/import").deleteRecursively()
                forgetVault()
            }
            worker.execute(::openAndStart)
        }
    }

    /**
     * Earlier versions could keep files in an encrypted vault; Rift no
     * longer keeps anything after a session, so what such a version left is
     * deleted: the vault's files, its lock settings and its keystore key.
     */
    private fun forgetVault() {
        val dir = File(app.filesDir, "rift/vault")
        val settings = File(app.filesDir, "rift/vault-lock")
        if (dir.exists() && !dir.deleteRecursively()) Log.e(TAG, "an earlier version's vault could not be deleted")
        if (settings.exists() && !settings.delete()) Log.e(TAG, "an earlier version's vault settings could not be deleted")
        try {
            val keys = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (keys.containsAlias(OLD_VAULT_KEY)) keys.deleteEntry(OLD_VAULT_KEY)
        } catch (e: java.security.GeneralSecurityException) {
            Log.e(TAG, "an earlier version's vault key could not be deleted", e)
        } catch (e: java.io.IOException) {
            Log.e(TAG, "an earlier version's vault key could not be deleted", e)
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
        _handedOver.value = null
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
        } finally {
            intelOpened.countDown()
        }
    }

    private fun nowUnix(): ULong = (System.currentTimeMillis() / 1000).toULong()

    private fun start(opened: Sessions, recovered: Long?) {
        try {
            val generation = opened.start().toLong()
            // Before the generation is current, so its first decision is watched.
            watch = Watch(generation, PageWatcher(NetworkLock.newSession(), WeeklyStats::count))
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
            sessions?.egress(generation.toULong(), database)?.port?.toInt()
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
            // With the database, the proxy checks every request's destination (§10.3).
            opened.egress(generation.toULong(), database)
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
        val decision = when (val d = navigator.decide(url, sandboxVerified, database, nowUnix())) {
            is Navigation.Proceed -> NavigationDecision.Proceed(d.notes.map(::fact))
            is Navigation.Confirm -> NavigationDecision.Confirm(d.reasons.map(::fact), d.notes.map(::fact), displaySafe(url))
            is Navigation.Block -> NavigationDecision.Block(fact(d.reason), d.inspectAnyway, displaySafe(url))
        }
        watcher(generation)?.navigation(url, decision)
        WeeklyStats.count(Tally.LINK_CHECKED)
        if (decision is NavigationDecision.Block) return decision
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
        browsed = generation
        return decision
    }

    /** The last generation whose window was allowed to load a page. */
    @Volatile private var browsed: Long? = null

    /**
     * Whether `generation` has loaded (or been allowed to load) any page. A
     * link from another app opens in a session that has not, so it never
     * shares one with pages opened before it.
     */
    fun hasBrowsed(generation: Long): Boolean = browsed == generation

    fun typed(input: String): String = typedAddress(input)

    /**
     * A file another app handed to Rift (ACTION_VIEW or ACTION_SEND): read
     * through the temporary grant it came with, never parsed here, and
     * streamed into this session's quarantine as a download is (§11.1).
     * Then it is scanned and previewed in isolated workers, and the home
     * screen opens it. Only `content:` URIs of other apps are read: a
     * `file:` path or one of Rift's own providers would make Rift read
     * with its own rights on another app's behalf.
     */
    fun takeIn(uri: Uri) {
        val generation = currentGeneration ?: return
        val opened = sessions ?: return
        val key = downloadKeys.incrementAndGet()
        val label = "a file from another app"
        _downloads.update { it + Download(key, label) }
        // Its own thread, not a transfer one: the other app controls how fast
        // (or whether) the content arrives, and must not hold up downloads. A
        // file still arriving at reset is not listed or kept (the generation
        // check here and the intake's cancellation).
        Thread({
            val outcome = try {
                Download(key, label, file = receive(opened, generation, uri))
            } catch (e: DownloadFailure) {
                Download(key, label, failure = describe(e))
            } catch (e: IOException) {
                Download(key, label, failure = "the other app's file could not be read: ${e.javaClass.simpleName}")
            } catch (e: SecurityException) {
                Download(key, label, failure = "the other app did not let Rift read the file")
            } catch (e: IllegalArgumentException) {
                Download(key, label, failure = e.message ?: "the file was refused")
            }
            Log.i(TAG, "file $key handed over in generation $generation: " + (outcome.file?.let { "stored ${it.size} bytes" } ?: "not taken in: ${outcome.failure}"))
            if (generation == currentGeneration) {
                _downloads.update { list -> list.map { if (it.key == key) outcome else it } }
                outcome.file?.let {
                    scan(it.id, scanWorker)
                    preview(it.id)
                    _handedOver.value = it.id
                }
            }
        }, "rift-intake").apply { isDaemon = true }.start()
    }

    fun handedOverShown() {
        _handedOver.value = null
    }

    private fun receive(opened: Sessions, generation: Long, uri: Uri): QuarantinedFile {
        require(uri.scheme == "content") { "Rift takes files only as content from another app, not ${displaySafe(uri.scheme ?: "a bare path")}" }
        val owner = uri.authority?.let { app.packageManager.resolveContentProvider(it, 0)?.packageName }
        require(owner != app.packageName && owner != Rift.BROWSER_PACKAGE) { "Rift does not take files from itself" }
        val resolver = app.contentResolver
        val name = resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst() && !cursor.isNull(0)) cursor.getString(0) else null
        } ?: uri.lastPathSegment ?: "file"
        opened.beginIntake(generation.toULong(), name, resolver.getType(uri)).use { intake ->
            val input = resolver.openInputStream(uri) ?: throw IOException("the other app gave no content")
            input.use {
                val buffer = ByteArray(INTAKE_CHUNK)
                while (true) {
                    val n = it.read(buffer)
                    if (n < 0) break
                    if (n > 0) intake.write(buffer.copyOf(n))
                }
            }
            return intake.finish()
        }
    }

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
            watcher(generation)?.let { watcher ->
                outcome.file?.let { watcher.downloaded(it.displayName) } ?: watcher.downloadRefused(outcome.url, outcome.failure.orEmpty())
            }
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
            if (verdict != null) {
                val name = _downloads.value.firstNotNullOfOrNull { it.file?.takeIf { f -> f.id == fileId }?.displayName } ?: "a file"
                watcher(generation)?.verdict(name, verdict)
                WeeklyStats.count(Tally.FILE_SCANNED)
            }
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
    fun installIntel(trustedRoot: ByteArray, repository: File, service: Class<out Service> = PreviewService::class.java) =
        install(service) { intel -> intel.verifyOffline(trustedRoot, repository.path) }

    /**
     * Fetches and installs the update published at `base` (its `metadata/`
     * and `targets/` directories) through the core's checked fetcher, verified
     * against [trustedRoot]. Local addresses are reached only for host names
     * the user allowed in this session (INV-13).
     */
    fun updateIntelOnline(base: String, service: Class<out Service> = PreviewService::class.java) {
        val root = trustedRoot()
        if (root == null) {
            _intelMessage.value = "This build has no trusted root, so it cannot install updates."
            return
        }
        val trimmed = base.trimEnd('/')
        val localHosts = _localHosts.value
        install(service, "Downloading the update…") { intel ->
            intel.verifyOnline(root, "$trimmed/metadata/", "$trimmed/targets/", localHosts)
        }
    }

    /** The update address this build was given (`RIFT_INTEL_URL`, android/build.sh), if any. */
    fun updateSource(): String? = try {
        app.assets.open(UPDATE_SOURCE).use { it.readBytes().decodeToString().trim() }.takeIf { it.startsWith("https://") }
    } catch (e: java.io.FileNotFoundException) {
        null
    }

    /** Verifies with `verify`, has a fresh worker compile the rules, then installs; on any failure the current database stays. */
    private fun install(service: Class<out Service>, progress: String = "Checking the update…", verify: (Intel) -> PendingIntel) {
        _intelMessage.value = progress
        updating.execute {
            // Opened on the session worker at start (before the first session,
            // so that its proxy gets it); an install asked for sooner waits.
            intelOpened.await(INTEL_OPEN_TIMEOUT_S, TimeUnit.SECONDS)
            val intel = database ?: run {
                _intelMessage.value = "The threat database could not be opened, so nothing was installed."
                return@execute
            }
            _intelMessage.value = try {
                verify(intel).use { pending ->
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

    /**
     * The root that imported updates are verified against (§13.2): the
     * production root if the build has one (`RIFT_INTEL_ROOT`, android/build.sh),
     * else the demo root of a debug build. Null: this build cannot install updates.
     */
    fun trustedRoot(): ByteArray? = listOf(PRODUCTION_ROOT, "$DEMO_INTEL/root.json").firstNotNullOfOrNull { path ->
        try {
            app.assets.open(path).use { it.readBytes() }
        } catch (e: java.io.FileNotFoundException) {
            null
        }
    }

    /**
     * Imports the repository in `tree`, which the user chose, verified against
     * [trustedRoot]. The copy is Rift's own state (files/rift, on the disposal
     * allowlist) and is removed after the attempt.
     */
    internal fun importIntel(tree: IntelImport.Tree, service: Class<out Service> = PreviewService::class.java) {
        _intelMessage.value = "Reading the update…"
        updating.execute {
            val root = trustedRoot()
            if (root == null) {
                _intelMessage.value = "This build has no trusted root, so it cannot install updates."
                return@execute
            }
            val copy = File(app.filesDir, "rift/import")
            try {
                val copied = IntelImport.copy(tree, File(copy, "repo"))
                Log.i(TAG, "intel import: copied ${copied.files} files, skipped ${copied.skipped}")
                installIntel(root, File(copy, "repo"), service)
            } catch (e: IntelImport.Refused) {
                _intelMessage.value = "the update was not read: ${e.message}"
            } catch (e: java.io.IOException) {
                Log.w(TAG, "intel import failed", e)
                _intelMessage.value = "the update could not be read from the chosen folder"
            } catch (e: SecurityException) {
                Log.w(TAG, "intel import failed", e)
                _intelMessage.value = "the chosen folder could not be read"
            }
            // Runs after the install on the same executor.
            updating.execute { copy.deleteRecursively() }
        }
    }

    /** Debug builds carry a signed demo database (`android/build.sh`); release builds do not. */
    fun demoIntelAvailable(): Boolean = try {
        app.assets.list(DEMO_INTEL)?.contains("root.json") == true
    } catch (e: java.io.IOException) {
        false
    }

    fun installDemoIntel(service: Class<out Service> = PreviewService::class.java) {
        updating.execute {
            if (!demoIntelAvailable()) {
                _intelMessage.value = "the demo database is not available in this build"
                return@execute
            }
            // Rift's own state (files/rift), so a reset meanwhile finds no stray file.
            val copy = File(app.filesDir, "rift/import")
            try {
                copy.deleteRecursively()
                copyAssets("$DEMO_INTEL/repo", File(copy, "repo"))
                val root = app.assets.open("$DEMO_INTEL/root.json").use { it.readBytes() }
                installIntel(root, File(copy, "repo"), service)
                // Runs after the install on the same executor; the copy is not needed after.
                updating.execute { copy.deleteRecursively() }
            } catch (e: java.io.IOException) {
                // A full disk, for one (F6); what was copied is not left behind.
                Log.w(TAG, "demo database not copied", e)
                copy.deleteRecursively()
                _intelMessage.value = "the demo database could not be copied, so nothing was installed: ${e.message}"
            }
        }
    }

    private fun copyAssets(path: String, target: File) {
        val children = app.assets.list(path).orEmpty()
        if (children.isEmpty()) {
            makeDirectory(target.parentFile!!)
            app.assets.open(path).use { input -> target.outputStream().use { input.copyTo(it) } }
        } else {
            makeDirectory(target)
            for (child in children) copyAssets("$path/$child", File(target, child))
        }
    }

    /** mkdirs reports failure (on a full disk, for one) only by returning false. */
    private fun makeDirectory(dir: File) {
        if (!dir.isDirectory && !dir.mkdirs()) throw java.io.IOException("could not create ${dir.name}")
    }

    private const val INTEL_OPEN_TIMEOUT_S = 30L
    private const val DEMO_INTEL = "intel-demo"
    private const val PRODUCTION_ROOT = "intel-root/root.json"
    private const val UPDATE_SOURCE = "intel-root/update-url.txt"

    /** Concurrent scans: enough that one hung worker does not hold the queue, few enough for memory. */
    private const val SCAN_WORKERS = 2

    /** Bytes per copy into the core when another app hands over a file. */
    private const val INTAKE_CHUNK = 256 * 1024

    /** The keystore alias of the vault key earlier versions made ([forgetVault]). */
    private const val OLD_VAULT_KEY = "rift-vault-wrap"

    /**
     * A per-session exception for one local host name (INV-13). The home
     * screen no longer offers it; the instrumented tests use it to reach
     * their fixture server.
     */
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
        render(fileId, "generation $generation", service, { max -> opened.preview(generation.toULong(), fileId, max, max) }) { outcome ->
            if (generation == currentGeneration) _previews.update { it + (fileId to outcome) }
        }
    }

    /**
     * Runs one prepared preview on the preview executor: a fresh isolated
     * worker for images and PDFs, or the core's escaped text. `publish`
     * receives the outcome, and decides whether it still belongs on screen.
     */
    internal fun render(
        key: String,
        owner: String,
        service: Class<out Service>,
        prepare: (UInt) -> CorePreview,
        publish: (Preview) -> Unit,
    ) = previewing.execute {
        val started = android.os.SystemClock.elapsedRealtime()
        val outcome = try {
            when (val prepared = prepare(Previewer.MAX_SIDE.toUInt())) {
                is CorePreview.Rendered -> prepared.job.use { job -> Preview(key, bitmap = Previewer.render(app, job, service)) }
                is CorePreview.Text -> Preview(key, text = prepared.text, note = textNote(prepared))
            }
        } catch (e: PreviewFailure) {
            Preview(key, failure = describe(e))
        } catch (e: IsolatedWorker.Failed) {
            Preview(key, failure = e.message)
        } catch (e: Exception) {
            Log.e(TAG, "preview failed", e)
            Preview(key, failure = "the preview failed: ${e.javaClass.simpleName}")
        }
        Log.i(TAG, "preview of $key in $owner after ${android.os.SystemClock.elapsedRealtime() - started} ms: " +
            (outcome.bitmap?.let { "${it.width}x${it.height}" } ?: outcome.text?.let { "text, ${it.length} chars" } ?: "failed: ${outcome.failure}"))
        publish(outcome)
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

    /**
     * Opens the browser app's window for `generation` (it refuses to load
     * pages without the lock's terms). Three times on CI (API 34), Android
     * removed the browser's task ("remove task") within 50 ms of a window
     * started right after a wipe, so the browser never registered and no
     * window appeared. Not by the clear itself, which removes the app's
     * recent tasks before it starts (AOSP 14); the cause is not confirmed.
     * If the browser has not registered for `generation` within
     * [WINDOW_ATTACH_MS], the window is opened again, at most
     * [WINDOW_REOPENS] times; each reopen is logged.
     */
    fun openWindow(context: Context, generation: Long, url: String?, reopens: Int = WINDOW_REOPENS) {
        context.startActivity(
            Intent().setComponent(Rift.BROWSER_ACTIVITY)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                .putExtra(Rift.EXTRA_GENERATION, generation)
                .apply { url?.let { putExtra(Rift.EXTRA_URL, it) } },
        )
        if (reopens <= 0) return
        val appContext = context.applicationContext
        Handler(Looper.getMainLooper()).postDelayed({
            if (browser?.generation != generation && currentGeneration == generation) {
                Log.w(TAG, "browser window for generation $generation did not attach; opening it again")
                openWindow(appContext, generation, url, reopens - 1)
            }
        }, WINDOW_ATTACH_MS)
    }

    /**
     * How long a new window may take to register its session. Registration
     * comes before the engine starts, 0.2–1.3 s after the process on CI.
     */
    private const val WINDOW_ATTACH_MS = 6_000L
    private const val WINDOW_REOPENS = 2

    fun rendererGone(generation: Long, crashed: Boolean) {
        Log.w(TAG, "renderer gone (crashed=$crashed) in generation $generation; ending the session")
        if (generation != currentGeneration) return
        _notice.value = "Session $generation ended because the page's renderer " +
            (if (crashed) "crashed. A crash can be a sign of an attack on the browser engine; " else "was stopped by the system; ") +
            "the session's data was wiped."
        reset(generation)
    }

    // ---- Live page watch (§10.5) ---------------------------------------------------

    /**
     * The browser engine refused something only it sees (a permission, a
     * file chooser, fullscreen). Validated: the generation must be current
     * with a registered browser, and `kind` one of [PageWatch.Attempt].
     */
    fun reportAttempt(generation: Long, kind: String, origin: String) {
        if (browser?.generation != generation || kind !in PageWatch.Attempt.ALL) return
        watcher(generation)?.attempt(kind, origin.take(MAX_ORIGIN_CHARS))
    }

    /** `generation`'s page watch, up to date, or null if it is not the current session. */
    fun pageWatch(generation: Long): PageWatch? {
        val watcher = watcher(generation)?.takeIf { generation == currentGeneration } ?: return null
        watcher.egress(egressStats())
        watcher.lock(NetworkLock.dropped.value)
        return watcher.snapshot(coverage(generation))
    }

    /** What the watch covers in this session, so that "nothing seen" has a meaning. */
    private fun coverage(generation: Long): List<String> = listOfNotNull(
        when (val intel = _intel.value) {
            is IntelStatus.Installed ->
                "Threat database ${intel.snapshot}" + (if (intel.demo) " (demo: it lists only Rift's own test content)" else "") +
                    (if (intel.stale) ", out of date" else "") + ": checked for every address and every request through Rift's proxy."
            else -> "No threat database is installed: addresses are checked by Rift's built-in rules only."
        },
        "Watched: requests for location, camera, microphone, files and fullscreen; connections to your local network; " +
            "connections around the proxy; every download, scanned in an isolated worker.",
        "Not seen: what scripts do inside the page, what you type into it, the contents of HTTPS traffic, and what a page writes to the clipboard.",
        ("Reduced isolation: there is no network lock in this session, so connections around the proxy are neither stopped nor seen.")
            .takeIf { _reduced.value == generation },
    )

    private const val MAX_ORIGIN_CHARS = 2_048

    /** The browser registered for disposal, detached so no further calls reach it. */
    internal fun detachBrowser(): IBrowser? = browser?.binder.also { browser = null }

    private fun fact(f: CoreFact) = Fact(f.code, f.text)
}
