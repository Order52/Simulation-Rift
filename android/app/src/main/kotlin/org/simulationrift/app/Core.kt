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
import org.simulationrift.core.DownloadFailure
import org.simulationrift.core.DownloadInfo
import org.simulationrift.core.Navigation
import org.simulationrift.core.QuarantinedFile
import org.simulationrift.core.Navigator
import org.simulationrift.core.PreviewFailure
import org.simulationrift.core.SessionFailure
import org.simulationrift.core.Sessions
import org.simulationrift.core.displaySafe
import org.simulationrift.core.typedAddress
import org.simulationrift.core.Fact as CoreFact

const val TAG = "Rift"

/**
 * The trusted controller (main process only). rift-core makes every decision;
 * this object sequences it for Android and tracks which `:browser` belongs to
 * which generation.
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

    private class RegisteredBrowser(val generation: Long, val binder: IBrowser) {
        @Volatile var sandbox: SandboxReport? = null
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

    private val _downloads = MutableStateFlow<List<Download>>(emptyList())
    val downloads: StateFlow<List<Download>> = _downloads

    private val _localHosts = MutableStateFlow<List<String>>(emptyList())
    val localHosts: StateFlow<List<String>> = _localHosts

    /** A preview of one quarantined file: pixels from the isolated worker, or why there are none. */
    data class Preview(val fileId: String, val bitmap: Bitmap? = null, val failure: String? = null) {
        val running get() = bitmap == null && failure == null
    }

    private val _previews = MutableStateFlow<Map<String, Preview>>(emptyMap())
    val previews: StateFlow<Map<String, Preview>> = _previews

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
        val opened = try {
            Sessions.open(File(app.filesDir, "rift").path, AndroidBrowserDisposal(app))
        } catch (e: SessionFailure) {
            fail(null, e)
            return
        }
        sessions = opened
        start(opened, opened.recovery().interruptedGeneration?.toLong())
    }

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
        currentGeneration = null
        // Recovery happens only through a fresh open, which repeats cleanup.
        opened?.close()
        sessions = null
        _state.value = State.Failed(describe(e))
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

    // ---- Interface for :browser (via CoreService) ----------------------------

    fun registerBrowser(generation: Long, binder: IBrowser): Boolean {
        if (generation != currentGeneration) return false
        browser = RegisteredBrowser(generation, binder)
        return true
    }

    fun reportSandbox(generation: Long, report: SandboxReport) {
        val registered = browser?.takeIf { it.generation == generation } ?: return
        registered.sandbox = report
        _sandbox.value = report
    }

    fun decide(generation: Long, url: String): NavigationDecision {
        if (generation != currentGeneration) {
            return NavigationDecision.Block(Fact("stale-session", "This browser window belongs to a session that has ended."), false, displaySafe(url))
        }
        val sandboxVerified = browser?.takeIf { it.generation == generation }?.sandbox?.verified == true
        return when (val d = navigator.decide(url, sandboxVerified)) {
            is Navigation.Proceed -> NavigationDecision.Proceed(d.notes.map(::fact))
            is Navigation.Confirm -> NavigationDecision.Confirm(d.reasons.map(::fact), d.notes.map(::fact), displaySafe(url))
            is Navigation.Block -> NavigationDecision.Block(fact(d.reason), d.inspectAnyway, displaySafe(url))
        }
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
            }
        }
    }

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
                opened.preview(generation.toULong(), fileId, Previewer.MAX_SIDE.toUInt(), Previewer.MAX_SIDE.toUInt()).use { job ->
                    Preview(fileId, bitmap = Previewer.render(app, job, service))
                }
            } catch (e: PreviewFailure) {
                Preview(fileId, failure = describe(e))
            } catch (e: Previewer.Failed) {
                Preview(fileId, failure = e.message)
            } catch (e: Exception) {
                Log.e(TAG, "preview failed", e)
                Preview(fileId, failure = "the preview failed: ${e.javaClass.simpleName}")
            }
            Log.i(TAG, "preview of $fileId in generation $generation after ${android.os.SystemClock.elapsedRealtime() - started} ms: " +
                (outcome.bitmap?.let { "${it.width}x${it.height}" } ?: "failed: ${outcome.failure}"))
            if (generation == currentGeneration) _previews.update { it + (fileId to outcome) }
        }
    }

    private fun describe(e: PreviewFailure): String = when (e) {
        is PreviewFailure.SessionEnded -> "the session this file belonged to has ended"
        is PreviewFailure.NotFound -> "the file is not in this session's quarantine"
        is PreviewFailure.Unsupported -> "Rift previews PNG, JPEG, WebP and PDF content only"
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
