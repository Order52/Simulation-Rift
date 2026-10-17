package org.simulationrift.app

import android.app.Application
import android.content.Context
import android.util.Log
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.simulationrift.core.Navigation
import org.simulationrift.core.Navigator
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

    private val _state = MutableStateFlow<State>(State.Opening)
    val state: StateFlow<State> = _state

    /** Last renderer-sandbox report, for the diagnostics screen. */
    private val _sandbox = MutableStateFlow<SandboxReport?>(null)
    val sandbox: StateFlow<SandboxReport?> = _sandbox

    // Session work is serialized here. Disposal blocks until :browser is gone,
    // so it never runs on the UI thread or on a Binder thread.
    private val worker = Executors.newSingleThreadExecutor { Thread(it, "rift-core") }
    private val started = AtomicBoolean(false)
    private lateinit var app: Context

    private var sessions: Sessions? = null // only touched on [worker]

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
        _state.value = State.Failed(e.message ?: e.javaClass.simpleName)
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

    fun rendererGone(generation: Long, crashed: Boolean) {
        Log.w(TAG, "renderer gone (crashed=$crashed) in generation $generation; ending the session")
        reset(generation)
    }

    /** The browser registered for disposal, detached so no further calls reach it. */
    internal fun detachBrowser(): IBrowser? = browser?.binder.also { browser = null }

    private fun fact(f: CoreFact) = Fact(f.code, f.text)
}
