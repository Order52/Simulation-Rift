package org.simulationrift.app

import android.content.ComponentName
import android.content.Context
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.IBinder
import android.os.RemoteException
import android.util.Log
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import org.simulationrift.bridge.Rift
import rikka.shizuku.Shizuku

/**
 * Extra isolation (§8.9): optional, off until the user turns it on, and
 * only with Shizuku (started with adb or root) or Sui (root), which run
 * Rift's helper, [HardeningService]. The helper uses Android's own tools on
 * the browser app:
 *
 * - shell or root: Android ignores the browser app's clipboard reads and
 *   writes, so nothing reaches the phone's clipboard from it, whatever the
 *   engine does; and at each reset the controller has Android clear the
 *   browser app itself instead of asking the browser to.
 * - root: firewall rules let the browser app's UID connect only to this
 *   session's proxy on loopback and into the network lock's VPN, which
 *   closes the loopback gap (§12) and keeps it off the network if the VPN
 *   goes.
 *
 * Each change is read back before it is shown as in effect. Without it, or
 * when it fails, Rift is as isolated as it is without root.
 */
object Hardening {

    /** One measure's state, as the home screen shows it. */
    sealed interface Measure {
        data object InEffect : Measure
        data class Pending(val text: String) : Measure
        data class Problem(val text: String) : Measure
    }

    sealed interface Helper {
        data object Off : Helper
        data object NotRunning : Helper
        data object AskingPermission : Helper
        data object Denied : Helper
        data object Connecting : Helper
        data class Connected(val root: Boolean) : Helper
        data class Failed(val reason: String) : Helper
    }

    data class Status(
        val on: Boolean = false,
        val helper: Helper = Helper.Off,
        val clipboard: Measure = Measure.Pending(""),
        val wipe: Measure = Measure.Pending(""),
        val network: Measure = Measure.Pending(""),
        /** Turned off while the helper was away: what it changed stays until it runs again. */
        val undoPending: Boolean = false,
    )

    private const val TAG = "RiftHardening"
    private const val REQUEST_CODE = 52
    private const val CALL_TIMEOUT_S = 30L
    private const val CONNECT_WAIT_S = 10L

    /** The user's choice, under rift-core's directory (kept across resets). */
    private const val CHOICE_FILE = "rift/extra-isolation"
    private const val ON = "on"
    private const val APPLIED = "applied"
    private const val UNDO = "undo"

    private val _status = MutableStateFlow(Status())
    val status: StateFlow<Status> = _status

    /** Every call to the helper, in order, off the main thread. */
    private val work = Executors.newSingleThreadExecutor { Thread(it, "rift-hardening") }

    private lateinit var app: Context

    @Volatile private var helper: IHardening? = null

    @Volatile private var root = false

    /** The current session's proxy port, once its browser has registered. */
    @Volatile private var sessionPort: Int? = null

    private val choiceFile get() = File(app.filesDir, CHOICE_FILE)

    private fun choice(): String? = try {
        choiceFile.readText().trim().ifEmpty { null }
    } catch (e: java.io.IOException) {
        null
    }

    private fun setChoice(value: String?) {
        if (value == null) choiceFile.delete() else choiceFile.apply { parentFile?.mkdirs() }.writeText(value)
    }

    private val args by lazy {
        val info = app.packageManager.getPackageInfo(app.packageName, 0)
        Shizuku.UserServiceArgs(ComponentName(app.packageName, HardeningService::class.java.name))
            .tag("rift-hardening")
            // A new install starts a new helper, never one running older code.
            .version((info.lastUpdateTime / 1000).toInt())
            .processNameSuffix("hardening")
            // Ends with Rift's process.
            .daemon(false)
    }

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            val connected = IHardening.Stub.asInterface(binder)
            work.execute { connected(connected) }
        }

        override fun onServiceDisconnected(name: ComponentName) {
            helper = null
            _status.update { it.copy(helper = if (it.on) Helper.Failed("Rift's helper stopped") else Helper.Off) }
        }
    }

    /** From the main process's start (Core.ensureStarted), on the main thread. */
    fun init(context: Context) {
        app = context.applicationContext
        val choice = choice()
        _status.value = Status(on = choice == ON || choice == APPLIED, undoPending = choice == UNDO)
        Shizuku.addBinderReceivedListenerSticky {
            when {
                choice() != null -> connect()
                // Off, but allowed before: what an earlier install, or Rift's
                // data before it was cleared, turned on is undone, and the
                // helper stops (connected() undoes when the choice is off).
                !Shizuku.isPreV11() && Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED -> connect()
            }
        }
        Shizuku.addBinderDeadListener {
            helper = null
            _status.update { if (it.on) it.copy(helper = Helper.NotRunning) else it }
        }
        Shizuku.addRequestPermissionResultListener { code, result ->
            if (code != REQUEST_CODE) return@addRequestPermissionResultListener
            if (result == PackageManager.PERMISSION_GRANTED) connect() else _status.update { it.copy(helper = Helper.Denied) }
        }
        if (_status.value.on && !Shizuku.pingBinder()) _status.update { it.copy(helper = Helper.NotRunning) }
    }

    /** The user turned extra isolation on (main thread). */
    fun enable() {
        if (choice() != APPLIED) setChoice(ON)
        _status.update { it.copy(on = true, undoPending = false) }
        connect()
    }

    /** The user turned it off: what the helper changed is undone, now or when it next runs. */
    fun disable() {
        _status.update { it.copy(on = false) }
        work.execute {
            val connected = helper
            if (connected == null) {
                val wasApplied = choice() == APPLIED || choice() == UNDO
                setChoice(if (wasApplied) UNDO else null)
                _status.value = Status(undoPending = wasApplied)
                return@execute
            }
            undo(connected)
        }
    }

    private fun connect() {
        if (!Shizuku.pingBinder()) {
            _status.update { it.copy(helper = Helper.NotRunning) }
            return
        }
        if (Shizuku.isPreV11() || Shizuku.getVersion() < 13) {
            _status.update { it.copy(helper = Helper.Failed("Shizuku 13 or later is needed")) }
            return
        }
        if (Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED) {
            when {
                // Denied before: Shizuku does not ask again.
                Shizuku.shouldShowRequestPermissionRationale() -> _status.update { it.copy(helper = Helper.Denied) }
                // Shizuku's own prompt: the user has extra isolation on.
                else -> {
                    _status.update { it.copy(helper = Helper.AskingPermission) }
                    Shizuku.requestPermission(REQUEST_CODE)
                }
            }
            return
        }
        _status.update { it.copy(helper = Helper.Connecting) }
        try {
            Shizuku.bindUserService(args, connection)
        } catch (e: RuntimeException) {
            Log.e(TAG, "could not start the helper", e)
            _status.update { it.copy(helper = Helper.Failed("Shizuku could not start Rift's helper: ${e.message}")) }
        }
    }

    /** On [work]. */
    private fun connected(connected: IHardening) {
        try {
            helper = connected
            root = connected.uid() == 0
            if (choice() == UNDO || choice() == null) {
                undo(connected)
                return
            }
            setChoice(APPLIED)
            _status.update { it.copy(helper = Helper.Connected(root), wipe = Measure.Pending("Used from the next reset on.")) }
            applyClipboard(connected)
            val port = sessionPort
            when {
                !root -> _status.update { it.copy(network = Measure.Pending("Needs root: Shizuku started with adb runs as shell.")) }
                port != null -> applyNetwork(connected, port)
                else -> _status.update { it.copy(network = Measure.Pending("Applied when the next session's browser starts.")) }
            }
            Log.i(TAG, "helper connected as ${if (root) "root" else "shell"}")
        } catch (e: RemoteException) {
            lost(e)
        }
    }

    private fun undo(connected: IHardening) {
        val problems = try {
            listOfNotNull(
                connected.blockClipboard(false),
                if (connected.uid() == 0) connected.unlockNetwork(browserUid()) else null,
            )
        } catch (e: RemoteException) {
            listOf("Rift's helper stopped: ${e.message}")
        }
        if (problems.isEmpty()) {
            setChoice(null)
            helper = null
            try {
                Shizuku.unbindUserService(args, connection, true)
            } catch (e: RuntimeException) {
                Log.w(TAG, "the helper did not stop", e)
            }
            _status.value = Status()
            Log.i(TAG, "extra isolation undone")
        } else {
            setChoice(UNDO)
            _status.value = Status(undoPending = true, helper = Helper.Failed(problems.joinToString("; ")))
        }
    }

    private fun applyClipboard(connected: IHardening) {
        val problem = connected.blockClipboard(true)
        _status.update { it.copy(clipboard = problem?.let(Measure::Problem) ?: Measure.InEffect) }
    }

    private fun applyNetwork(connected: IHardening, port: Int) {
        val problem = connected.lockNetwork(browserUid(), port)
        _status.update { it.copy(network = problem?.let(Measure::Problem) ?: Measure.InEffect) }
        if (problem != null) Log.e(TAG, "network rules not in effect: $problem")
    }

    private fun browserUid(): Int = app.packageManager.getApplicationInfo(Rift.BROWSER_PACKAGE, 0).uid

    private fun lost(e: RemoteException) {
        Log.e(TAG, "the helper stopped", e)
        helper = null
        _status.update { it.copy(helper = Helper.Failed("Rift's helper stopped")) }
    }

    /** Runs `block` on [work] with the helper, if it is connected and wanted; null otherwise. */
    private fun <T> withHelper(block: (IHardening) -> T): T? {
        if (!_status.value.on || helper == null) return null
        return try {
            work.submit<T?> { helper?.let { h -> try { block(h) } catch (e: RemoteException) { lost(e); null } } }.get(CALL_TIMEOUT_S, TimeUnit.SECONDS)
        } catch (e: TimeoutException) {
            Log.e(TAG, "the helper did not answer", e)
            null
        }
    }

    /**
     * Before a session's browser gets its proxy (Core.registerBrowser):
     * the clipboard block again (each wipe could have reset it) and, with
     * root, the firewall rules for this session's port. Blocks for up to a
     * few seconds; never on the main thread.
     */
    fun beforeBrowsing(proxyPort: Int) {
        sessionPort = proxyPort
        // A helper still starting (Rift was just launched) is waited for: with
        // root, the rules of an earlier run would refuse this session's port.
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(CONNECT_WAIT_S)
        while (_status.value.on && _status.value.helper == Helper.Connecting && helper == null && System.nanoTime() < deadline) {
            Thread.sleep(50)
        }
        withHelper { h ->
            applyClipboard(h)
            if (root) applyNetwork(h, proxyPort)
        }
    }

    /**
     * The reset's wipe (AndroidBrowserDisposal): true once Android has
     * cleared the browser app at the helper's request, false if the helper
     * failed, null without it. Either way the reset then checks a fresh
     * browser instance for files.
     */
    fun clearBrowser(): Boolean? = withHelper { h ->
        val problem = h.clearBrowser()
        _status.update { it.copy(wipe = problem?.let { p -> Measure.Problem("The last wipe through the helper failed: $p") } ?: Measure.InEffect) }
        problem == null
    }
}
