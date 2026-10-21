package org.simulationrift.app

import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.ServiceConnection
import android.os.Build
import android.os.IBinder
import android.os.RemoteException
import android.util.Log
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import org.simulationrift.bridge.ISession
import org.simulationrift.bridge.Rift
import org.simulationrift.core.BrowserDisposal
import org.simulationrift.core.DisposalException

/**
 * Engine-side disposal (§15 steps 3–5), called by rift-core during a reset
 * and again during launch recovery, so every step is idempotent. The browser
 * is a separate app, so disposal is the system's: its session service asks
 * Android to clear the browser app's data, which kills every process of the
 * package and deletes everything it owns. This throws unless a fresh
 * browser instance then holds no file at all and the controller holds only
 * Rift's own files; rift-core then reports the cleanup as failed instead of
 * starting a session.
 *
 * Blocks for up to a few seconds, so it never runs on the UI thread or on a
 * Binder thread: binding callbacks arrive on the main thread.
 */
class AndroidBrowserDisposal(private val context: Context) : BrowserDisposal {

    @Volatile private var wipedThisLaunch = false

    override fun destroyBrowserState(generation: ULong) {
        endBrowserWindow()
        wipeBrowser()
        val leftovers = leftovers()
        if (leftovers.isNotEmpty()) {
            throw DisposalException.Failed(leftovers.take(10).joinToString("; ") { "unexpected file remains: $it" })
        }
        Log.i(TAG, "generation $generation disposed")
    }

    /**
     * Before the first session of each launch (§15), so that a crash, a kill
     * or a lost reset in an earlier run leaves nothing in the browser.
     */
    fun wipeOnceThisLaunch() {
        if (!wipedThisLaunch) wipeBrowser()
    }

    /** Best effort: asks the browser window to finish, so Android does not restore it. */
    private fun endBrowserWindow() {
        try {
            Core.detachBrowser()?.shutdown()
        } catch (e: RemoteException) {
            // Already dead or dying; the wipe decides.
            Log.i(TAG, "browser did not answer shutdown: $e")
        }
    }

    /**
     * Has the system wipe the browser app, then checks a fresh instance of
     * it. The controller cannot read the browser's files (another UID), so
     * the inventory comes from the fresh instance, which runs only the
     * browser APK's code, started after the system deleted everything the
     * old one could have changed.
     */
    private fun wipeBrowser() {
        val cleared = CompletableFuture<Unit>()
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context, intent: Intent) {
                if (intent.data?.schemeSpecificPart == Rift.BROWSER_PACKAGE) cleared.complete(Unit)
            }
        }
        val filter = IntentFilter(Intent.ACTION_PACKAGE_DATA_CLEARED).apply { addDataScheme("package") }
        // A system broadcast: delivered to a receiver that is not exported.
        if (Build.VERSION.SDK_INT >= 33) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            context.registerReceiver(receiver, filter)
        }
        try {
            val old = Bound.connect(context)
            val oldPid: Int
            val died = CompletableFuture<Unit>()
            try {
                oldPid = old.session.pid()
                old.binder.linkToDeath({ died.complete(Unit) }, 0)
                val accepted = try {
                    old.session.wipe()
                } catch (e: RemoteException) {
                    true // the usual outcome: the process died during the call
                }
                if (!accepted) throw DisposalException.Failed("Android refused to clear the browser app's data")
                await(died, "the browser app did not stop for the wipe")
            } catch (e: RemoteException) {
                throw DisposalException.Failed("the browser's session service failed: $e")
            } finally {
                old.close()
            }
            val started = System.nanoTime()
            await(cleared, "Android did not confirm that the browser app's data was cleared", CLEAR_TIMEOUT_MS)
            Log.i(TAG, "browser data cleared after ${(System.nanoTime() - started) / 1_000_000} ms")
            checkFresh(oldPid)
            wipedThisLaunch = true
        } finally {
            context.unregisterReceiver(receiver)
        }
    }

    /** §15 step 4: a new process, and not one file anywhere in the browser app. */
    private fun checkFresh(oldPid: Int) {
        val fresh = connectFresh()
        try {
            val pid = fresh.session.pid()
            if (pid == oldPid) throw DisposalException.Failed("the browser process survived the wipe (pid $pid)")
            val files = fresh.session.inventory()
            if (files.isNotEmpty()) {
                throw DisposalException.Failed(files.take(10).joinToString("; ") { "browser file remains after the wipe: $it" })
            }
            Log.i(TAG, "browser wiped: pid $oldPid -> $pid, no files")
        } catch (e: RemoteException) {
            throw DisposalException.Failed("the fresh browser instance did not answer: $e")
        } finally {
            fresh.close()
        }
    }

    /**
     * The first bind after the clear can stall on a slow device (CI, API 34:
     * no connection within 10 s), so it is retried a bounded number of times.
     * Each failure is logged; the last one fails the reset.
     */
    private fun connectFresh(): Bound {
        var failure: DisposalException.Failed? = null
        for (attempt in 1..FRESH_ATTEMPTS) {
            try {
                return Bound.connect(context)
            } catch (e: DisposalException.Failed) {
                Log.w(TAG, "fresh browser instance, attempt $attempt of $FRESH_ATTEMPTS: ${e.message}")
                failure = e
            }
        }
        throw checkNotNull(failure)
    }

    private fun <T> await(future: CompletableFuture<T>, failure: String, timeoutMs: Long = WIPE_TIMEOUT_MS): T = try {
        future.get(timeoutMs, TimeUnit.MILLISECONDS)
    } catch (e: TimeoutException) {
        throw DisposalException.Failed("$failure within $timeoutMs ms")
    }

    /** A binding to the browser's session service. */
    private class Bound(val binder: IBinder, val session: ISession, private val context: Context, private val connection: ServiceConnection) {
        fun close() = context.unbindService(connection)

        companion object {
            fun connect(context: Context): Bound {
                val app = context.applicationContext
                val connected = CompletableFuture<IBinder>()
                val connection = object : ServiceConnection {
                    override fun onServiceConnected(name: ComponentName, service: IBinder) {
                        connected.complete(service)
                    }

                    override fun onServiceDisconnected(name: ComponentName) = Unit

                    // The package was cleared: this binding is gone for good.
                    override fun onBindingDied(name: ComponentName) {
                        connected.completeExceptionally(IllegalStateException("binding died"))
                    }

                    override fun onNullBinding(name: ComponentName) {
                        connected.completeExceptionally(IllegalStateException("no session interface"))
                    }
                }
                val bound = try {
                    app.bindService(Intent().setComponent(Rift.SESSION_SERVICE), connection, Context.BIND_AUTO_CREATE)
                } catch (e: SecurityException) {
                    throw DisposalException.Failed("the browser app refused the controller: ${e.message}")
                }
                if (!bound) {
                    app.unbindService(connection)
                    throw DisposalException.Failed("the browser app is not installed")
                }
                val binder = try {
                    connected.get(BIND_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                } catch (e: Exception) {
                    app.unbindService(connection)
                    throw DisposalException.Failed("the browser's session service did not start: $e")
                }
                return Bound(binder, ISession.Stub.asInterface(binder), app, connection)
            }
        }
    }

    /**
     * Inventory of the controller against an allowlist of Rift's own files
     * (§15 step 5): any other file is a leftover. The controller never loads
     * WebView, so any engine state here is one; a new kind of state fails
     * the reset visibly instead of surviving it.
     */
    private fun leftovers(): List<String> {
        val dataDir = context.dataDir
        return dataDir.walkTopDown()
            .filter { !it.isDirectory }
            .map { it.relativeTo(dataDir).path }
            .filter { path -> ALLOWED.none { it.matches(path) } }
            .sorted()
            .toList()
    }

    companion object {
        private const val WIPE_TIMEOUT_MS = 10_000L

        /**
         * The first clears after an install took 9.2 s and over 10 s to be
         * confirmed on a cold CI emulator (API 34), later ones under 0.5 s.
         * Running out still fails the reset.
         */
        private const val CLEAR_TIMEOUT_MS = 30_000L
        private const val BIND_TIMEOUT_MS = 10_000L
        private const val FRESH_ATTEMPTS = 3

        /**
         * Files that may remain after a reset. Each entry is Rift's own state or
         * an Android runtime file measured on the emulators; see
         * docs/reports/phase-2.md for where each one comes from.
         */
        private val ALLOWED = listOf(
            Regex("files/rift/.*"), // rift-core: session marker, intel (sessions/<gen> is deleted by the core)
            // androidx.profileinstaller (via Compose): an empty marker that the
            // ART baseline profile was installed, and (release builds) the APK
            // update time it was written for. Neither holds browsing data.
            Regex("files/profileInstalled"),
            Regex("files/profileinstaller_profileWrittenFor_lastUpdateTime\\.dat"),
        )
    }
}
