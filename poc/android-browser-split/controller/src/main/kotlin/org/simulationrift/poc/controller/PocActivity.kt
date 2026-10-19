package org.simulationrift.poc.controller

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import android.os.Process
import android.os.RemoteException
import android.os.SystemClock
import android.util.Log
import java.io.File
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import org.simulationrift.poc.ISession

/**
 * Driven by run-poc.sh with `am start --es step <name>`. Every result is a
 * logcat line tagged POC, which the script collects.
 */
class PocActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handle(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handle(intent)
    }

    private fun handle(intent: Intent) {
        val step = intent.getStringExtra("step") ?: return
        thread(name = "poc-$step") {
            try {
                when (step) {
                    "setup" -> setup()
                    "browse" -> browse(intent.getStringExtra("mode") ?: "none", intent.getStringExtra("run") ?: "run")
                    "wipe" -> wipe(intent.getStringExtra("run") ?: "wipe")
                    "inventory" -> log("inventory ${intent.getStringExtra("run")}: ${session().inventory()}")
                    "vpn-on" -> {
                        // Consent is given by run-poc.sh with appops (no dialog in a test).
                        log("vpn consent needed: ${android.net.VpnService.prepare(this) != null}")
                        startService(Intent(this, BrowserVpn::class.java))
                        Thread.sleep(1_000)
                    }
                    "vpn-off" -> {
                        startService(Intent(this, BrowserVpn::class.java).putExtra("stop", true))
                        Thread.sleep(500)
                    }
                }
            } catch (e: Exception) {
                log("$step FAILED ${e.javaClass.simpleName}: ${e.message}")
            }
            log("$step ${intent.getStringExtra("run") ?: "-"} done")
        }
    }

    private fun setup() {
        File(filesDir, "canary.txt").writeText("controller secret")
        log("controller uid=${Process.myUid()} canary=${File(filesDir, "canary.txt").path}")
        if (proxy == null) {
            proxy = Proxy("localhost", null).also { it.start() }
            authProxy = Proxy("localhost", TOKEN).also { it.start() }
        }
        log("proxy port=${proxy!!.port} authport=${authProxy!!.port}")
        log("browser hello: ${session().hello()}")
    }

    private fun browse(mode: String, run: String) {
        val port = when (mode) {
            "auth" -> authProxy!!.port
            "none" -> 0
            else -> proxy!!.port
        }
        startActivity(
            Intent().setComponent(ComponentName(BROWSER, "$BROWSER.WebActivity"))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
                .putExtra("url", "http://localhost:8780/page.html?run=$run")
                .putExtra("mode", mode)
                .putExtra("port", port)
                .putExtra("token", if (mode == "auth") TOKEN else null),
        )
        log("browse $run mode=$mode port=$port started")
    }

    /**
     * Asks the browser app to wipe itself, then measures when its process
     * dies and when a fresh one answers, and what it then holds.
     */
    private fun wipe(run: String) {
        val (binder, s) = sessionBinder()
        log("wipe $run before: ${s.hello()} files=${s.inventory().size}")
        val died = CompletableFuture<Long>()
        binder.linkToDeath({ died.complete(SystemClock.elapsedRealtime()) }, 0)
        val t0 = SystemClock.elapsedRealtime()
        val answer = try {
            s.wipe().toString()
        } catch (e: RemoteException) {
            "died during call (${e.javaClass.simpleName})"
        }
        val tDeath = died.get(10, TimeUnit.SECONDS) - t0
        Thread.sleep(200) // let the package manager finish before binding again
        val tBind = SystemClock.elapsedRealtime()
        val fresh = session()
        val hello = fresh.hello()
        val tFresh = SystemClock.elapsedRealtime() - t0
        log("wipe $run answer=$answer death_ms=$tDeath fresh_ms=$tFresh (bind ${SystemClock.elapsedRealtime() - tBind} ms) after: $hello inventory=${fresh.inventory()}")
    }

    private fun session(): ISession = sessionBinder().second

    private fun sessionBinder(): Pair<IBinder, ISession> {
        val future = CompletableFuture<IBinder>()
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                future.complete(service)
            }

            override fun onServiceDisconnected(name: ComponentName) {}

            override fun onBindingDied(name: ComponentName) {
                // The package was cleared; this binding is gone for good.
                applicationContext.unbindService(this)
            }
        }
        val intent = Intent().setComponent(ComponentName(BROWSER, "$BROWSER.SessionService"))
        check(applicationContext.bindService(intent, connection, Context.BIND_AUTO_CREATE)) { "bind refused" }
        val binder = future.get(10, TimeUnit.SECONDS)
        return binder to ISession.Stub.asInterface(binder)
    }

    private fun log(line: String) = Log.i("POC", line)

    companion object {
        const val BROWSER = "org.simulationrift.poc.browser"
        /** A per-run value in the product; fixed here so the outsider test can try it too. */
        const val TOKEN = "poc-session-token"
        @Volatile private var proxy: Proxy? = null
        @Volatile private var authProxy: Proxy? = null
    }
}
