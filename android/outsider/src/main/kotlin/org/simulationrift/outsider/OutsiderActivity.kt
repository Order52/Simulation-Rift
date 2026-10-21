package org.simulationrift.outsider

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.IBinder
import android.os.ResultReceiver
import android.provider.Settings
import android.util.Base64
import android.widget.EditText
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * Tries, as an unrelated app, everything S24 expects to be refused, and
 * returns each outcome through the ResultReceiver in `receiver`. With
 * `vpn` = "take" or "release" it instead starts or stops [OutsiderVpn];
 * with `overlay` = "show" or "hide", [OutsiderOverlay] (h3); with `field`,
 * it stays open with one text field, an ordinary app's window for h3 and
 * h4 to compare Rift's with.
 */
class OutsiderActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        @Suppress("DEPRECATION") // the typed overload needs API 33
        val receiver = intent.getParcelableExtra<ResultReceiver>("receiver")
        if (intent.getBooleanExtra("field", false)) {
            setContentView(EditText(this).apply {
                hint = "Outsider field"
                setText("Outsider text")
            })
            return
        }
        intent.getStringExtra("overlay")?.let { overlay ->
            val allowed = Settings.canDrawOverlays(this)
            if (allowed || overlay == "hide") startService(Intent(this, OutsiderOverlay::class.java).putExtra("stop", overlay == "hide"))
            receiver?.send(0, Bundle().apply { putString("overlay", if (allowed) overlay else "not allowed") })
            finish()
            return
        }
        when (intent.getStringExtra("vpn")) {
            "take" -> {
                // As any VPN app does. With consent already given (run-tests.sh)
                // this makes the outsider the device's VPN app, which revokes
                // the previous one.
                val consent = android.net.VpnService.prepare(this)
                if (consent == null) startService(Intent(this, OutsiderVpn::class.java))
                receiver?.send(0, Bundle().apply { putString("vpn", if (consent == null) "started" else "needs consent") })
                finish()
                return
            }
            "release" -> {
                startService(Intent(this, OutsiderVpn::class.java).putExtra("stop", true))
                receiver?.send(0, Bundle())
                finish()
                return
            }
        }
        val port = intent.getIntExtra("proxyPort", 0)
        thread(name = "outsider") {
            val results = Bundle()
            try {
                probe(results, port)
            } finally {
                receiver?.send(0, results)
                runOnUiThread { finish() }
            }
        }
    }

    private fun probe(results: Bundle, port: Int) {
        results.putString("permission", if (checkSelfPermission(RIFT_PERMISSION) == PackageManager.PERMISSION_GRANTED) "GRANTED" else "DENIED")
        results.putString("bind.session", attempt { bind(ComponentName(BROWSER, "$BROWSER.SessionService")) })
        results.putString("bind.core", attempt { bind(ComponentName(CONTROLLER, "$CONTROLLER.CoreService")) })
        results.putString("start.browser", attempt {
            startActivity(Intent().setComponent(ComponentName(BROWSER, "$BROWSER.BrowserActivity")).putExtra("org.simulationrift.GENERATION", 1L))
            "started"
        })
        results.putString("proxy.none", attempt { proxyStatus(port, null) })
        val wrong = "Basic " + Base64.encodeToString("rift:not-the-token".toByteArray(), Base64.NO_WRAP)
        results.putString("proxy.wrong", attempt { proxyStatus(port, wrong) })
    }

    /** The status line the proxy answers a CONNECT with. */
    private fun proxyStatus(port: Int, authorization: String?): String = Socket().use { socket ->
        socket.connect(InetSocketAddress("127.0.0.1", port), 3_000)
        socket.soTimeout = 5_000
        val head = "CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n" +
            (authorization?.let { "Proxy-Authorization: $it\r\n" } ?: "") + "\r\n"
        socket.getOutputStream().write(head.toByteArray())
        socket.getInputStream().bufferedReader().readLine() ?: "no answer"
    }

    private fun bind(component: ComponentName): String {
        val connected = CompletableFuture<IBinder>()
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                connected.complete(service)
            }

            override fun onServiceDisconnected(name: ComponentName) = Unit
        }
        if (!applicationContext.bindService(Intent().setComponent(component), connection, Context.BIND_AUTO_CREATE)) {
            throw SecurityException("bindService returned false")
        }
        return try {
            connected.get(5, TimeUnit.SECONDS)
            "connected"
        } finally {
            applicationContext.unbindService(connection)
        }
    }

    private fun attempt(block: () -> String): String = try {
        "ALLOWED " + block()
    } catch (e: Throwable) {
        "DENIED ${e.javaClass.simpleName}: ${e.message}"
    }

    private companion object {
        const val CONTROLLER = "org.simulationrift.app"
        const val BROWSER = "org.simulationrift.browser"
        const val RIFT_PERMISSION = "org.simulationrift.permission.RIFT"
    }
}
