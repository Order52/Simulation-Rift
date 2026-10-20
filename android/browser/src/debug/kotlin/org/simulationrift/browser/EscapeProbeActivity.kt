package org.simulationrift.browser

import android.app.Activity
import android.app.Application
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import android.os.Process
import android.os.ResultReceiver
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import org.simulationrift.bridge.IBrowser
import org.simulationrift.bridge.ICore
import org.simulationrift.bridge.NavigationDecision
import org.simulationrift.bridge.Rift
import org.simulationrift.bridge.SessionGrant

/**
 * Debug builds only (S23, S26). Runs, in the `:web` process, what code
 * there could try after a WebView escape, and returns each outcome to the
 * test through the ResultReceiver in [EXTRA_RECEIVER]. It never loads
 * WebView.
 */
class EscapeProbeActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        @Suppress("DEPRECATION") // the typed overload needs API 33
        val receiver = intent.getParcelableExtra<ResultReceiver>(EXTRA_RECEIVER)
        val port = intent.getIntExtra(EXTRA_FIXTURE_PORT, 0)
        val stale = intent.getLongExtra(EXTRA_STALE_GENERATION, 0)
        thread(name = "escape-probe") {
            val results = Bundle()
            try {
                probe(results, port, stale)
            } finally {
                receiver?.send(0, results)
                runOnUiThread { finish() }
            }
        }
    }

    private fun probe(results: Bundle, port: Int, stale: Long) {
        results.putString("uid", Process.myUid().toString())
        results.putString("process", Application.getProcessName())
        val controller = Rift.CONTROLLER_PACKAGE
        for ((key, path) in listOf(
            "file.rift" to "/data/data/$controller/files/rift",
            "file.marker" to "/data/user/0/$controller/files/rift/session.marker",
            "file.device" to "/data/user_de/0/$controller",
            "file.prefs" to "/data/data/$controller/shared_prefs",
        )) {
            results.putString(key, attempt {
                val f = File(path)
                if (f.isDirectory) "listed ${f.list()?.toList()}" else "read ${f.readBytes().size} bytes"
            })
        }
        results.putString("bind.worker", attempt { bind(ComponentName(controller, "$controller.PreviewService")) { "connected" } })
        results.putString("core.stale", attempt {
            bind(Rift.CORE_SERVICE) { binder ->
                val core = ICore.Stub.asInterface(binder)
                val grant = SessionGrant.fromBundle(core.register(stale, object : IBrowser.Stub() {
                    override fun shutdown() = Unit
                }))
                val decision = NavigationDecision.fromBundle(core.decide(stale, "https://example.org/"))
                "register=${grant::class.simpleName} decide=" +
                    ((decision as? NavigationDecision.Block)?.reason?.code ?: decision::class.simpleName)
            }
        })
        // Direct sockets, as escaped native code would open them: no proxy.
        for ((key, target) in listOf(
            "tcp.host" to InetSocketAddress("10.0.2.2", port),
            "tcp.public" to InetSocketAddress("1.1.1.1", 443),
            "tcp.loopback" to InetSocketAddress("127.0.0.1", port),
        )) {
            results.putString(key, attempt {
                Socket().use { it.connect(target, SOCKET_TIMEOUT_MS) }
                "connected"
            })
        }
        results.putString("udp.host", attempt {
            DatagramSocket().use { socket ->
                val data = UDP_MARKER.toByteArray()
                socket.send(DatagramPacket(data, data.size, InetAddress.getByName("10.0.2.2"), STUN_PORT))
            }
            "sent (whether it arrived is in the fixture's UDP log)"
        })
        results.putString("dns", attempt { InetAddress.getAllByName("example.com").joinToString { it.hostAddress.orEmpty() } })
    }

    private fun bind(component: ComponentName, use: (IBinder) -> String): String {
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
            use(connected.get(BIND_TIMEOUT_S, TimeUnit.SECONDS))
        } finally {
            applicationContext.unbindService(connection)
        }
    }

    private fun attempt(block: () -> String): String = try {
        "ALLOWED " + block()
    } catch (e: Throwable) {
        "DENIED ${e.javaClass.simpleName}: ${e.message}"
    }

    companion object {
        const val EXTRA_RECEIVER = "receiver"
        const val EXTRA_FIXTURE_PORT = "fixturePort"
        const val EXTRA_STALE_GENERATION = "staleGeneration"
        const val UDP_MARKER = "rift-escaped-udp"
        const val STUN_PORT = 3478
        private const val SOCKET_TIMEOUT_MS = 3_000
        private const val BIND_TIMEOUT_S = 5L
    }
}
