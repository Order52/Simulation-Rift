package org.simulationrift.poc.browser

import android.annotation.SuppressLint
import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import android.os.Process
import android.util.Log
import android.webkit.HttpAuthHandler
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.webkit.ProxyConfig
import androidx.webkit.ProxyController
import androidx.webkit.WebViewFeature
import java.io.File
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import org.simulationrift.poc.ICore

/**
 * The page host in `:web`. Before the page, it probes what code in this
 * process (as after a WebView escape) can reach of the controller.
 */
class WebActivity : Activity() {

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val url = intent.getStringExtra("url") ?: return
        val mode = intent.getStringExtra("mode") ?: "none"
        val port = intent.getIntExtra("port", 0)
        val token = intent.getStringExtra("token")
        thread { escapeProbes() }

        val web = WebView(this)
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        web.webViewClient = object : WebViewClient() {
            override fun onReceivedHttpAuthRequest(view: WebView, handler: HttpAuthHandler, host: String, realm: String) {
                Log.i("POC", "web auth request host=$host realm=$realm token=${token != null}")
                if (token != null && realm == "rift") handler.proceed("rift", token) else handler.cancel()
            }
        }
        setContentView(web)
        if (mode == "none") {
            web.loadUrl(url)
            return
        }
        check(WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)) { "no proxy override" }
        val config = ProxyConfig.Builder().addProxyRule("127.0.0.1:$port").let {
            // "implicit": Chromium's default bypass for localhost and link-local stays.
            if (mode == "implicit") it else it.removeImplicitRules()
        }.build()
        ProxyController.getInstance().setProxyOverride(config, Executors.newSingleThreadExecutor()) {
            Log.i("POC", "web proxy override applied mode=$mode port=$port")
            runOnUiThread { web.loadUrl(url) }
        }
    }

    private fun escapeProbes() {
        val controller = "org.simulationrift.poc.controller"
        val controllerUid = try {
            packageManager.getPackageUid(controller, 0)
        } catch (e: Exception) {
            -1
        }
        log("uid=${Process.myUid()} controller uid=$controllerUid process=${android.app.Application.getProcessName()}")
        for (path in listOf("/data/data/$controller/files/canary.txt", "/data/user/0/$controller/files/canary.txt", "/data/data/$controller", "/data/user_de/0/$controller")) {
            log("read $path: " + attempt {
                val f = File(path)
                if (f.isDirectory) "listed ${f.list()?.toList()}" else "read '${f.readText()}'"
            })
        }
        // Direct sockets, as escaped code in this process would use (no proxy).
        for ((host, port) in listOf("10.0.2.2" to 8780, "1.1.1.1" to 443, "127.0.0.1" to 8780)) {
            log("connect $host:$port: " + attempt {
                java.net.Socket().use { it.connect(java.net.InetSocketAddress(host, port), 3_000) }
                "connected"
            })
        }
        log("udp 10.0.2.2:3478: " + attempt {
            java.net.DatagramSocket().use { s ->
                val data = "escaped-udp".toByteArray()
                s.send(java.net.DatagramPacket(data, data.size, java.net.InetAddress.getByName("10.0.2.2"), 3478))
            }
            "sent (arrival is in fixture.log)"
        })
        log("dns example.com: " + attempt { java.net.InetAddress.getAllByName("example.com").joinToString { it.hostAddress ?: "?" } })
        log("bind hidden: " + bindResult(ComponentName(controller, "$controller.HiddenService")))
        log("bind core: " + bindResult(ComponentName(controller, "$controller.CoreService")) { ICore.Stub.asInterface(it).hello() })
    }

    private fun bindResult(component: ComponentName, use: ((IBinder) -> String)? = null): String = attempt {
        val future = CompletableFuture<IBinder>()
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                future.complete(service)
            }

            override fun onServiceDisconnected(name: ComponentName) {}
        }
        if (!applicationContext.bindService(Intent().setComponent(component), connection, Context.BIND_AUTO_CREATE)) {
            "bindService returned false"
        } else {
            val binder = future.get(5, TimeUnit.SECONDS)
            "connected" + (use?.let { ": " + it(binder) } ?: "")
        }
    }

    private fun attempt(block: () -> String): String = try {
        "ALLOWED " + block()
    } catch (e: Throwable) {
        "DENIED ${e.javaClass.simpleName}: ${e.message}"
    }

    private fun log(line: String) = Log.i("POC", "web $line")
}
