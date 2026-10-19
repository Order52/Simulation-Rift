package org.simulationrift.poc.outsider

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.IBinder
import android.util.Log
import java.io.File
import java.net.Socket
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/** Another app on the device (T7), signed with a different key. */
class OutsiderActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val port = intent.getIntExtra("port", 0)
        val authPort = intent.getIntExtra("authport", 0)
        thread {
            val c = "org.simulationrift.poc.controller"
            val b = "org.simulationrift.poc.browser"
            log("permission granted: ${checkSelfPermission("org.simulationrift.poc.permission.RIFT") == PackageManager.PERMISSION_GRANTED}")
            log("bind browser session: " + bind(ComponentName(b, "$b.SessionService")))
            log("bind controller core: " + bind(ComponentName(c, "$c.CoreService")))
            log("start browser page: " + attempt {
                startActivity(Intent().setComponent(ComponentName(b, "$b.WebActivity")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK).putExtra("url", "http://localhost:8780/page.html?run=outsider"))
                "started"
            })
            for (path in listOf("/data/data/$c/files/canary.txt", "/data/data/$b")) {
                log("read $path: " + attempt { File(path).let { if (it.isDirectory) "listed ${it.list()?.toList()}" else it.readText() } })
            }
            log("open proxy: " + proxyRequest(port))
            log("auth proxy without token: " + proxyRequest(authPort))
            log("done")
        }
    }

    private fun proxyRequest(port: Int): String = attempt {
        Socket("127.0.0.1", port).use { s ->
            s.soTimeout = 5_000
            s.getOutputStream().write("GET http://localhost:8780/outsider-probe HTTP/1.1\r\nHost: localhost:8780\r\n\r\n".toByteArray())
            s.getInputStream().bufferedReader().readLine() ?: "no answer"
        }
    }

    private fun bind(component: ComponentName): String = attempt {
        val future = CompletableFuture<IBinder>()
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                future.complete(service)
            }

            override fun onServiceDisconnected(name: ComponentName) {}
        }
        if (!bindService(Intent().setComponent(component), connection, Context.BIND_AUTO_CREATE)) "bindService returned false"
        else {
            future.get(5, TimeUnit.SECONDS)
            "connected"
        }
    }

    private fun attempt(block: () -> String): String = try {
        "ALLOWED " + block()
    } catch (e: Throwable) {
        "DENIED ${e.javaClass.simpleName}: ${e.message}"
    }

    private fun log(line: String) = Log.i("POC", "outsider $line")
}
