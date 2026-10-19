package org.simulationrift.poc.controller

import android.util.Base64
import android.util.Log
import java.io.BufferedInputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors
import kotlin.concurrent.thread

/**
 * PoC of the browser's network boundary: an HTTP proxy on loopback that
 * resolves every destination itself and refuses loopback, private,
 * link-local and multicast addresses, except one allowed host name (the
 * fixture through adb reverse). Optional Basic proxy auth with a token.
 */
class Proxy(private val allowedHost: String, private val token: String?) {
    private val server = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
    private val pool = Executors.newCachedThreadPool()
    val port: Int get() = server.localPort

    fun start() {
        thread(name = "poc-proxy") {
            while (true) {
                val client = server.accept()
                pool.execute { handle(client) }
            }
        }
    }

    private fun handle(client: Socket) {
        client.use {
            val input = BufferedInputStream(client.getInputStream())
            val out = client.getOutputStream()
            val head = readHead(input) ?: return
            val lines = head.split("\r\n")
            val (method, target) = lines.first().split(" ").let { it[0] to it.getOrElse(1) { "" } }
            if (token != null) {
                val auth = lines.firstOrNull { it.startsWith("Proxy-Authorization:", ignoreCase = true) }
                    ?.substringAfter(':')?.trim()
                val expected = "Basic " + Base64.encodeToString("rift:$token".toByteArray(), Base64.NO_WRAP)
                if (auth != expected) {
                    log("AUTH-REQUIRED $method $target (header ${if (auth == null) "absent" else "wrong"})")
                    out.write("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"rift\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".toByteArray())
                    return
                }
            }
            val (host, port, originForm) = if (method == "CONNECT") {
                Triple(target.substringBeforeLast(':'), target.substringAfterLast(':').toIntOrNull() ?: 443, null)
            } else {
                val url = java.net.URL(target)
                Triple(url.host, if (url.port == -1) 80 else url.port, (url.file.ifEmpty { "/" }))
            }
            val denied = check(host)
            if (denied != null) {
                log("DENY $method $host:$port ($denied)")
                out.write("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".toByteArray())
                return
            }
            log("ALLOW $method $host:$port")
            // Connects to the address that was checked, not the name again (no rebinding).
            val upstream = Socket()
            upstream.connect(InetSocketAddress(InetAddress.getAllByName(host).first(), port), 10_000)
            upstream.use {
                if (method == "CONNECT") {
                    out.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray())
                } else {
                    val rest = lines.drop(1).filter { !it.startsWith("Proxy-", ignoreCase = true) && !it.startsWith("Connection:", ignoreCase = true) && it.isNotEmpty() }
                    val request = "$method $originForm ${lines.first().substringAfterLast(' ')}\r\n" + rest.joinToString("") { "$it\r\n" } + "Connection: close\r\n\r\n"
                    upstream.getOutputStream().write(request.toByteArray())
                }
                val up = thread { pipe(input, upstream.getOutputStream()) }
                pipe(upstream.getInputStream(), out)
                up.join(1_000)
            }
        }
    }

    /** Null if allowed, otherwise the reason. */
    private fun check(host: String): String? {
        if (host.equals(allowedHost, ignoreCase = true)) return null
        val addresses = try {
            InetAddress.getAllByName(host).toList()
        } catch (e: Exception) {
            return "does not resolve"
        }
        val bad = addresses.firstOrNull {
            it.isLoopbackAddress || it.isSiteLocalAddress || it.isLinkLocalAddress || it.isMulticastAddress || it.isAnyLocalAddress
        }
        return bad?.let { "resolves to non-public ${it.hostAddress}" }
    }

    private fun readHead(input: InputStream): String? {
        val buf = StringBuilder()
        while (buf.length < 16_384) {
            val c = input.read()
            if (c < 0) return null
            buf.append(c.toChar())
            if (buf.endsWith("\r\n\r\n")) return buf.removeSuffix("\r\n\r\n").toString()
        }
        return null
    }

    private fun pipe(from: InputStream, to: OutputStream) {
        try {
            from.copyTo(to)
            to.flush()
        } catch (e: java.io.IOException) {
            // The other side closed.
        }
    }

    private fun log(line: String) = Log.i("POC", "proxy $line")
}
