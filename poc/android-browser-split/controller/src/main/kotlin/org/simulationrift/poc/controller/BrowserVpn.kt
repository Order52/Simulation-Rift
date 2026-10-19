package org.simulationrift.poc.controller

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import kotlin.concurrent.thread

/**
 * A VPN that applies to the browser app's UID only and forwards nothing:
 * every packet the browser sends outside loopback arrives here and is
 * dropped. The loopback proxy is then the browser's only way out.
 */
class BrowserVpn : VpnService() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.getBooleanExtra("stop", false) == true) {
            tun?.close()
            tun = null
            stopSelf()
            Log.i("POC", "vpn stopped")
            return START_NOT_STICKY
        }
        if (tun == null) {
            val established = Builder()
                .setSession("Rift browser isolation")
                .addAddress("10.111.0.1", 32)
                .addAddress("fd00:7269:6674::1", 128)
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .addDnsServer("10.111.0.2")
                .addAllowedApplication("org.simulationrift.poc.browser")
                .setBlocking(true)
                .establish()
            tun = established
            Log.i("POC", "vpn established=${established != null}")
            established?.let { drain(it) }
        }
        return START_NOT_STICKY
    }

    /** Reads and drops; logs the first packets per destination. */
    private fun drain(fd: ParcelFileDescriptor) = thread(name = "poc-vpn") {
        val input = FileInputStream(fd.fileDescriptor)
        val buf = ByteArray(32_767)
        val seen = HashMap<String, Int>()
        try {
            while (true) {
                val n = input.read(buf)
                if (n <= 0) break
                val summary = describe(buf, n)
                val count = (seen[summary] ?: 0) + 1
                seen[summary] = count
                if (count <= 2) Log.i("POC", "vpn dropped $summary (#$count)")
            }
        } catch (e: java.io.IOException) {
            Log.i("POC", "vpn read ended: ${e.message}")
        }
    }

    private fun describe(p: ByteArray, n: Int): String {
        val version = (p[0].toInt() shr 4) and 0xF
        if (version == 4 && n >= 24) {
            val proto = p[9].toInt() and 0xFF
            val ihl = (p[0].toInt() and 0xF) * 4
            val dst = (16..19).joinToString(".") { (p[it].toInt() and 0xFF).toString() }
            val port = if (proto == 6 || proto == 17) ((p[ihl + 2].toInt() and 0xFF) shl 8) or (p[ihl + 3].toInt() and 0xFF) else 0
            return "${protoName(proto)} -> $dst:$port"
        }
        if (version == 6 && n >= 44) {
            val proto = p[6].toInt() and 0xFF
            val port = if (proto == 6 || proto == 17) ((p[42].toInt() and 0xFF) shl 8) or (p[43].toInt() and 0xFF) else 0
            return "${protoName(proto)}/v6 -> port $port"
        }
        return "v$version packet"
    }

    private fun protoName(p: Int) = when (p) {
        6 -> "TCP"
        17 -> "UDP"
        1 -> "ICMP"
        58 -> "ICMPv6"
        else -> "proto$p"
    }

    override fun onRevoke() {
        Log.i("POC", "vpn revoked")
        tun?.close()
        tun = null
    }

    companion object {
        @Volatile private var tun: ParcelFileDescriptor? = null
    }
}
