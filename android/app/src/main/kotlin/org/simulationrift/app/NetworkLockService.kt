package org.simulationrift.app

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import android.util.Log
import java.net.InetAddress
import kotlin.concurrent.thread
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.simulationrift.bridge.Rift

/**
 * The network lock's state (§8.8, INV-14): a VPN that applies to the
 * browser app only and forwards nothing, so the browser's one way out is
 * the egress proxy on loopback.
 */
object NetworkLock {
    sealed interface State {
        /** Not requested yet in this run. */
        data object Off : State

        /** Android's one-time VPN consent is needed; only the user can give it. */
        data object NeedsConsent : State

        data object Starting : State

        data object Active : State

        /**
         * The lock ran and was taken away (another VPN started, or the user
         * turned it off). Rift does not take it back on its own, which would
         * stop the other VPN; the user turns it on again.
         */
        data class Lost(val reason: String) : State

        data class Unavailable(val reason: String) : State
    }

    /** What the lock has dropped since it started: packets, and the first distinct destinations. */
    data class Dropped(val packets: Long = 0, val destinations: List<String> = emptyList())

    private val _state = MutableStateFlow<State>(State.Off)
    val state: StateFlow<State> = _state

    private val _dropped = MutableStateFlow(Dropped())
    val dropped: StateFlow<Dropped> = _dropped

    val active: Boolean get() = _state.value == State.Active

    /**
     * Starts the lock if the user has consented; otherwise reports
     * [State.NeedsConsent] and the home screen asks. Never takes the VPN
     * from another app without the user's action: after [State.Lost] only
     * an explicit call with `userAction` restarts it.
     */
    fun start(context: Context, userAction: Boolean) {
        val current = _state.value
        if (current == State.Active || current == State.Starting) return
        if (current is State.Lost && !userAction) return
        if (VpnService.prepare(context) != null) {
            _state.value = State.NeedsConsent
            return
        }
        _state.value = State.Starting
        context.startService(Intent(context, NetworkLockService::class.java))
    }

    internal fun established() {
        _dropped.value = Dropped()
        _state.value = State.Active
        Log.i(TAG, "network lock active")
    }

    internal fun unavailable(reason: String) {
        _state.value = State.Unavailable(reason)
        Log.w(TAG, "network lock unavailable: $reason")
    }

    internal fun lost(reason: String) {
        if (_state.value != State.Active) return
        _state.value = State.Lost(reason)
        Log.w(TAG, "network lock lost: $reason")
        Core.networkLockLost()
    }

    /** From the drain thread, at most once per [NetworkLockService.PUBLISH_MS]: the UI redraws on each value. */
    internal fun publishDrops(dropped: Dropped) {
        _dropped.value = dropped
    }
}

/**
 * The VPN behind [NetworkLock]. Routes all IPv4 and IPv6 traffic of the
 * browser app (and of no other app, Rift's controller included) into a tun
 * device that it reads and drops: no packet is forwarded, so there is no
 * userspace network stack in the trusted controller. Loopback is not routed
 * through a VPN, which is how the browser still reaches the egress proxy.
 */
class NetworkLockService : VpnService() {

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (tun == null) establish()
        return START_NOT_STICKY
    }

    private fun establish() {
        val established = try {
            Builder()
                .setSession("Rift browser isolation")
                .addAddress(TUN_V4, 32)
                .addAddress(TUN_V6, 128)
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                // Inside the tun's own range, so name lookups are dropped too
                // instead of going to the network's resolver.
                .addDnsServer(DNS_V4)
                .addAllowedApplication(Rift.BROWSER_PACKAGE)
                .setBlocking(false)
                .establish()
        } catch (e: PackageManager.NameNotFoundException) {
            NetworkLock.unavailable("the browser app is not installed")
            stopSelf()
            return
        } catch (e: IllegalStateException) {
            NetworkLock.unavailable("Android refused the VPN: ${e.message}")
            stopSelf()
            return
        }
        if (established == null) {
            // Consent was withdrawn, or another app is the always-on VPN.
            NetworkLock.unavailable("Android did not allow the VPN; another VPN may be set as always-on")
            stopSelf()
            return
        }
        tun = established
        NetworkLock.established()
        drain(established)
    }

    /**
     * Reads and drops every packet until the tun is closed. The counts are
     * published at most once per [PUBLISH_MS], whatever the packet rate.
     */
    private fun drain(fd: ParcelFileDescriptor) = thread(name = "rift-lock") {
        val buffer = ByteArray(MAX_PACKET)
        val poll = StructPollfd().apply {
            this.fd = fd.fileDescriptor
            events = OsConstants.POLLIN.toShort()
        }
        val failed = OsConstants.POLLERR or OsConstants.POLLHUP or OsConstants.POLLNVAL
        var packets = 0L
        val destinations = LinkedHashSet<String>()
        var published = 0L
        var lastPublish = 0L
        try {
            while (tun === fd) {
                // Bounded, so a closed tun ends the loop even if poll never wakes.
                val ready = Os.poll(arrayOf(poll), POLL_MS)
                if (ready > 0 && (poll.revents.toInt() and failed) != 0) {
                    if (tun === fd) Log.w(TAG, "network lock tun reported ${poll.revents}")
                    break
                }
                if (ready > 0) {
                    while (true) {
                        val n = try {
                            Os.read(fd.fileDescriptor, buffer, 0, buffer.size)
                        } catch (e: ErrnoException) {
                            if (e.errno == OsConstants.EAGAIN) break else throw e
                        }
                        if (n <= 0) break
                        packets++
                        if (destinations.size < MAX_DESTINATIONS) destinations += describe(buffer, n)
                    }
                }
                val now = SystemClock.elapsedRealtime()
                if (packets != published && now - lastPublish >= PUBLISH_MS) {
                    NetworkLock.publishDrops(NetworkLock.Dropped(packets, destinations.toList()))
                    published = packets
                    lastPublish = now
                }
            }
        } catch (e: ErrnoException) {
            if (tun === fd) Log.w(TAG, "network lock read failed", e)
        }
    }

    override fun onRevoke() {
        close()
        NetworkLock.lost("another VPN started, or the network lock was turned off in Settings")
        super.onRevoke()
    }

    override fun onDestroy() {
        close()
        NetworkLock.lost("the network lock stopped")
        super.onDestroy()
    }

    private fun close() {
        val open = tun
        tun = null
        try {
            open?.close()
        } catch (e: java.io.IOException) {
            Log.w(TAG, "closing the network lock failed", e)
        }
    }

    private companion object {
        const val TUN_V4 = "10.111.0.1"
        const val TUN_V6 = "fd00:7269:6674::1"
        const val DNS_V4 = "10.111.0.2"
        const val MAX_PACKET = 32_767
        const val POLL_MS = 500
        const val PUBLISH_MS = 1_000L
        const val MAX_DESTINATIONS = 32

        @Volatile var tun: ParcelFileDescriptor? = null

        /** "TCP 10.0.2.2:8766" for the diagnostics list; bounds-checked against `n`. */
        fun describe(p: ByteArray, n: Int): String {
            if (n < 1) return "empty packet"
            return when ((p[0].toInt() shr 4) and 0xF) {
                4 -> {
                    val ihl = (p[0].toInt() and 0xF) * 4
                    if (n < 20 || ihl < 20) return "short IPv4 packet"
                    val proto = p[9].toInt() and 0xFF
                    val address = InetAddress.getByAddress(p.copyOfRange(16, 20)).hostAddress
                    "${protocol(proto)} $address" + port(p, n, proto, ihl)
                }
                6 -> {
                    if (n < 40) return "short IPv6 packet"
                    val proto = p[6].toInt() and 0xFF
                    val address = InetAddress.getByAddress(p.copyOfRange(24, 40)).hostAddress
                    "${protocol(proto)} [$address]" + port(p, n, proto, 40)
                }
                else -> "not an IP packet"
            }
        }

        fun port(p: ByteArray, n: Int, proto: Int, offset: Int): String {
            if ((proto != 6 && proto != 17) || n < offset + 4) return ""
            return ":" + (((p[offset + 2].toInt() and 0xFF) shl 8) or (p[offset + 3].toInt() and 0xFF))
        }

        fun protocol(p: Int) = when (p) {
            6 -> "TCP"
            17 -> "UDP"
            1 -> "ICMP"
            58 -> "ICMPv6"
            else -> "protocol $p"
        }
    }
}
