package org.simulationrift.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.util.Log
import androidx.core.content.ContextCompat
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.json.JSONException
import org.json.JSONObject
import org.simulationrift.core.RelayCheck
import org.simulationrift.core.RelayFailure
import org.simulationrift.core.RelaySetting

/**
 * The relay (§8.12): pages' connections, downloads and Where it goes sent
 * through Tor (Orbot) or a SOCKS5 relay, so sites see the relay's address,
 * not the phone's, and no name is looked up by the phone. Rift's own
 * fetches (updates, lists) still go direct.
 *
 * Orbot listens on loopback, where any app can listen once Orbot stops, and
 * Android gives an app no way to ask who owns a loopback port (the VPN API
 * that does answers only for the apps a VPN covers, here the browser). So
 * Rift lets a connection through only while the app it pinned (by package
 * and signing certificate, when the user chose it) is installed and has said
 * it is running on that port. That word comes by broadcast, which another
 * app could also send: the gap is in §24.
 *
 * The choice is kept in Rift's files as a setting; a session keeps the relay
 * it started with, so a change resets the session.
 */
object Relay {

    const val ORBOT = "org.torproject.android"
    const val ORBOT_PORT = 9050

    sealed interface Choice {
        data object Off : Choice
        /** An app's SOCKS port on loopback: [cert] is the SHA-256 of its signing certificate, pinned when chosen. */
        data class App(val pkg: String, val cert: String, val port: Int) : Choice
        /** A SOCKS5 relay at a public `ip:port`. */
        data class Socks(val address: String) : Choice
    }

    /** What the relay app last said about itself. */
    data class Status(val on: Boolean, val port: Int)

    private const val TAG = "RiftRelay"
    private const val ACTION_START = "org.torproject.android.intent.action.START"
    private const val ACTION_STATUS = "org.torproject.android.intent.action.STATUS"
    private const val EXTRA_PACKAGE = "org.torproject.android.intent.extra.PACKAGE_NAME"
    private const val EXTRA_STATUS = "org.torproject.android.intent.extra.STATUS"
    private const val EXTRA_SOCKS_PORT = "org.torproject.android.intent.extra.SOCKS_PROXY_PORT"

    private val _choice = MutableStateFlow<Choice>(Choice.Off)
    val choice: StateFlow<Choice> = _choice
    private val _status = MutableStateFlow<Status?>(null)
    val status: StateFlow<Status?> = _status

    private lateinit var app: Context
    private lateinit var file: File

    /** From Core.ensureStarted, before the first session starts. */
    fun init(context: Context) {
        app = context.applicationContext
        file = File(File(app.filesDir, "rift").apply { mkdirs() }, "relay.json")
        _choice.value = read()
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                report(intent.getStringExtra(EXTRA_STATUS) == "ON", intent.getIntExtra(EXTRA_SOCKS_PORT, ORBOT_PORT))
            }
        }
        // Orbot sends it from its own UID, so it cannot be a protected broadcast.
        ContextCompat.registerReceiver(app, receiver, IntentFilter(ACTION_STATUS), ContextCompat.RECEIVER_EXPORTED)
        if (_choice.value is Choice.App) askToStart()
    }

    /** The relay app's word on itself; the receiver's, or a test's. */
    fun report(on: Boolean, port: Int) {
        _status.value = Status(on, port)
    }

    /**
     * Pins [pkg] as installed now and uses its SOCKS port. Returns the
     * certificate digest pinned, or null if the app is not installed.
     */
    fun useApp(pkg: String = ORBOT, port: Int = ORBOT_PORT): String? {
        val cert = certificate(pkg) ?: return null
        choose(Choice.App(pkg, cert, port))
        askToStart()
        return cert
    }

    /** Uses the SOCKS5 relay at `ip:port`; returns why not, or null. */
    fun useSocks(address: String): String? {
        try {
            RelaySetting(address.trim(), null).close()
        } catch (e: RelayFailure) {
            return describe(e)
        }
        choose(Choice.Socks(address.trim()))
        return null
    }

    fun turnOff() = choose(Choice.Off)

    /** Asks Orbot to start; it answers with its status. */
    fun askToStart() {
        val chosen = _choice.value as? Choice.App ?: return
        app.sendBroadcast(Intent(ACTION_START).setPackage(chosen.pkg).putExtra(EXTRA_PACKAGE, app.packageName))
    }

    /** The relay sessions go through, for the core; null for none. Throws if one is chosen and unusable, so nothing goes direct. */
    @Throws(RelayFailure::class)
    fun setting(): RelaySetting? = when (val c = _choice.value) {
        Choice.Off -> null
        is Choice.App -> RelaySetting("127.0.0.1:${c.port}", AppCheck(c))
        is Choice.Socks -> RelaySetting(c.address, null)
    }

    fun describe(e: RelayFailure): String = when (e) {
        is RelayFailure.Address -> "Enter the relay as an IP address and port, such as 203.0.113.5:1080."
        is RelayFailure.Refused -> e.detail.replaceFirstChar { it.uppercase() } + "."
    }

    /** Also R1's, to pin a certificate that is not the app's. */
    internal fun choose(choice: Choice) {
        _choice.value = choice
        write(choice)
        Core.relayChanged()
    }

    /** SHA-256 of `pkg`'s signing certificate (one signer), hex; null if not installed. */
    private fun certificate(pkg: String): String? = try {
        val info = app.packageManager.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
        val signing = info.signingInfo ?: return null
        val certs = if (signing.hasMultipleSigners()) return null else signing.signingCertificateHistory
        certs?.lastOrNull()?.let { hex(MessageDigest.getInstance("SHA-256").digest(it.toByteArray())) }
    } catch (e: PackageManager.NameNotFoundException) {
        null
    }

    private class AppCheck(private val chosen: Choice.App) : RelayCheck {
        private val cert = chosen.cert.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

        override fun trusted(localPort: UShort, relayPort: UShort): Boolean {
            val said = _status.value
            val running = said != null && said.on && said.port == relayPort.toInt()
            val same = app.packageManager.hasSigningCertificate(chosen.pkg, cert, PackageManager.CERT_INPUT_SHA256)
            if (!running || !same) Log.w(TAG, "refused the relay on port $relayPort: running=$running, pinned app=$same")
            return running && same
        }
    }

    private fun read(): Choice = try {
        if (!file.isFile) return Choice.Off
        val json = JSONObject(file.readText())
        when (json.optString("kind")) {
            "app" -> Choice.App(json.getString("pkg"), json.getString("cert"), json.getInt("port"))
            "socks" -> Choice.Socks(json.getString("address"))
            else -> Choice.Off
        }
    } catch (e: IOException) {
        unreadable(e)
    } catch (e: JSONException) {
        unreadable(e)
    }

    /** A setting that cannot be read is a relay that cannot be used: sessions fail rather than go direct. */
    private fun unreadable(e: Exception): Choice {
        Log.e(TAG, "the relay setting is unreadable", e)
        return Choice.Socks("unreadable")
    }

    private fun write(choice: Choice) {
        val json = when (choice) {
            Choice.Off -> JSONObject().put("kind", "off")
            is Choice.App -> JSONObject().put("kind", "app").put("pkg", choice.pkg).put("cert", choice.cert).put("port", choice.port)
            is Choice.Socks -> JSONObject().put("kind", "socks").put("address", choice.address)
        }
        val temp = File(file.parentFile, "relay.json.tmp")
        temp.writeText(json.toString())
        if (!temp.renameTo(file)) Log.e(TAG, "the relay setting could not be saved")
    }

    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }
}
