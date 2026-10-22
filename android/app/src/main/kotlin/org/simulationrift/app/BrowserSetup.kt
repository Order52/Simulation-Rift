package org.simulationrift.app

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.simulationrift.bridge.Rift

/**
 * The sealed browser ships inside Rift's APK (§8.10), so Rift is one file to
 * install, and stays a separate app: its own UID is what isolates it (ADR-04),
 * and what the network lock applies to. On first run, and after an update of
 * Rift, Rift installs the APK it carries through Android's package installer,
 * which asks the user. Sessions start only once the installed browser is
 * exactly the one Rift carries (the same bytes), signed with Rift's own key.
 */
object BrowserSetup {

    sealed interface State {
        data object Checking : State

        /** The installed browser is the one Rift carries. */
        data object Ready : State

        /** Not installed, or another version: `update` if one is installed. */
        data class Needed(val update: Boolean) : State

        /** Android's "install unknown apps" permission for Rift is off. */
        data object NeedsPermission : State

        data object Installing : State

        data class Failed(val reason: String) : State
    }

    private const val TAG = "RiftSetup"
    private const val ASSET = "browser/rift-browser.apk"
    private const val ACTION_RESULT = "org.simulationrift.app.BROWSER_INSTALLED"

    private val _state = MutableStateFlow<State>(State.Checking)
    val state: StateFlow<State> = _state

    /** The carried APK's SHA-256, read once. */
    @Volatile private var carried: ByteArray? = null

    /**
     * Whether sessions may start (Core, on its worker thread): the browser
     * installed is the carried one. Sets [state] either way.
     */
    fun ready(context: Context): Boolean {
        val wanted = try {
            carried ?: context.assets.open(ASSET).use(::sha256).also { carried = it }
        } catch (e: IOException) {
            _state.value = State.Failed("this build of Rift carries no browser: ${e.message}")
            return false
        }
        val installed = try {
            File(context.packageManager.getApplicationInfo(Rift.BROWSER_PACKAGE, 0).sourceDir).inputStream().use(::sha256)
        } catch (e: PackageManager.NameNotFoundException) {
            _state.value = State.Needed(update = false)
            return false
        } catch (e: IOException) {
            _state.value = State.Needed(update = true)
            return false
        }
        val same = MessageDigest.isEqual(wanted, installed)
        _state.value = if (same) State.Ready else State.Needed(update = true)
        return same
    }

    /**
     * The user asked to install (main thread). Without Android's permission
     * for Rift to install apps, reports [State.NeedsPermission]: the home
     * screen opens that setting, and calls this again on return.
     */
    fun install(context: Context) {
        val app = context.applicationContext
        if (!app.packageManager.canRequestPackageInstalls()) {
            _state.value = State.NeedsPermission
            return
        }
        _state.value = State.Installing
        Thread({ installNow(app) }, "rift-setup").start()
    }

    private fun installNow(app: Context) {
        val copy = File(app.cacheDir, "rift-browser.apk")
        try {
            app.assets.open(ASSET).use { input -> copy.outputStream().use { input.copyTo(it) } }
            verify(app, copy)?.let { return fail(it) }
            val installer = app.packageManager.packageInstaller
            val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
                setAppPackageName(Rift.BROWSER_PACKAGE)
                // An update of an app Rift installed itself needs no second confirmation (API 31+).
                if (Build.VERSION.SDK_INT >= 31) setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
            }
            val id = installer.createSession(params)
            installer.openSession(id).use { session ->
                session.openWrite("base.apk", 0, copy.length()).use { out ->
                    copy.inputStream().use { it.copyTo(out) }
                    session.fsync(out)
                }
                listen(app)
                val result = PendingIntent.getBroadcast(
                    app, id, Intent(ACTION_RESULT).setPackage(app.packageName),
                    // Mutable: the installer adds the outcome to it.
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
                )
                session.commit(result.intentSender)
            }
        } catch (e: IOException) {
            fail("the browser could not be written: ${e.message}")
        } catch (e: SecurityException) {
            fail("Android refused: ${e.message}")
        } finally {
            copy.delete()
        }
    }

    /** The carried APK is Rift's browser, signed with exactly the certificates Rift is signed with; null if so. */
    private fun verify(app: Context, apk: File): String? {
        val pm = app.packageManager
        val archive = pm.getPackageArchiveInfo(apk.path, PackageManager.GET_SIGNING_CERTIFICATES)
            ?: return "the carried browser is not a readable APK"
        if (archive.packageName != Rift.BROWSER_PACKAGE) return "the carried APK is ${archive.packageName}, not Rift's browser"
        val own = pm.getPackageInfo(app.packageName, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo?.apkContentsSigners
        val theirs = archive.signingInfo?.apkContentsSigners
        if (own == null || theirs == null) return "the carried browser's signature could not be read"
        val digests = { certs: Array<android.content.pm.Signature> -> certs.map { sha256(it.toByteArray().inputStream()).toList() }.toSet() }
        return if (digests(own) == digests(theirs)) null else "the carried browser is not signed with Rift's key"
    }

    private var listening = false

    /** The installer's outcome, delivered to Rift alone (an explicit, unexported broadcast). */
    @Synchronized
    private fun listen(app: Context) {
        if (listening) return
        listening = true
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context, intent: Intent) {
                when (val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)) {
                    PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                        // Android's own confirmation screen.
                        @Suppress("DEPRECATION")
                        val confirm = intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
                        if (confirm == null) fail("Android gave no confirmation screen") else c.startActivity(confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                    }
                    PackageInstaller.STATUS_SUCCESS -> {
                        Log.i(TAG, "sealed browser installed")
                        Core.browserInstalled()
                    }
                    else -> fail(
                        if (status == PackageInstaller.STATUS_FAILURE_ABORTED) "the install was cancelled"
                        else intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: "the install failed ($status)",
                    )
                }
            }
        }
        val filter = IntentFilter(ACTION_RESULT)
        if (Build.VERSION.SDK_INT >= 33) app.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED) else app.registerReceiver(receiver, filter)
    }

    private fun fail(reason: String) {
        Log.e(TAG, "browser setup failed: $reason")
        _state.value = State.Failed(reason)
    }

    private fun sha256(input: InputStream): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(64 * 1024)
        while (true) {
            val n = input.read(buffer)
            if (n < 0) break
            digest.update(buffer, 0, n)
        }
        return digest.digest()
    }
}
