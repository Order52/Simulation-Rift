package org.simulationrift.app

import android.app.ActivityManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.annotation.VisibleForTesting
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.Executors
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.simulationrift.core.AppRelease
import org.simulationrift.core.AppUpdateFailure
import org.simulationrift.core.downloadAppRelease
import org.simulationrift.core.newerAppRelease

/**
 * Rift updates itself (§8.11). Once a day, with the switch on (the
 * default), the core asks GitHub for Rift's latest release and, if it is
 * newer, downloads the APK and checks it against the SHA-256 published with
 * it. Here the APK must also be Rift's own package, a higher version, and
 * signed with exactly Rift's certificates; then Android's installer gets it.
 *
 * The first update asks the user (Android's own screen, after a tap on
 * Install). Once Rift has installed itself, Android lets it install later
 * updates without asking (API 31+), and Rift does so by itself, but only
 * while none of its screens is in front and no browser window is open.
 *
 * With "Check when Rift opens" on (the default), each launch also asks, and
 * a newer release is offered in a dialog: one tap downloads, checks and
 * installs it. A check the user started (at launch or with Check now)
 * downloads nothing until the user taps Update, so it costs one small
 * request on a metered network; it works whether or not the daily one is on.
 */
object SelfUpdate {

    sealed interface State {
        /** A debug build: it updates with the build tools, never from releases. */
        data object DebugBuild : State
        data object Idle : State
        data object Checking : State
        data class UpToDate(val checkedAt: Long) : State
        /** A newer release, not downloaded yet. */
        data class Available(val release: AppRelease) : State
        data class Downloading(val version: String) : State
        /** Downloaded and checked; `problem`: why the last install did not happen. */
        data class Ready(val version: String, val problem: String? = null) : State
        data object Installing : State
        data class Failed(val reason: String) : State
    }

    private const val TAG = "RiftUpdate"
    private const val OFF_FILE = "self-update-off"
    private const val LAUNCH_OFF_FILE = "self-update-launch-off"
    private const val CHECKED_FILE = "self-update-checked"
    private const val APK = "update/rift.apk"
    private const val ACTION_RESULT = "org.simulationrift.app.SELF_UPDATED"
    const val STALE_MS = 24L * 60 * 60 * 1000

    private val _state = MutableStateFlow<State>(State.Idle)
    val state: StateFlow<State> = _state

    /** Daily checks, and installing by itself. */
    private val _automatic = MutableStateFlow(true)
    val automatic: StateFlow<Boolean> = _automatic

    /** A check at each launch, with a dialog if there is a newer release. */
    private val _atLaunch = MutableStateFlow(true)
    val atLaunch: StateFlow<Boolean> = _atLaunch

    /** Whether the update dialog is open: offered at launch, then followed through after Update. */
    private val _dialog = MutableStateFlow(false)
    val dialog: StateFlow<Boolean> = _dialog
    private val work = Executors.newSingleThreadExecutor { Thread(it, "rift-self-update") }
    private lateinit var app: Context

    fun init(context: Context) {
        app = context.applicationContext
        File(app.cacheDir, APK).delete()
        val debuggable = (app.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
        _state.value = if (debuggable) State.DebugBuild else State.Idle
        _automatic.value = !File(app.filesDir, OFF_FILE).exists()
        _atLaunch.value = !File(app.filesDir, LAUNCH_OFF_FILE).exists()
    }

    fun setEnabled(on: Boolean) {
        if (_state.value == State.DebugBuild) return
        val file = File(app.filesDir, OFF_FILE)
        _automatic.value = on
        if (on) {
            file.delete()
            refreshIfStale()
        } else {
            file.createNewFile()
        }
    }

    fun setAtLaunch(on: Boolean) {
        if (_state.value == State.DebugBuild) return
        val file = File(app.filesDir, LAUNCH_OFF_FILE)
        _atLaunch.value = on
        if (on) file.delete() else file.createNewFile()
    }

    /** Daily, from the content filters' timer and at start. */
    fun refreshIfStale() {
        if (!::app.isInitialized || !_automatic.value || _state.value == State.DebugBuild) return
        when (val now = _state.value) {
            is State.Ready -> if (now.problem == null) installQuietlyIfAllowed()
            is State.Checking, is State.Downloading, State.Installing -> return
            else -> {
                if (now is State.Failed || System.currentTimeMillis() - lastChecked() > STALE_MS) start(download = true)
            }
        }
    }

    /** Rift was opened (not recreated): asks, and opens the dialog if there is a newer release. */
    fun checkAtLaunch() {
        if (!::app.isInitialized || !_atLaunch.value || _state.value == State.DebugBuild) return
        when (_state.value) {
            is State.Available, is State.Ready -> _dialog.value = true
            // The daily check got there first: the dialog opens when it ends.
            is State.Checking, is State.Downloading -> launching = true
            State.Installing -> return
            else -> {
                launching = true
                start(download = false)
            }
        }
    }

    /** The user tapped Check now. */
    fun checkNow() = start(download = false)

    /** The user closed the dialog. */
    fun dismiss() {
        _dialog.value = false
    }

    @Volatile private var launching = false

    private fun start(download: Boolean) {
        if (_state.value == State.DebugBuild) return
        _state.value = State.Checking
        work.execute { check(download) }
    }

    private fun check(download: Boolean) {
        val installed = installedVersion() ?: return fail("Rift's own version could not be read")
        try {
            val release: AppRelease? = newerAppRelease(installed)
            File(app.filesDir, CHECKED_FILE).writeText(System.currentTimeMillis().toString())
            if (release == null) {
                _state.value = State.UpToDate(System.currentTimeMillis())
                return
            }
            if (download) fetchAndVerify(release) else _state.value = State.Available(release)
            if (launching) _dialog.value = true
        } catch (e: AppUpdateFailure) {
            fail(e.message ?: "the update check failed")
        } catch (e: IOException) {
            fail("the update check failed: ${e.message}")
        } finally {
            launching = false
        }
    }

    /** Downloads [release] and checks it; installs by itself if allowed. */
    private fun fetchAndVerify(release: AppRelease) {
        _state.value = State.Downloading(release.version)
        val apk = File(app.cacheDir, APK).apply { parentFile?.mkdirs() }
        downloadAppRelease(release, apk.path)
        verify(apk)?.let { apk.delete(); return fail(it) }
        Log.i(TAG, "update ${release.version} downloaded and verified")
        _state.value = State.Ready(release.version)
        installQuietlyIfAllowed()
    }

    private var readyVersion: String? = null

    /** The user tapped Update or Install: downloads it first if needed, then installs. */
    fun install() {
        when (val now = _state.value) {
            is State.Available -> {
                readyVersion = now.release.version
                _state.value = State.Downloading(now.release.version)
                work.execute {
                    try {
                        fetchAndVerify(now.release)
                        if (_state.value is State.Ready) {
                            _state.value = State.Installing
                            installNow()
                        }
                    } catch (e: AppUpdateFailure) {
                        fail(e.message ?: "the download failed")
                    } catch (e: IOException) {
                        fail("the download failed: ${e.message}")
                    }
                }
            }
            is State.Ready -> {
                readyVersion = now.version
                _state.value = State.Installing
                work.execute(::installNow)
            }
            else -> Unit
        }
    }

    /** Whether Android lets Rift install apps ("Install unknown apps"); read again on each return to Rift. */
    private val _mayInstall = MutableStateFlow(true)
    val mayInstall: StateFlow<Boolean> = _mayInstall

    fun resumed() {
        if (::app.isInitialized) _mayInstall.value = app.packageManager.canRequestPackageInstalls()
    }

    /** Without asking, only where Android allows it and nothing of Rift is in use. */
    private fun installQuietlyIfAllowed() {
        if (!_automatic.value || _state.value !is State.Ready || !canInstallQuietly() || Core.browsing() || inFront()) return
        Log.i(TAG, "installing the update by itself")
        install()
    }

    private fun canInstallQuietly(): Boolean {
        if (Build.VERSION.SDK_INT < 31) return false
        val source = try {
            app.packageManager.getInstallSourceInfo(app.packageName).installingPackageName
        } catch (e: PackageManager.NameNotFoundException) {
            null
        }
        return source == app.packageName && app.packageManager.canRequestPackageInstalls()
    }

    private fun inFront(): Boolean {
        val info = ActivityManager.RunningAppProcessInfo()
        ActivityManager.getMyMemoryState(info)
        return info.importance <= ActivityManager.RunningAppProcessInfo.IMPORTANCE_VISIBLE &&
            info.importance != ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND_SERVICE
    }

    private fun installNow() {
        val apk = File(app.cacheDir, APK)
        if (!apk.exists()) return fail("the downloaded update is gone; it will be downloaded again")
        verify(apk)?.let { apk.delete(); return fail(it) }
        if (!app.packageManager.canRequestPackageInstalls()) {
            return fail("allow Rift to install apps in Android's settings (Install unknown apps), then tap Install again")
        }
        try {
            val installer = app.packageManager.packageInstaller
            val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
                setAppPackageName(app.packageName)
                if (Build.VERSION.SDK_INT >= 31) setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
            }
            val id = installer.createSession(params)
            installer.openSession(id).use { session ->
                session.openWrite("base.apk", 0, apk.length()).use { out ->
                    apk.inputStream().use { it.copyTo(out) }
                    session.fsync(out)
                }
                listen()
                val result = PendingIntent.getBroadcast(
                    app, id, Intent(ACTION_RESULT).setPackage(app.packageName),
                    // Mutable: the installer adds the outcome to it.
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
                )
                session.commit(result.intentSender)
            }
        } catch (e: IOException) {
            fail("the update could not be written: ${e.message}")
        } catch (e: SecurityException) {
            fail("Android refused: ${e.message}")
        }
    }

    /** Rift's own package, newer than this install, signed with exactly Rift's certificates; null if so. */
    private fun verify(apk: File): String? {
        val pm = app.packageManager
        val archive = pm.getPackageArchiveInfo(apk.path, PackageManager.GET_SIGNING_CERTIFICATES)
            ?: return "the update is not a readable APK"
        if (archive.packageName != app.packageName) return "the update is ${archive.packageName}, not Rift"
        val own = pm.getPackageInfo(app.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        if (archive.longVersionCode <= own.longVersionCode) return "the update is not newer than this install"
        val mine = own.signingInfo?.apkContentsSigners
        val theirs = archive.signingInfo?.apkContentsSigners
        if (mine == null || theirs == null) return "the update's signature could not be read"
        val digests = { certs: Array<android.content.pm.Signature> ->
            certs.map { MessageDigest.getInstance("SHA-256").digest(it.toByteArray()).toList() }.toSet()
        }
        return if (digests(mine) == digests(theirs)) null else "the update is not signed with Rift's key"
    }

    /**
     * Tests only (N11): a debug build never checks, so the dialog is shown
     * for a made-up release; null puts the debug state back.
     */
    @VisibleForTesting
    internal fun offerForTest(version: String?) {
        _state.value = if (version == null) State.DebugBuild else State.Available(AppRelease(version))
        _dialog.value = version != null
    }

    private var listening = false

    @Synchronized
    private fun listen() {
        if (listening) return
        listening = true
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context, intent: Intent) {
                when (val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)) {
                    PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                        @Suppress("DEPRECATION")
                        val confirm = intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
                        if (confirm == null) fail("Android gave no confirmation screen") else c.startActivity(confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                    }
                    // Android replaces Rift and ends this process; nothing more happens here.
                    PackageInstaller.STATUS_SUCCESS -> Log.i(TAG, "update installed")
                    else -> {
                        val problem = if (status == PackageInstaller.STATUS_FAILURE_ABORTED) "the install was cancelled"
                        else intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: "the install failed ($status)"
                        Log.w(TAG, "self-update: $problem")
                        // The checked APK is still there: Install can be tapped again.
                        val version = readyVersion
                        _state.value = if (version != null && File(app.cacheDir, APK).exists()) State.Ready(version, problem) else State.Failed(problem)
                    }
                }
            }
        }
        val filter = IntentFilter(ACTION_RESULT)
        if (Build.VERSION.SDK_INT >= 33) app.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED) else app.registerReceiver(receiver, filter)
    }

    private fun installedVersion(): String? = try {
        app.packageManager.getPackageInfo(app.packageName, 0).versionName
    } catch (e: PackageManager.NameNotFoundException) {
        null
    }

    private fun lastChecked(): Long = try {
        File(app.filesDir, CHECKED_FILE).readText().trim().toLong()
    } catch (e: IOException) {
        0L
    } catch (e: NumberFormatException) {
        0L
    }

    private fun fail(reason: String) {
        Log.w(TAG, "self-update: $reason")
        _state.value = State.Failed(reason)
    }
}
