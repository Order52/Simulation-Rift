package org.simulationrift.app

import android.app.ActivityManager
import android.content.Context
import android.os.Process
import android.os.RemoteException
import android.os.SystemClock
import android.util.Log
import java.io.File
import org.simulationrift.core.BrowserDisposal
import org.simulationrift.core.DisposalException

/**
 * Engine-side disposal (§15 steps 3–5), called by rift-core during a reset
 * and again during launch recovery, so every step is idempotent. It throws
 * unless the browser process is gone and nothing but Rift's own files remain;
 * rift-core then reports the cleanup as failed instead of starting a session.
 */
class AndroidBrowserDisposal(private val context: Context) : BrowserDisposal {

    override fun destroyBrowserState(generation: ULong) {
        endBrowserProcess()
        val failures = deleteBrowserData()
        val leftovers = leftovers()
        if (failures.isNotEmpty() || leftovers.isNotEmpty()) {
            val reason = (failures + leftovers.map { "unexpected file remains: $it" }).take(10).joinToString("; ")
            throw DisposalException.Failed(reason)
        }
        Log.i(TAG, "generation $generation disposed")
    }

    /**
     * Asks :browser to finish its activity (so Android does not restore it
     * with the old generation), then kills the process and waits until it is
     * gone. Killing is what disposes of the engine's in-memory state.
     */
    private fun endBrowserProcess() {
        try {
            Core.detachBrowser()?.shutdown()
        } catch (e: RemoteException) {
            // Already dead or dying; the checks below decide.
            Log.i(TAG, "browser did not answer shutdown: $e")
        }
        browserPids().forEach { Process.killProcess(it) }
        if (!waitForBrowserExit(EXIT_TIMEOUT_MS)) {
            throw DisposalException.Failed("browser process still running: ${browserPids()}")
        }
    }

    private fun browserPids(): List<Int> {
        val name = "${context.packageName}$BROWSER_PROCESS_SUFFIX"
        return context.getSystemService(ActivityManager::class.java).runningAppProcesses.orEmpty()
            .filter { it.processName == name }
            .map { it.pid }
    }

    private fun waitForBrowserExit(timeoutMs: Long): Boolean {
        val deadline = SystemClock.elapsedRealtime() + timeoutMs
        while (true) {
            val alive = browserPids().filter { File("/proc/$it").exists() }
            if (alive.isEmpty()) return true
            if (SystemClock.elapsedRealtime() > deadline) return false
            SystemClock.sleep(POLL_MS)
        }
    }

    /**
     * Deletes the WebView data of every generation (not only this one, so a
     * directory left by an earlier failed cleanup goes too) and every file in
     * `shared_prefs/`. WebView writes some state there, outside the suffix
     * (PoC A2: `AwOriginVisitLoggerPrefs.xml`, hashes of visited origins).
     * Rift keeps nothing in SharedPreferences, so the directory is default-deny.
     */
    private fun deleteBrowserData(): List<String> {
        val targets = browserDirectories() + (File(context.dataDir, "shared_prefs").listFiles()?.toList() ?: emptyList())
        return targets.mapNotNull { target ->
            if (target.deleteRecursively()) null else "could not delete ${target.relativeTo(context.dataDir)}"
        }
    }

    private fun browserDirectories(): List<File> =
        listOf(context.dataDir, context.cacheDir, context.codeCacheDir).flatMap { root ->
            root.walkTopDown().maxDepth(2).filter { it.isDirectory && GENERATION_DIRECTORY.matches(it.name) }.toList()
        }.distinct()

    /**
     * Inventory against an allowlist of Rift's own files (§15 step 5): any
     * other file, or any generation directory, is a leftover. A new kind of
     * engine state therefore fails the reset visibly instead of surviving it.
     */
    private fun leftovers(): List<String> {
        val dataDir = context.dataDir
        val files = dataDir.walkTopDown()
            .filter { it.isFile || GENERATION_DIRECTORY.matches(it.name) }
            .map { it.relativeTo(dataDir).path }
            .filter { path -> ALLOWED.none { it.matches(path) } }
        return files.sorted().toList()
    }

    companion object {
        const val BROWSER_PROCESS_SUFFIX = ":browser"
        private const val EXIT_TIMEOUT_MS = 5_000L
        private const val POLL_MS = 20L

        /** WebView's per-generation directories, from `setDataDirectorySuffix("s<n>")`. */
        private val GENERATION_DIRECTORY = Regex(".+_s[0-9]+")

        /**
         * Files that may remain after a reset. Each entry is Rift's own state or
         * an Android runtime file measured on the emulators; see
         * docs/reports/phase-2.md for where each one comes from.
         */
        private val ALLOWED = listOf(
            Regex("files/rift/.*"), // rift-core: session marker, vault (sessions/<gen> is deleted by the core)
            // androidx.profileinstaller (via Compose): an empty marker that the
            // ART baseline profile was installed, and (release builds) the APK
            // update time it was written for. Neither holds browsing data.
            Regex("files/profileInstalled"),
            Regex("files/profileinstaller_profileWrittenFor_lastUpdateTime\\.dat"),
        )
    }
}
