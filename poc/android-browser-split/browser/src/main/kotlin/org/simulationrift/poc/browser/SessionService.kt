package org.simulationrift.poc.browser

import android.app.ActivityManager
import android.app.Application
import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.os.Process
import android.os.SystemClock
import android.util.Log
import java.io.File
import org.simulationrift.poc.ISession

/** Runs in the browser app's default process, which never loads WebView. */
class SessionService : Service() {
    private val binder = object : ISession.Stub() {
        override fun hello(): String =
            "uid=${Process.myUid()} pid=${Process.myPid()} process=${Application.getProcessName()} started=${Process.getStartElapsedRealtime()} now=${SystemClock.elapsedRealtime()}"

        override fun inventory(): List<String> {
            val roots = listOfNotNull(dataDir, externalCacheDir?.parentFile)
            return roots.flatMap { root ->
                root.walkTopDown().filter { it != root }.map { "${it.relativeTo(root).path}${if (it.isDirectory) "/" else ""}" }.toList()
            }.sorted()
        }

        override fun wipe(): Boolean {
            Log.i("POC", "browser wipe requested in pid ${Process.myPid()}")
            return getSystemService(ActivityManager::class.java).clearApplicationUserData()
        }
    }

    override fun onBind(intent: Intent): IBinder = binder
}
