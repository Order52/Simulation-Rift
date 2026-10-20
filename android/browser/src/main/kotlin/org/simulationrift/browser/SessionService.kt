package org.simulationrift.browser

import android.app.ActivityManager
import android.app.Application
import android.app.Service
import android.content.Intent
import android.os.Environment
import android.os.IBinder
import android.os.Process
import android.util.Log
import java.io.File
import org.simulationrift.bridge.ISession
import org.simulationrift.bridge.Rift

/**
 * The controller's handle on the browser app as a whole (§15 steps 3–4). It
 * runs in the default process, which never loads WebView, so a fresh
 * instance after a wipe reports on an app in which nothing has run yet.
 */
class SessionService : Service() {

    private val binder = object : ISession.Stub() {
        override fun pid(): Int {
            Rift.requireCaller(this@SessionService, Rift.CONTROLLER_PACKAGE)
            return Process.myPid()
        }

        override fun inventory(): List<String> {
            Rift.requireCaller(this@SessionService, Rift.CONTROLLER_PACKAGE)
            return files()
        }

        override fun wipe(): Boolean {
            Rift.requireCaller(this@SessionService, Rift.CONTROLLER_PACKAGE)
            Log.i(TAG, "system wipe requested in pid ${Process.myPid()}")
            return getSystemService(ActivityManager::class.java).clearApplicationUserData()
        }
    }

    override fun onCreate() {
        super.onCreate()
        check(Application.getProcessName() == packageName) { "SessionService runs in the default process only" }
    }

    override fun onBind(intent: Intent): IBinder = binder

    /**
     * Every file this app owns: credential- and device-protected storage and
     * its external directories, read without creating any of them.
     */
    private fun files(): List<String> {
        @Suppress("DEPRECATION") // the path only; nothing is created or read through it
        val external = Environment.getExternalStorageDirectory()
        val roots = listOf(
            "data" to dataDir,
            "device" to createDeviceProtectedStorageContext().dataDir,
            "external" to File(external, "Android/data/$packageName"),
            "media" to File(external, "Android/media/$packageName"),
        )
        return roots.flatMap { (label, root) ->
            root.walkTopDown().filter { !it.isDirectory }.map { "$label/${it.relativeTo(root).path}" }.toList()
        }.sorted()
    }
}

const val TAG = "RiftBrowser"
