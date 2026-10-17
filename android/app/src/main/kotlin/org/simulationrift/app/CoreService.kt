package org.simulationrift.app

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.Bundle
import android.os.IBinder
import android.os.Process
import org.simulationrift.core.DownloadInfo

/**
 * Hosts [ICore] in the main process for `:browser`. The service is not
 * exported, so only this app's UID can bind it; the UID check below repeats
 * that on every call as defence in depth.
 */
class CoreService : Service() {

    private val binder = object : ICore.Stub() {
        override fun register(generation: Long, browser: IBrowser): Boolean {
            checkCaller()
            return Core.registerBrowser(generation, browser)
        }

        override fun reportSandbox(generation: Long, verified: Boolean, detail: String) {
            checkCaller()
            Core.reportSandbox(generation, SandboxReport(verified, detail))
        }

        override fun decide(generation: Long, url: String): Bundle {
            checkCaller()
            return Core.decide(generation, url).toBundle()
        }

        override fun typedAddress(input: String): String {
            checkCaller()
            return Core.typed(input)
        }

        override fun submitDownload(
            generation: Long,
            url: String,
            cookie: String?,
            userAgent: String,
            referer: String?,
            contentDisposition: String?,
        ) {
            checkCaller()
            Core.submitDownload(generation, DownloadInfo(url, cookie, userAgent, referer, contentDisposition))
        }

        override fun requestReset(generation: Long) {
            checkCaller()
            Core.reset(generation)
        }

        override fun rendererGone(generation: Long, crashed: Boolean) {
            checkCaller()
            Core.rendererGone(generation, crashed)
        }
    }

    private fun checkCaller() {
        if (Binder.getCallingUid() != Process.myUid()) throw SecurityException("caller is not this app")
    }

    override fun onBind(intent: Intent): IBinder {
        Core.ensureStarted(this)
        return binder
    }
}
