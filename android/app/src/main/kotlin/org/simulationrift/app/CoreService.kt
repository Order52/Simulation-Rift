package org.simulationrift.app

import android.app.Service
import android.content.Intent
import android.os.Bundle
import android.os.IBinder
import org.simulationrift.bridge.IBrowser
import org.simulationrift.bridge.ICore
import org.simulationrift.bridge.Rift
import org.simulationrift.core.DownloadInfo

/**
 * Hosts [ICore] in the main process for the browser app (§8.3). The
 * service requires Rift's signature permission; every call also checks that
 * the caller is the browser app's UID and is signed with Rift's key, so no
 * other app (and no other process of this one) can use it.
 */
class CoreService : Service() {

    private val binder = object : ICore.Stub() {
        override fun register(generation: Long, browser: IBrowser): Bundle {
            checkCaller()
            return Core.registerBrowser(generation, browser).toBundle()
        }

        override fun reportSandbox(generation: Long, verified: Boolean, detail: String) {
            checkCaller()
            Core.reportSandbox(generation, SandboxReport(verified, detail))
        }

        override fun reportNetwork(generation: Long, proxied: Boolean, locked: Boolean, detail: String) {
            checkCaller()
            Core.reportNetwork(generation, NetworkReport(proxied, locked, detail))
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

    private fun checkCaller() = Rift.requireCaller(this, Rift.BROWSER_PACKAGE)

    override fun onBind(intent: Intent): IBinder {
        Core.ensureStarted(this)
        return binder
    }
}
