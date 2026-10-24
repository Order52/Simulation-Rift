package org.simulationrift.app

import android.app.Service
import android.content.Intent
import android.os.Bundle
import android.os.IBinder
import org.simulationrift.bridge.IBrowser
import org.simulationrift.bridge.ICore
import org.simulationrift.bridge.PageHiding
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

        override fun inspectAnyway(generation: Long, url: String) {
            checkCaller()
            Core.inspectAnyway(generation, url)
        }

        override fun rendererGone(generation: Long, crashed: Boolean) {
            checkCaller()
            Core.rendererGone(generation, crashed)
        }

        override fun reportAttempt(generation: Long, kind: String, origin: String) {
            checkCaller()
            Core.reportAttempt(generation, kind, origin)
        }

        override fun reportDecoy(generation: Long, kind: String, origin: String, detail: String) {
            checkCaller()
            Core.reportDecoy(generation, kind, origin, detail)
        }

        override fun filtersOn(generation: Long): Boolean {
            checkCallerFast()
            return Core.isBrowser(generation) && ContentFilter.active()
        }

        override fun blockRequest(generation: Long, url: String, page: String, kind: String): Boolean {
            checkCallerFast()
            return Core.isBrowser(generation) && ContentFilter.blocks(url, page, kind)
        }

        override fun hidingFor(generation: Long, url: String): Bundle {
            checkCallerFast()
            return (if (Core.isBrowser(generation)) ContentFilter.hiding(url) else PageHiding.NONE).toBundle()
        }

        override fun genericHiding(generation: Long, classes: List<String>, ids: List<String>, exceptions: List<String>): String {
            checkCallerFast()
            return if (Core.isBrowser(generation)) ContentFilter.generic(classes, ids, exceptions) else ""
        }

        override fun pageWatch(generation: Long): Bundle {
            checkCaller()
            return Core.pageWatch(generation)?.toBundle() ?: Bundle()
        }

        override fun reportPage(generation: Long, url: String, names: String, password: Boolean, card: Boolean) {
            checkCaller()
            Core.reportPage(generation, url, names, password, card)
        }

        override fun testOpenReport(generation: Long): Bundle {
            checkCaller()
            return Core.testOpenReport(generation)?.toBundle() ?: Bundle()
        }
    }

    private fun checkCaller() = Rift.requireCaller(this, Rift.BROWSER_PACKAGE)

    /** For the content filters' calls, which come for every request of a page. */
    private fun checkCallerFast() = Rift.requireCallerFast(this, Rift.BROWSER_PACKAGE)

    override fun onBind(intent: Intent): IBinder {
        Core.ensureStarted(this)
        return binder
    }
}
