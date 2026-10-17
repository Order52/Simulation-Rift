package org.simulationrift.poc

import android.app.Service
import android.app.ZygotePreload
import android.content.ClipboardManager
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.pdf.PdfRenderer
import android.os.Bundle
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.SharedMemory
import android.os.SystemClock
import androidx.core.os.BundleCompat
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import kotlin.math.max
import kotlin.math.min

/**
 * Runs in an `isolatedProcess`: a random UID with no permissions and the
 * `isolated_app` SELinux domain. It only ever sees descriptors it is handed.
 */
open class WorkerService : Service() {

    private val binder = object : IWorker.Stub() {
        override fun probe(canaryPath: String, tcpPort: Int): String = buildString {
            appendLine("kotlin.isIsolated=${Process.isIsolated()}")
            appendLine("kotlin.uid=${Process.myUid()}")
            appendLine("kotlin.read_canary=" + attempt { File(canaryPath).readText().length.toString() + " chars" })
            appendLine(
                "kotlin.list_app_files=" + attempt {
                    (File(canaryPath).parentFile?.list() ?: throw SecurityException("list() returned null")).size.toString()
                },
            )
            appendLine(
                "kotlin.tcp_connect=" + attempt {
                    Socket().use { it.connect(InetSocketAddress("127.0.0.1", tcpPort), 2000) }
                    "connected"
                },
            )
            appendLine("kotlin.dns=" + attempt { InetAddress.getByName("example.com").hostAddress ?: "null" })
            appendLine(
                "kotlin.clipboard=" + attempt {
                    val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager?
                        ?: throw SecurityException("no clipboard service")
                    "clip items=${clipboard.primaryClip?.itemCount}"
                },
            )
            append(Native.probes(canaryPath, tcpPort))
        }

        override fun renderPdf(pdf: ParcelFileDescriptor, pageIndex: Int, output: Bundle): String {
            val shm = BundleCompat.getParcelable(output, "shm", SharedMemory::class.java)
                ?: return "status=ERROR\nerror=no output region"
            val maxW = output.getInt("maxW")
            val maxH = output.getInt("maxH")
            val started = SystemClock.elapsedRealtimeNanos()
            return try {
                PdfRenderer(pdf).use { renderer ->
                    if (pageIndex !in 0 until renderer.pageCount) return "status=ERROR\nerror=page out of range"
                    renderer.openPage(pageIndex).use { page ->
                        val scale = min(maxW.toFloat() / page.width, maxH.toFloat() / page.height)
                        val w = max(1, (page.width * scale).toInt())
                        val h = max(1, (page.height * scale).toInt())
                        val bitmap = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
                        bitmap.eraseColor(Color.WHITE)
                        page.render(bitmap, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                        if (bitmap.byteCount > shm.size) return "status=ERROR\nerror=output region too small"
                        val buffer = shm.mapReadWrite()
                        try {
                            bitmap.copyPixelsToBuffer(buffer)
                        } finally {
                            SharedMemory.unmap(buffer)
                        }
                        val ms = (SystemClock.elapsedRealtimeNanos() - started) / 1_000_000.0
                        "status=OK\nwidth=$w\nheight=$h\npages=${renderer.pageCount}\nbytes=${bitmap.byteCount}\nrender_ms=%.1f".format(ms)
                    }
                }
            } catch (e: Throwable) {
                "status=ERROR\nerror=${e.javaClass.simpleName}: ${e.message}"
            }
        }

        override fun yaraScan(rules: String, input: ParcelFileDescriptor, timeoutMs: Long): String =
            input.use { Native.yaraScan(rules, it.fd, timeoutMs) }

        override fun pid(): Int = Process.myPid()

        override fun zygotePreload(): String = WorkerZygotePreload.status
    }

    override fun onBind(intent: Intent): IBinder = binder
}

/** The same worker, forked from the app zygote (`useAppZygote`) instead of the system zygote. */
class ZygoteWorkerService : WorkerService()

/**
 * Runs once in the app zygote, before any worker is forked from it. Loading the
 * native library here means each worker inherits it instead of loading it.
 */
class WorkerZygotePreload : ZygotePreload {
    override fun doPreload(appInfo: ApplicationInfo) {
        // A throw here would take down the zygote; record the outcome instead.
        status = try {
            System.loadLibrary("rift_poc_native")
            "loaded"
        } catch (e: Throwable) {
            "FAILED ${e.javaClass.simpleName}: ${e.message}"
        }
    }

    companion object {
        /** Inherited by forked workers; "none" in workers not forked from the app zygote. */
        @Volatile
        var status: String = "none"
    }
}
