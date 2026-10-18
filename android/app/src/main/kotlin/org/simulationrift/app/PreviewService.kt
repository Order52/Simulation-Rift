package org.simulationrift.app

import android.app.Service
import android.app.ZygotePreload
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.pdf.PdfRenderer
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.SharedMemory
import java.io.File
import java.io.IOException
import kotlin.math.floor
import kotlin.math.max
import kotlin.math.min
import org.simulationrift.worker.Job
import org.simulationrift.worker.PlatformResult
import org.simulationrift.worker.WorkerEngine
import org.simulationrift.worker.reject

/**
 * The untrusted-input worker (§8.6). It is an `isolatedProcess`: a random UID
 * in the `isolated_app` domain, with no permissions and no access to the
 * app's files. It sees only the frames and descriptors the controller hands
 * it, and the controller validates everything it returns.
 *
 * It loads `rift_worker_ffi` (parsers and protocol) and never `rift_ffi`, so
 * no core, session or vault code is mapped here. Each instance previews one
 * file and is then retired by unbinding.
 */
open class PreviewService : Service() {

    protected val engine by lazy {
        val status = ownStatus()
        WorkerEngine(status["Seccomp"].let { it != null && it != "0" }, status["NoNewPrivs"] == "1")
    }

    private val binder = object : IPreviewWorker.Stub() {
        override fun hello(request: ByteArray): ByteArray = this@PreviewService.hello(request)

        override fun render(request: ByteArray, input: ParcelFileDescriptor, output: SharedMemory): ByteArray =
            try {
                this@PreviewService.render(request, input, output)
            } finally {
                input.close()
                output.close()
            }
    }

    override fun onBind(intent: Intent): IBinder = binder

    protected open fun hello(request: ByteArray): ByteArray = engine.handle(request, null).frame

    protected open fun render(request: ByteArray, input: ParcelFileDescriptor, output: SharedMemory): ByteArray =
        when (val job = engine.job(request)) {
            Job.Native -> {
                val reply = engine.handle(request, readBounded(input))
                val pixels = reply.pixels
                when {
                    pixels == null -> reply.frame
                    pixels.size > output.size -> reject().frame
                    else -> {
                        write(output, pixels)
                        reply.frame
                    }
                }
            }
            is Job.PdfPage -> engine.platformReply(request, renderPdf(job, input, output)).frame
            Job.Invalid -> reject().frame
        }

    /** PdfRenderer (PDFium, in this process) fits the page into the requested box. */
    private fun renderPdf(job: Job.PdfPage, input: ParcelFileDescriptor, output: SharedMemory): PlatformResult = try {
        // PdfRenderer closes the descriptor it is given.
        PdfRenderer(input.dup()).use { renderer ->
            val index = job.page.toInt()
            if (job.page > Int.MAX_VALUE.toUInt() || index >= renderer.pageCount) return PlatformResult.Malformed
            renderer.openPage(index).use { page ->
                val maxW = job.maxWidth.toInt()
                val maxH = job.maxHeight.toInt()
                if (page.width <= 0 || page.height <= 0 || maxW <= 0 || maxH <= 0) return PlatformResult.Malformed
                val scale = min(maxW.toDouble() / page.width, maxH.toDouble() / page.height)
                val w = floor(page.width * scale).toInt().coerceIn(1, maxW)
                val h = floor(page.height * scale).toInt().coerceIn(1, maxH)
                if (w.toLong() * h * 4 > output.size) return PlatformResult.TooLarge
                val bitmap = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
                try {
                    // Opaque white page, so premultiplied and straight alpha agree.
                    bitmap.eraseColor(Color.WHITE)
                    page.render(bitmap, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                    val buffer = output.mapReadWrite()
                    try {
                        bitmap.copyPixelsToBuffer(buffer)
                    } finally {
                        SharedMemory.unmap(buffer)
                    }
                } finally {
                    bitmap.recycle()
                }
                PlatformResult.Bitmap(w.toUInt(), h.toUInt())
            }
        }
    } catch (e: SecurityException) {
        PlatformResult.Encrypted // PdfRenderer's answer to a password-protected file
    } catch (e: IOException) {
        PlatformResult.Malformed
    } catch (e: RuntimeException) {
        PlatformResult.EngineFailure
    }

    companion object {
        /** The controller's input limit (rift-ffi MAX_PREVIEW_INPUT); more is a protocol violation. */
        private const val MAX_INPUT = 32 * 1024 * 1024

        /** Reads the whole input, refusing more than [MAX_INPUT]: the size is the controller's, but checked here too. */
        private fun readBounded(input: ParcelFileDescriptor): ByteArray? {
            val stream = ParcelFileDescriptor.AutoCloseInputStream(input.dup())
            return stream.use {
                val out = java.io.ByteArrayOutputStream()
                val chunk = ByteArray(64 * 1024)
                while (true) {
                    val n = it.read(chunk)
                    if (n < 0) break
                    if (out.size() + n > MAX_INPUT) return null
                    out.write(chunk, 0, n)
                }
                out.toByteArray()
            }
        }

        private fun write(output: SharedMemory, pixels: ByteArray) {
            val buffer = output.mapReadWrite()
            try {
                buffer.put(pixels)
            } finally {
                SharedMemory.unmap(buffer)
            }
        }

        /** This process's own /proc status fields (Seccomp, NoNewPrivs, ...). */
        internal fun ownStatus(): Map<String, String> = try {
            File("/proc/self/status").readLines().mapNotNull { line ->
                line.split(':', limit = 2).takeIf { it.size == 2 }?.let { it[0] to it[1].trim() }
            }.toMap()
        } catch (e: IOException) {
            emptyMap() // reported as unconfined, which the controller refuses
        }
    }
}

/**
 * Runs once in the app zygote, before workers are forked from it (§8.6: the
 * app zygote is required for cold-start time). It only loads native code: the
 * zygote must stay single-threaded, so no JNA or UniFFI object is created here.
 */
class PreviewZygotePreload : ZygotePreload {
    override fun doPreload(appInfo: ApplicationInfo) {
        // A throw here would take down the zygote. A failed preload is not a
        // security problem: the worker then loads the libraries itself.
        try {
            System.loadLibrary("jnidispatch")
            System.loadLibrary("rift_worker_ffi")
        } catch (e: UnsatisfiedLinkError) {
            android.util.Log.w(TAG, "worker preload failed", e)
        }
    }
}
