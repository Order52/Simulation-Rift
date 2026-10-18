package org.simulationrift.app

import android.app.Service
import android.content.Context
import android.graphics.Bitmap
import android.os.SharedMemory
import java.nio.ByteBuffer
import org.simulationrift.core.PreviewJob

/**
 * The controller's side of a preview (§8.6, main process). Each preview gets
 * a fresh isolated worker ([IsolatedWorker]):
 *
 * 1. the service must be declared `isolatedProcess` (S7: no fallback);
 * 2. its Hello reply must report seccomp, before it is given any input;
 * 3. input is a sealed memfd, output a region the controller owns;
 * 4. every call has a deadline; on expiry the worker is unbound, which ends
 *    the isolated process (the app cannot signal it);
 * 5. the reply is validated by rift-ffi, the worker retired, and only then
 *    are the pixels copied out.
 */
object Previewer {
    /** The box previews are fitted into; 2048 x 2048 x 4 is the protocol's bitmap limit. */
    const val MAX_SIDE = 2048
    private const val REGION_BYTES = MAX_SIDE * MAX_SIDE * 4

    private const val HELLO_TIMEOUT_MS = 2_000L
    /** The worker's own deadline is 10 s (rift-ffi PREVIEW_DEADLINE_MS); this is the backstop. */
    private const val RENDER_TIMEOUT_MS = 12_000L

    /**
     * Runs `job` in a fresh instance of `service` and returns the validated
     * bitmap. Blocks: call it off the UI thread. Throws [IsolatedWorker.Failed]
     * or rift-ffi's PreviewFailure.
     */
    fun render(context: Context, job: PreviewJob, service: Class<out Service> = PreviewService::class.java): Bitmap {
        val worker = IsolatedWorker.bind(context, service)
        try {
            val binder = worker.connected()
            job.acceptHello(worker.call("hello", HELLO_TIMEOUT_MS) { binder.hello(job.helloFrame()) })
            val region = SharedMemory.create("rift-preview", REGION_BYTES)
            try {
                val reply = IsolatedWorker.sealedMemfd(job.input()).use { input ->
                    worker.call("render", RENDER_TIMEOUT_MS) { binder.render(job.requestFrame(), input, region) }
                }
                val header = job.accept(reply, region.size.toULong())
                // No writes can race the copy once the worker process is gone.
                worker.retire()
                return copyOut(region, header.width.toInt(), header.height.toInt())
            } finally {
                region.close()
            }
        } finally {
            worker.retire()
        }
    }

    /** Validated RGBA8 (unpremultiplied) rows into an ARGB bitmap. */
    private fun copyOut(region: SharedMemory, width: Int, height: Int): Bitmap {
        val buffer: ByteBuffer = region.mapReadOnly()
        try {
            val colors = IntArray(width * height)
            for (i in colors.indices) {
                val p = i * 4
                val r = buffer.get(p).toInt() and 0xff
                val g = buffer.get(p + 1).toInt() and 0xff
                val b = buffer.get(p + 2).toInt() and 0xff
                val a = buffer.get(p + 3).toInt() and 0xff
                colors[i] = (a shl 24) or (r shl 16) or (g shl 8) or b
            }
            return Bitmap.createBitmap(colors, width, height, Bitmap.Config.ARGB_8888)
        } finally {
            SharedMemory.unmap(buffer)
        }
    }
}
