package org.simulationrift.app

import android.app.Service
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.ServiceInfo
import android.graphics.Bitmap
import android.os.DeadObjectException
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.RemoteException
import android.os.SharedMemory
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import java.nio.ByteBuffer
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import org.simulationrift.core.PreviewJob

/**
 * The controller's side of a preview (§8.6, main process). Each preview gets
 * a fresh isolated worker:
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

    private const val CONNECT_TIMEOUT_MS = 5_000L
    private const val HELLO_TIMEOUT_MS = 2_000L
    /** The worker's own deadline is 10 s (rift-ffi PREVIEW_DEADLINE_MS); this is the backstop. */
    private const val RENDER_TIMEOUT_MS = 12_000L

    /** A preview failed for a reason outside the protocol: binding, deadline or crash. */
    class Failed(message: String) : Exception(message)

    private val instances = AtomicLong()
    private val calls = Executors.newCachedThreadPool { Thread(it, "rift-preview-call") }
    private val callbacks = Executors.newSingleThreadExecutor { Thread(it, "rift-preview-binding") }

    /**
     * Runs `job` in a fresh instance of `service` and returns the validated
     * bitmap. Blocks: call it off the UI thread. Throws [Failed] or rift-ffi's
     * PreviewFailure.
     */
    fun render(context: Context, job: PreviewJob, service: Class<out Service> = PreviewService::class.java): Bitmap {
        requireIsolated(context, service)
        val worker = Worker.bind(context, service, "preview_${instances.incrementAndGet()}")
        try {
            val binder = worker.connected()
            job.acceptHello(worker.call("hello", HELLO_TIMEOUT_MS) { binder.hello(job.helloFrame()) })
            val region = SharedMemory.create("rift-preview", REGION_BYTES)
            try {
                val reply = sealedMemfd(job.input()).use { input ->
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

    /** S7: refuse, before binding, any component the platform would not isolate. */
    private fun requireIsolated(context: Context, service: Class<out Service>) {
        @Suppress("DEPRECATION") // the flags overload needs API 33
        val info = context.packageManager.getServiceInfo(ComponentName(context, service), 0)
        if (info.flags and ServiceInfo.FLAG_ISOLATED_PROCESS == 0) {
            throw Failed("the preview worker is not declared as an isolated process, so previews are disabled")
        }
        if (info.exported) throw Failed("the preview worker is exported, so previews are disabled")
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

    /** RAM-backed, read-only input: the worker cannot change the bytes the controller hashed (PoC A7). */
    private fun sealedMemfd(bytes: ByteArray): ParcelFileDescriptor {
        val fd = Os.memfd_create("rift-preview-input", MFD_ALLOW_SEALING)
        try {
            var offset = 0
            while (offset < bytes.size) offset += Os.write(fd, bytes, offset, bytes.size - offset)
            Os.lseek(fd, 0, OsConstants.SEEK_SET)
            Os.fcntlInt(fd, F_ADD_SEALS, F_SEAL_SHRINK or F_SEAL_GROW or F_SEAL_WRITE)
            // Seals cannot be removed, so the worker's copy is immutable however it is opened.
            return ParcelFileDescriptor.dup(fd)
        } catch (e: ErrnoException) {
            throw Failed("could not prepare the preview input: ${e.message}")
        } catch (e: java.io.IOException) {
            throw Failed("could not prepare the preview input: ${e.message}")
        } finally {
            Os.close(fd)
        }
    }

    /** One bound worker instance; retiring it unbinds, which ends the isolated process. */
    private class Worker private constructor(private val context: Context) : ServiceConnection {
        private val binder = CompletableFuture<IPreviewWorker>()
        private val retired = AtomicBoolean(false)

        override fun onServiceConnected(name: ComponentName, service: IBinder) {
            binder.complete(IPreviewWorker.Stub.asInterface(service))
        }

        override fun onServiceDisconnected(name: ComponentName) {
            binder.completeExceptionally(Failed("the preview worker stopped unexpectedly"))
        }

        override fun onBindingDied(name: ComponentName) = onServiceDisconnected(name)

        override fun onNullBinding(name: ComponentName) {
            binder.completeExceptionally(Failed("the preview worker did not provide an interface"))
        }

        fun connected(): IPreviewWorker = await(binder, CONNECT_TIMEOUT_MS, "start")

        fun <T> call(what: String, timeoutMs: Long, block: () -> T): T =
            await(CompletableFuture.supplyAsync(block, calls), timeoutMs, what)

        private fun <T> await(future: CompletableFuture<T>, timeoutMs: Long, what: String): T = try {
            future.get(timeoutMs, TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            retire()
            throw Failed("the preview worker did not $what in time and was stopped")
        } catch (e: ExecutionException) {
            retire()
            throw when (val cause = e.cause) {
                is Failed -> cause
                is DeadObjectException -> Failed("the preview worker stopped unexpectedly")
                is RemoteException -> Failed("the preview worker failed: ${cause.javaClass.simpleName}")
                is RuntimeException -> Failed("the preview worker failed: ${cause.javaClass.simpleName}")
                else -> Failed("the preview worker failed")
            }
        }

        fun retire() {
            if (retired.compareAndSet(false, true)) {
                context.unbindService(this)
                binder.completeExceptionally(Failed("the preview worker was retired"))
            }
        }

        companion object {
            fun bind(context: Context, service: Class<out Service>, instance: String): Worker {
                val worker = Worker(context)
                val bound = try {
                    context.bindIsolatedService(Intent(context, service), Context.BIND_AUTO_CREATE, instance, callbacks, worker)
                } catch (e: RuntimeException) {
                    throw Failed("the preview worker could not be started: ${e.javaClass.simpleName}")
                }
                if (!bound) {
                    context.unbindService(worker)
                    throw Failed("the preview worker could not be started")
                }
                return worker
            }
        }
    }

    private const val MFD_ALLOW_SEALING = 0x2
    private const val F_ADD_SEALS = 1033
    private const val F_SEAL_SHRINK = 0x2
    private const val F_SEAL_GROW = 0x4
    private const val F_SEAL_WRITE = 0x8
}
