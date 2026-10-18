package org.simulationrift.app

import android.app.Service
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.ServiceInfo
import android.os.DeadObjectException
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.RemoteException
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * One bound instance of an isolated worker service (§8.6), for one job.
 * Every call has a deadline; on expiry, a crash or [retire], the worker is
 * unbound, which ends the isolated process (the app cannot signal it).
 */
internal class IsolatedWorker private constructor(private val context: Context) : ServiceConnection {
    /** A job failed for a reason outside the protocol: binding, deadline or crash. */
    class Failed(message: String) : Exception(message)

    private val binder = CompletableFuture<IPreviewWorker>()
    private val retired = AtomicBoolean(false)

    override fun onServiceConnected(name: ComponentName, service: IBinder) {
        binder.complete(IPreviewWorker.Stub.asInterface(service))
    }

    override fun onServiceDisconnected(name: ComponentName) {
        binder.completeExceptionally(Failed("the worker stopped unexpectedly"))
    }

    override fun onBindingDied(name: ComponentName) = onServiceDisconnected(name)

    override fun onNullBinding(name: ComponentName) {
        binder.completeExceptionally(Failed("the worker did not provide an interface"))
    }

    fun connected(): IPreviewWorker = await(binder, CONNECT_TIMEOUT_MS, "start")

    fun <T> call(what: String, timeoutMs: Long, block: () -> T): T =
        await(CompletableFuture.supplyAsync(block, calls), timeoutMs, what)

    private fun <T> await(future: CompletableFuture<T>, timeoutMs: Long, what: String): T = try {
        future.get(timeoutMs, TimeUnit.MILLISECONDS)
    } catch (e: TimeoutException) {
        retire()
        throw Failed("the worker did not $what in time and was stopped")
    } catch (e: ExecutionException) {
        retire()
        throw when (val cause = e.cause) {
            is Failed -> cause
            is DeadObjectException -> Failed("the worker stopped unexpectedly")
            is RemoteException -> Failed("the worker failed: ${cause.javaClass.simpleName}")
            is RuntimeException -> Failed("the worker failed: ${cause.javaClass.simpleName}")
            else -> Failed("the worker failed")
        }
    }

    fun retire() {
        if (retired.compareAndSet(false, true)) {
            context.unbindService(this)
            binder.completeExceptionally(Failed("the worker was retired"))
        }
    }

    companion object {
        private const val CONNECT_TIMEOUT_MS = 5_000L

        private val instances = AtomicLong()
        private val calls = Executors.newCachedThreadPool { Thread(it, "rift-worker-call") }
        private val callbacks = Executors.newSingleThreadExecutor { Thread(it, "rift-worker-binding") }

        /** S7: refuses, before binding, any component the platform would not isolate. */
        fun bind(context: Context, service: Class<out Service>): IsolatedWorker {
            @Suppress("DEPRECATION") // the flags overload needs API 33
            val info = context.packageManager.getServiceInfo(ComponentName(context, service), 0)
            if (info.flags and ServiceInfo.FLAG_ISOLATED_PROCESS == 0) {
                throw Failed("the worker is not declared as an isolated process, so this feature is disabled")
            }
            if (info.exported) throw Failed("the worker is exported, so this feature is disabled")

            val worker = IsolatedWorker(context)
            // Instance names allow only letters, digits and '_' (Phase 2 finding 5).
            val instance = "worker_${instances.incrementAndGet()}"
            val bound = try {
                context.bindIsolatedService(Intent(context, service), Context.BIND_AUTO_CREATE, instance, callbacks, worker)
            } catch (e: RuntimeException) {
                throw Failed("the worker could not be started: ${e.javaClass.simpleName}")
            }
            if (!bound) {
                context.unbindService(worker)
                throw Failed("the worker could not be started")
            }
            return worker
        }

        /** RAM-backed, read-only input: the worker cannot change the bytes the controller hashed (PoC A7). */
        fun sealedMemfd(bytes: ByteArray): ParcelFileDescriptor {
            val fd = Os.memfd_create("rift-worker-input", MFD_ALLOW_SEALING)
            try {
                var offset = 0
                while (offset < bytes.size) offset += Os.write(fd, bytes, offset, bytes.size - offset)
                Os.lseek(fd, 0, OsConstants.SEEK_SET)
                Os.fcntlInt(fd, F_ADD_SEALS, F_SEAL_SHRINK or F_SEAL_GROW or F_SEAL_WRITE)
                // Seals cannot be removed, so the worker's copy is immutable however it is opened.
                return ParcelFileDescriptor.dup(fd)
            } catch (e: ErrnoException) {
                throw Failed("could not prepare the worker input: ${e.message}")
            } catch (e: java.io.IOException) {
                throw Failed("could not prepare the worker input: ${e.message}")
            } finally {
                Os.close(fd)
            }
        }

        private const val MFD_ALLOW_SEALING = 0x2
        private const val F_ADD_SEALS = 1033
        private const val F_SEAL_SHRINK = 0x2
        private const val F_SEAL_GROW = 0x4
        private const val F_SEAL_WRITE = 0x8
    }
}
