package org.simulationrift.app

import android.app.Service
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Intent
import android.content.ServiceConnection
import android.os.Environment
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.SharedMemory
import android.system.Os
import android.system.OsConstants
import java.io.File
import java.io.FileDescriptor
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import org.simulationrift.worker.PlatformResult
import org.simulationrift.worker.WorkerEngine
import org.simulationrift.worker.confineCurrentThread

// Debug builds only (src/debug): workers for the S3–S7 instrumented tests.
// Each isolated one is declared exactly like PreviewService.

/** S3/S4: reports what a worker-identical isolated process can reach. */
class ProbeWorkerService : Service() {
    private val binder = object : IWorkerProbe.Stub() {
        override fun probe(canaryPath: String, tcpPort: Int): String = buildString {
            val status = PreviewService.ownStatus()
            appendLine("isolated=${Process.isIsolated()}")
            appendLine("uid=${Process.myUid()}")
            appendLine("seccomp=${status["Seccomp"]}")
            appendLine("no_new_privs=${status["NoNewPrivs"]}")
            appendLine("read_canary=" + attempt { File(canaryPath).readText().length.toString() + " chars" })
            appendLine("list_app_files=" + attempt { (File(canaryPath).parentFile?.list() ?: throw SecurityException("list() returned null")).size.toString() })
            appendLine("write_app_files=" + attempt { File(File(canaryPath).parentFile, "from-worker").writeText("x"); "written" })
            appendLine(
                "list_external_storage=" + attempt {
                    @Suppress("DEPRECATION")
                    (Environment.getExternalStorageDirectory().list() ?: throw SecurityException("list() returned null")).size.toString()
                },
            )
            appendLine("tcp_connect=" + attempt { Socket().use { it.connect(InetSocketAddress("127.0.0.1", tcpPort), 2000) }; "connected" })
            appendLine("udp_socket=" + attempt { DatagramSocket().use { "opened" } })
            appendLine("dns=" + attempt { InetAddress.getByName("example.com").hostAddress ?: "null" })
            appendLine(
                "clipboard=" + attempt {
                    val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager? ?: throw SecurityException("no clipboard service")
                    "items=${clipboard.primaryClip?.itemCount}"
                },
            )
            appendLine(
                "bind_core=" + attempt {
                    val connection = object : ServiceConnection {
                        override fun onServiceConnected(name: ComponentName, service: IBinder) = Unit
                        override fun onServiceDisconnected(name: ComponentName) = Unit
                    }
                    val bound = bindService(Intent().setClassName(packageName, "$packageName.CoreService"), connection, BIND_AUTO_CREATE)
                    if (bound) unbindService(connection)
                    if (bound) "bound" else throw SecurityException("bindService returned false")
                },
            )
            appendLine("unix_socket=" + attempt { unixSocket() })
            appendLine("exec_mapping=" + attempt { execMapping() })
            // The same two on a thread with PreviewService's parser filter.
            appendLine("unix_socket_filtered_thread=" + onFilteredThread { unixSocket() })
            appendLine("exec_mapping_filtered_thread=" + onFilteredThread { execMapping() })
        }
    }

    override fun onBind(intent: Intent): IBinder = binder

    private fun unixSocket(): String {
        val fd = Os.socket(OsConstants.AF_UNIX, OsConstants.SOCK_STREAM, 0)
        Os.close(fd)
        return "created"
    }

    private fun execMapping(): String {
        val address = Os.mmap(0, 4096, OsConstants.PROT_READ or OsConstants.PROT_EXEC, OsConstants.MAP_PRIVATE or OsConstants.MAP_ANONYMOUS, FileDescriptor(), 0)
        Os.munmap(address, 4096)
        return "mapped"
    }

    private fun onFilteredThread(block: () -> String): String {
        var result = "not run"
        val thread = Thread {
            result = try {
                confineCurrentThread()
                attempt(block)
            } catch (e: Throwable) {
                "FILTER FAILED ${e.javaClass.simpleName}: ${e.message}"
            }
        }
        thread.start()
        thread.join()
        return result
    }

    private fun attempt(block: () -> String): String = try {
        "ALLOWED " + block()
    } catch (e: Throwable) {
        "DENIED ${e.javaClass.simpleName}: ${e.message}"
    }
}

/**
 * S4: PreviewService itself, which checks from inside the render path that
 * the parser-thread filter is in force: if it can still create an AF_UNIX
 * socket it answers garbage, which the controller rejects.
 */
class FilterCheckingPreviewService : PreviewService() {
    override fun render(request: ByteArray, input: ParcelFileDescriptor, output: SharedMemory): ByteArray {
        val unfiltered = try {
            Os.close(Os.socket(OsConstants.AF_UNIX, OsConstants.SOCK_STREAM, 0))
            true
        } catch (e: android.system.ErrnoException) {
            false
        }
        return if (unfiltered) byteArrayOf(0) else super.render(request, input, output)
    }
}

/** S6: never answers the render request. */
class HangingPreviewService : PreviewService() {
    override fun render(request: ByteArray, input: ParcelFileDescriptor, output: SharedMemory): ByteArray {
        while (true) Thread.sleep(60_000)
    }
}

/** S6: dies mid-request, as a parser crash would. */
class CrashingPreviewService : PreviewService() {
    override fun render(request: ByteArray, input: ParcelFileDescriptor, output: SharedMemory): ByteArray {
        Process.killProcess(Process.myPid())
        throw IllegalStateException("unreachable")
    }
}

/** S5: claims a bitmap larger than the requested box and the region. */
class OversizedPreviewService : PreviewService() {
    override fun render(request: ByteArray, input: ParcelFileDescriptor, output: SharedMemory): ByteArray =
        engine.platformReply(request, PlatformResult.Bitmap(65_535u, 65_535u)).frame
}

/** S5: a frame whose length prefix claims 4 GiB, followed by noise. */
class GarbagePreviewService : PreviewService() {
    override fun render(request: ByteArray, input: ParcelFileDescriptor, output: SharedMemory): ByteArray =
        byteArrayOf(-1, -1, -1, -1) + ByteArray(60_000) { (it * 31).toByte() }
}

/** S5: answers the render request with its (valid) Hello reply: wrong job and type. */
class ReplayingPreviewService : PreviewService() {
    private var lastHello: ByteArray = ByteArray(0)

    override fun hello(request: ByteArray): ByteArray = super.hello(request).also { lastHello = it }

    override fun render(request: ByteArray, input: ParcelFileDescriptor, output: SharedMemory): ByteArray = lastHello
}

/** S7 (simulated): a worker whose process reports no seccomp filter. */
class NoSeccompPreviewService : PreviewService() {
    private val unconfined by lazy { WorkerEngine(false, false) }

    override fun hello(request: ByteArray): ByteArray = unconfined.handle(request, null).frame
}

/**
 * S7: PreviewService's code without isolation. If the controller ever sent it
 * input, it would leave a marker in the app's files, which the test checks.
 */
class UnconfinedPreviewService : PreviewService() {
    override fun render(request: ByteArray, input: ParcelFileDescriptor, output: SharedMemory): ByteArray {
        File(filesDir, MARKER).writeText("render reached an unconfined worker")
        return super.render(request, input, output)
    }

    companion object {
        const val MARKER = "unconfined-render-called"
    }
}
