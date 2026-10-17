package org.simulationrift.poc

import android.app.Activity
import android.app.ActivityManager
import android.content.ComponentName
import android.content.Intent
import android.content.ServiceConnection
import android.graphics.Bitmap
import android.graphics.Color
import android.os.Bundle
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.SharedMemory
import android.os.SystemClock
import android.system.Os
import android.system.OsConstants
import android.util.Log
import java.io.File
import java.io.FileDescriptor
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * Trusted controller. Each launch runs one test named by the `test` extra and
 * writes `files/results/<name>.txt`; poc/android-feasibility/run-poc.sh drives it.
 */
class MainActivity : Activity() {

    private companion object {
        const val WORKER_SCAN_TIMEOUT_MS = 15_000L

        /** Loops over every byte for every byte: runs far past any deadline here. */
        const val SLOW_RULES =
            "rule rift_slow { condition: for all i in (0..filesize - 1) : (for all j in (0..filesize - 1) : (uint8(i) != 0x100 + j)) }"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val test = intent.getStringExtra("test")
        val label = intent.getStringExtra("label") ?: "default"
        when (test) {
            "worker" -> thread { runWorkerTests(); finish() }
            "lifecycle" -> thread { Results.write(this, "lifecycle", runLifecycleTests()); finish() }
            "browse" -> {
                startActivity(
                    Intent(this, BrowserActivity::class.java)
                        .putExtra("test", intent.getStringExtra("mode"))
                        .putExtra("label", intent.getStringExtra("label")),
                )
                finish()
            }
            // A pending marker means an interrupted reset: only `recover` may run.
            // This also stops Android's relaunch of the crashed activity (same
            // intent) from repeating the crash.
            "reset" -> thread {
                Results.write(this, "reset-$label", if (marker.exists()) "reset=REFUSED recovery-pending\n" else reset(crashBeforeDelete = false))
                finish()
            }
            "reset-crash" -> if (marker.exists()) finish() else thread { reset(crashBeforeDelete = true) }
            "recover" -> thread { Results.write(this, "recover-$label", recover()); finish() }
            "inventory" -> {
                Results.write(this, "inventory-$label", inventory(dataDir))
                finish()
            }
            else -> finish()
        }
    }

    // ---- A2: disposal --------------------------------------------------------

    private val marker get() = File(filesDir, "reset-marker")

    /**
     * Reset as specified in §15: record intent, kill `:browser`, delete the old
     * generation's WebView directories, verify, then advance the generation.
     */
    private fun reset(crashBeforeDelete: Boolean): String = buildString {
        val generation = Generation.read(this@MainActivity)
        marker.writeText("RESETTING $generation")
        appendLine("generation.before=$generation")
        appendLine("browser.killed=${killBrowserProcess()}")
        if (crashBeforeDelete) {
            // Simulates the app dying mid-reset; `recover` must finish the job.
            Process.killProcess(Process.myPid())
        }
        append(deleteGeneration(generation))
        Generation.write(this@MainActivity, generation + 1)
        marker.delete()
        appendLine("generation.after=${generation + 1}")
    }

    private fun recover(): String = buildString {
        if (!marker.exists()) {
            appendLine("recovery=not-needed")
            return@buildString
        }
        val generation = marker.readText().removePrefix("RESETTING ").trim().toInt()
        appendLine("recovery=marker-found generation=$generation")
        appendLine("browser.killed=${killBrowserProcess()}")
        append(deleteGeneration(generation))
        Generation.write(this@MainActivity, generation + 1)
        marker.delete()
        appendLine("generation.after=${generation + 1}")
    }

    private fun killBrowserProcess(): String {
        val manager = getSystemService(ActivityManager::class.java)
        val name = "$packageName:browser"
        val pid = manager.runningAppProcesses?.firstOrNull { it.processName == name }?.pid ?: return "not-running"
        Process.killProcess(pid)
        val deadline = SystemClock.elapsedRealtime() + 5_000
        while (SystemClock.elapsedRealtime() < deadline) {
            if (!File("/proc/$pid").exists()) return "pid $pid exited"
            SystemClock.sleep(50)
        }
        return "pid $pid STILL ALIVE"
    }

    /**
     * Deletes every directory carrying this generation's WebView suffix, plus
     * all shared preferences. WebView writes some state at the app level, not
     * under the suffix (A2 found `AwOriginVisitLoggerPrefs.xml`, a set of
     * visited-origin hashes with a date). The controller stores nothing in
     * SharedPreferences, so everything there is browser state: default-deny.
     */
    private fun deleteGeneration(generation: Int): String = buildString {
        val suffix = Generation.suffix(generation)
        val roots = listOf(dataDir, cacheDir, codeCacheDir)
        val targets = roots.flatMap { root ->
            root.walkTopDown().maxDepth(2).filter { it.isDirectory && it.name.endsWith("_$suffix") }.toList()
        }.distinct()
        targets.forEach { appendLine("deleted ${it.relativeTo(dataDir)} ok=${it.deleteRecursively()}") }
        val prefs = File(dataDir, "shared_prefs")
        prefs.listFiles()?.forEach { appendLine("deleted ${it.relativeTo(dataDir)} ok=${it.delete()}") }
        val leftovers = roots.flatMap { root ->
            root.walkTopDown().filter { it.path.contains("_$suffix") }.toList()
        } + (prefs.listFiles()?.toList() ?: emptyList())
        appendLine("verify.leftovers=${leftovers.size}")
    }

    // ---- A4–A7: isolated worker ---------------------------------------------

    private fun runWorkerTests() {
        val out = StringBuilder()
        val canary = File(filesDir, "canary-secret.txt").apply { writeText("vault-canary: never readable by a worker\n") }
        val pdfBytes = assets.open("sample.pdf").use { it.readBytes() }
        val pdfFile = File(filesDir, "sample.pdf").apply { writeBytes(pdfBytes) }

        val (worker, bindMs) = bindWorker() ?: run {
            Results.write(this, "worker", "bind=FAILED")
            return
        }
        out.appendLine("bind_ms=%.1f".format(bindMs))
        out.appendLine("controller.uid=${Process.myUid()}")
        out.append(worker.probe(canary.path, FIXTURE_PORT))

        // A4 with a regular file descriptor.
        ParcelFileDescriptor.open(pdfFile, ParcelFileDescriptor.MODE_READ_ONLY).use { pfd ->
            out.append(renderAndValidate(worker, pfd, "pdf_file"))
        }
        // A7: plaintext only in RAM — a sealed, read-only memfd.
        try {
            sealedMemfd(pdfBytes).use { pfd -> out.append(renderAndValidate(worker, pfd, "pdf_memfd")) }
        } catch (e: Exception) {
            out.appendLine("pdf_memfd.status=ERROR ${e.javaClass.simpleName}: ${e.message}")
        }

        // A5: YARA-X inside the worker, on a marker file and a 16 MiB file.
        val rules = """
            rule rift_demo_marker { strings: ${'$'}a = "RIFT-DEMO-MALWARE-MARKER" condition: ${'$'}a }
            rule rift_demo_hex { strings: ${'$'}h = { 52 49 46 54 ?? 44 45 4D 4F } condition: ${'$'}h }
        """.trimIndent()
        val marked = File(filesDir, "marked.bin").apply { writeText("prefix RIFT-DEMO-MALWARE-MARKER suffix") }
        val large = File(filesDir, "large.bin").apply {
            outputStream().use { stream -> val chunk = ByteArray(1 shl 20) { (it * 31).toByte() }; repeat(16) { stream.write(chunk) } }
        }
        for ((name, file) in listOf("yara_marker" to marked, "yara_16mib" to large)) {
            ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY).use { pfd ->
                worker.yaraScan(rules, pfd, WORKER_SCAN_TIMEOUT_MS).lineSequence().filter { it.isNotBlank() }.forEach { out.appendLine("$name.$it") }
            }
        }
        Results.write(this, "worker", out.toString())
    }

    // ---- Worker lifecycle: cold start, signals, deadlines ----------------------

    /**
     * Answers the questions Phase 0 left open about the isolated worker:
     * how long a fresh worker takes to start (with and without the app zygote),
     * whether the app can signal it, whether YARA-X's own timeout fires there,
     * and whether unbinding retires a worker stuck in a scan.
     */
    private fun runLifecycleTests(): String = buildString {
        val samples = 5
        for ((label, service) in listOf("system_zygote" to WorkerService::class.java, "app_zygote" to ZygoteWorkerService::class.java)) {
            val times = (1..samples).map { i ->
                val fresh = bindFresh(service, "${label}_$i") ?: return@map null
                val (bound, connectMs) = fresh
                val firstCall = SystemClock.elapsedRealtimeNanos()
                val pid = bound.worker.pid()
                val callMs = (SystemClock.elapsedRealtimeNanos() - firstCall) / 1_000_000.0
                if (i == 1) appendLine("$label.zygote_preload=${bound.worker.zygotePreload()}")
                appendLine("$label.sample$i connect_ms=%.1f first_call_ms=%.1f pid=$pid retired=${bound.retire()}".format(connectMs, callMs))
                connectMs
            }
            val ok = times.filterNotNull().sorted()
            appendLine("$label.connect_ms.median=" + (ok.getOrNull(ok.size / 2)?.let { "%.1f".format(it) } ?: "n/a") + " of ${ok.size}/$samples")
        }

        // Signals: the worker has another UID, so kill(2) should fail with EPERM.
        bindFresh(WorkerService::class.java, "signal")?.first?.let { bound ->
            val pid = bound.worker.pid()
            appendLine("signal.kill0=" + attempt { Os.kill(pid, 0); "delivered" })
            appendLine("signal.sigkill=" + attempt { Os.kill(pid, OsConstants.SIGKILL); "delivered" })
            Process.killProcess(pid) // reports nothing; checked through the binder below
            SystemClock.sleep(500)
            appendLine("signal.alive_after=${bound.binder.pingBinder()}")
            appendLine("signal.retired=${bound.retire()}")
        } ?: appendLine("signal=BIND_FAILED")

        val input = File(filesDir, "slow-input.bin").apply { writeBytes(ByteArray(256 * 1024)) }

        // YARA-X's own deadline inside the isolated process (Deadline::InProcess).
        bindFresh(WorkerService::class.java, "timeout")?.first?.let { bound ->
            val started = SystemClock.elapsedRealtime()
            val reply = ParcelFileDescriptor.open(input, ParcelFileDescriptor.MODE_READ_ONLY).use { bound.worker.yaraScan(SLOW_RULES, it, 2_000) }
            appendLine("timeout.reply=" + reply.lines().filter { it.isNotBlank() }.joinToString(" "))
            appendLine("timeout.wall_ms=${SystemClock.elapsedRealtime() - started}")
            appendLine("timeout.retired=${bound.retire()}")
        } ?: appendLine("timeout=BIND_FAILED")

        // A worker stuck in a scan with no deadline: does unbinding retire it?
        bindFresh(WorkerService::class.java, "stuck")?.first?.let { bound ->
            var callOutcome = "still running"
            val caller = thread {
                callOutcome = try {
                    ParcelFileDescriptor.open(input, ParcelFileDescriptor.MODE_READ_ONLY).use { bound.worker.yaraScan(SLOW_RULES, it, 0) }
                        .lines().first()
                } catch (e: Exception) {
                    e.javaClass.simpleName
                }
            }
            SystemClock.sleep(1_500)
            appendLine("stuck.alive_while_scanning=${bound.binder.pingBinder()}")
            appendLine("stuck.retired=${bound.retire(timeoutMs = 20_000)}")
            caller.join(5_000)
            appendLine("stuck.blocked_call=$callOutcome")
        } ?: appendLine("stuck=BIND_FAILED")
    }

    /** A bound worker in its own process, and how to unbind it and wait for that process to die. */
    private inner class BoundWorker(val worker: IWorker, val binder: IBinder, private val connection: ServiceConnection) {
        private val died = CountDownLatch(1)

        init {
            binder.linkToDeath({ died.countDown() }, 0)
        }

        /** Unbinds, then reports how long the process took to die, or that it did not. */
        fun retire(timeoutMs: Long = 10_000): String {
            val started = SystemClock.elapsedRealtime()
            unbindService(connection)
            return if (died.await(timeoutMs, TimeUnit.MILLISECONDS)) {
                "died_after_unbind_ms=${SystemClock.elapsedRealtime() - started}"
            } else {
                "STILL_ALIVE_after_${timeoutMs}ms"
            }
        }
    }

    /** Binds a new isolated process (a distinct instance name, `[A-Za-z0-9_.]`, never reuses one). */
    private fun bindFresh(serviceClass: Class<*>, instance: String): Pair<BoundWorker, Double>? {
        val latch = CountDownLatch(1)
        var bound: BoundWorker? = null
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                bound = BoundWorker(IWorker.Stub.asInterface(service), service, this)
                latch.countDown()
            }

            override fun onServiceDisconnected(name: ComponentName) = Unit
        }
        val started = SystemClock.elapsedRealtimeNanos()
        try {
            bindIsolatedService(Intent(this, serviceClass), BIND_AUTO_CREATE, instance, mainExecutor, connection)
        } catch (e: RuntimeException) {
            Log.e(TAG, "bind $instance failed", e)
            return null
        }
        if (!latch.await(10, TimeUnit.SECONDS)) return null
        val ms = (SystemClock.elapsedRealtimeNanos() - started) / 1_000_000.0
        return bound?.let { it to ms }
    }

    private fun bindWorker(): Pair<IWorker, Double>? {
        val latch = CountDownLatch(1)
        var worker: IWorker? = null
        val started = SystemClock.elapsedRealtimeNanos()
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                worker = IWorker.Stub.asInterface(service)
                latch.countDown()
            }

            override fun onServiceDisconnected(name: ComponentName) = Unit
        }
        bindService(Intent(this, WorkerService::class.java), connection, BIND_AUTO_CREATE)
        if (!latch.await(10, TimeUnit.SECONDS)) return null
        val ms = (SystemClock.elapsedRealtimeNanos() - started) / 1_000_000.0
        return worker?.let { it to ms }
    }

    private fun sealedMemfd(bytes: ByteArray): ParcelFileDescriptor {
        val mfdAllowSealing = 0x2
        val fdAddSeals = 1033
        val sealShrink = 0x2
        val sealGrow = 0x4
        val sealWrite = 0x8
        val fd: FileDescriptor = Os.memfd_create("rift-preview", mfdAllowSealing)
        try {
            var offset = 0
            while (offset < bytes.size) offset += Os.write(fd, bytes, offset, bytes.size - offset)
            Os.lseek(fd, 0, OsConstants.SEEK_SET)
            Os.fcntlInt(fd, fdAddSeals, sealShrink or sealGrow or sealWrite)
            return ParcelFileDescriptor.dup(fd)
        } finally {
            Os.close(fd)
        }
    }

    /** The controller validates every field of the worker's answer (INV-3). */
    private fun renderAndValidate(worker: IWorker, pdf: ParcelFileDescriptor, name: String): String = buildString {
        val maxW = 1024
        val maxH = 1024
        val shm = SharedMemory.create("rift-render", maxW * maxH * 4)
        try {
            val request = Bundle().apply {
                putParcelable("shm", shm)
                putInt("maxW", maxW)
                putInt("maxH", maxH)
            }
            val reply = worker.renderPdf(pdf, 0, request)
            reply.lineSequence().filter { it.isNotBlank() }.forEach { appendLine("$name.$it") }
            val fields = reply.lineSequence().mapNotNull { it.split('=', limit = 2).takeIf { p -> p.size == 2 } }
                .associate { it[0] to it[1] }
            val w = fields["width"]?.toIntOrNull()
            val h = fields["height"]?.toIntOrNull()
            if (fields["status"] != "OK" || w == null || h == null || w !in 1..maxW || h !in 1..maxH) {
                appendLine("$name.validation=REJECTED")
                return@buildString
            }
            val buffer = shm.mapReadOnly()
            try {
                val bitmap = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
                buffer.limit(w * h * 4)
                bitmap.copyPixelsFromBuffer(buffer)
                val pixels = IntArray(w * h).also { bitmap.getPixels(it, 0, w, 0, 0, w, h) }
                val inked = pixels.count { it != Color.WHITE }
                appendLine("$name.validation=OK inked_pixels=$inked of ${pixels.size}")
                Results.file(this@MainActivity, "$name.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
            } finally {
                SharedMemory.unmap(buffer)
            }
        } finally {
            shm.close()
        }
    }
}
