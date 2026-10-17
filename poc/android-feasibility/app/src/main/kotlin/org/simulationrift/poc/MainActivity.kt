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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val test = intent.getStringExtra("test")
        val label = intent.getStringExtra("label") ?: "default"
        when (test) {
            "worker" -> thread { runWorkerTests(); finish() }
            "browse" -> {
                startActivity(
                    Intent(this, BrowserActivity::class.java)
                        .putExtra("test", intent.getStringExtra("mode"))
                        .putExtra("label", intent.getStringExtra("label")),
                )
                finish()
            }
            "reset" -> thread { Results.write(this, "reset-$label", reset(crashBeforeDelete = false)); finish() }
            "reset-crash" -> thread { reset(crashBeforeDelete = true) }
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

    /** Deletes every directory carrying this generation's WebView suffix. */
    private fun deleteGeneration(generation: Int): String = buildString {
        val suffix = Generation.suffix(generation)
        val roots = listOf(dataDir, cacheDir, codeCacheDir)
        val targets = roots.flatMap { root ->
            root.walkTopDown().maxDepth(2).filter { it.isDirectory && it.name.endsWith("_$suffix") }.toList()
        }
        targets.forEach { appendLine("deleted ${it.relativeTo(dataDir)} ok=${it.deleteRecursively()}") }
        val leftovers = roots.flatMap { root ->
            root.walkTopDown().filter { it.path.contains("_$suffix") }.toList()
        }
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
                worker.yaraScan(rules, pfd).lineSequence().filter { it.isNotBlank() }.forEach { out.appendLine("$name.$it") }
            }
        }
        Results.write(this, "worker", out.toString())
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
                File(filesDir, "results/$name.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
            } finally {
                SharedMemory.unmap(buffer)
            }
        } finally {
            shm.close()
        }
    }
}
