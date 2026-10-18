package org.simulationrift.app

import android.app.Service
import android.content.Context
import org.simulationrift.core.IntelFailure
import org.simulationrift.core.PendingIntel
import org.simulationrift.core.ScanFailure
import org.simulationrift.core.ScanJob
import org.simulationrift.core.Verdict

/**
 * The controller's side of a scan (§12.1, main process): one fresh isolated
 * worker per file, with the same checks as a preview (isolation before
 * binding, seccomp before input, a deadline on every call). The worker
 * compiles the database's rules, then scans a sealed memfd. rift-ffi
 * validates each reply and decides the status; a worker that fails only
 * removes rule coverage, which the verdict then names.
 */
object Scanner {
    private const val HELLO_TIMEOUT_MS = 2_000L
    private const val LOAD_TIMEOUT_MS = 10_000L
    /** The worker's own deadline is 15 s (rift-ffi SCAN_DEADLINE_MS); this is the backstop. */
    private const val SCAN_TIMEOUT_MS = 17_000L

    /** Scans with `job` in a fresh instance of `service`. Blocks: call it off the UI thread. */
    fun scan(context: Context, job: ScanJob, service: Class<out Service> = PreviewService::class.java): Verdict = try {
        val worker = IsolatedWorker.bind(context, service)
        try {
            val binder = worker.connected()
            job.acceptHello(worker.call("start", HELLO_TIMEOUT_MS) { binder.hello(job.helloFrame()) })
            val loaded = IsolatedWorker.sealedMemfd(job.rules()).use { rules ->
                worker.call("load the rules", LOAD_TIMEOUT_MS) { binder.call(job.loadFrame(), rules) }
            }
            job.acceptLoad(loaded)
            val reply = IsolatedWorker.sealedMemfd(job.input()).use { input ->
                worker.call("scan", SCAN_TIMEOUT_MS) { binder.call(job.scanFrame(), input) }
            }
            job.finish(reply)
        } finally {
            worker.retire()
        }
    } catch (e: IsolatedWorker.Failed) {
        job.failed(e.message ?: "the scan worker failed")
    } catch (e: ScanFailure.Unconfined) {
        job.failed("the scan worker is not confined (${e.detail})")
    } catch (e: ScanFailure.BadReply) {
        job.failed("the scan worker sent an invalid reply (${e.detail}) and was stopped")
    }

    /**
     * The install check (§13.2): a fresh worker must compile exactly the rules
     * the verified update describes. Throws [IsolatedWorker.Failed] or
     * rift-ffi's IntelFailure; on success `pending` may be installed.
     */
    fun check(context: Context, pending: PendingIntel, service: Class<out Service> = PreviewService::class.java) {
        val worker = IsolatedWorker.bind(context, service)
        try {
            val binder = worker.connected()
            pending.acceptHello(worker.call("start", HELLO_TIMEOUT_MS) { binder.hello(pending.helloFrame()) })
            val loaded = IsolatedWorker.sealedMemfd(pending.rules()).use { rules ->
                worker.call("load the rules", LOAD_TIMEOUT_MS) { binder.call(pending.loadFrame(), rules) }
            }
            pending.acceptLoad(loaded)
        } finally {
            worker.retire()
        }
    }

    fun describe(e: IntelFailure): String = when (e) {
        is IntelFailure.Storage -> "the threat database storage failed: ${e.detail}"
        is IntelFailure.Refused -> "the update was refused: ${e.detail}"
        is IntelFailure.Unconfined -> "the checking worker is not confined (${e.detail})"
        is IntelFailure.BadReply -> "the checking worker sent an invalid reply (${e.detail})"
        is IntelFailure.NotChecked -> "the update has not passed its rule check"
        is IntelFailure.Poisoned -> "threat database state is unusable after an internal error"
    }
}
