package org.simulationrift.app

import android.os.SystemClock
import org.simulationrift.bridge.Fact
import org.simulationrift.bridge.NavigationDecision
import org.simulationrift.bridge.PageWatch
import org.simulationrift.bridge.PageWatch.Level
import org.simulationrift.core.EgressStats
import org.simulationrift.core.ScanStatus
import org.simulationrift.core.Verdict
import org.simulationrift.core.displaySafe

/**
 * The live page watch of one session (§10.5). Every event comes from a
 * point where Rift enforces something: the core's navigation decisions, the
 * egress proxy's refusals, the network lock's drops, download captures and
 * scan verdicts, and the browser engine's permission callbacks (reported by
 * kind only, and validated here). Nothing a page says is read.
 *
 * One session's events stay together until the session ends: what one page
 * did can stay in the session (its storage, a service worker, a compromised
 * renderer), so the status is the session's, and only a reset clears it.
 * Bounded: repeats are counted, and when the list is full a new event
 * replaces the oldest of a lower level, or is counted as not listed.
 */
internal class PageWatcher(private val lockEpoch: Long) {
    private val events = LinkedHashMap<String, PageWatch.Event>()
    private var nextSeq = 1L
    private var unlisted = 0
    private var lastDenial = 0L
    private val lockSeen = HashSet<String>()

    @Synchronized
    fun record(level: Level, code: String, subject: String, text: String) {
        val key = "$code\u0000$subject"
        val now = SystemClock.elapsedRealtime()
        events[key]?.let { seen ->
            events[key] = seen.copy(count = (seen.count + 1).coerceAtMost(MAX_COUNT), lastSeen = now)
            return
        }
        if (events.size >= MAX_EVENTS) {
            val evicted = events.entries.firstOrNull { it.value.level > level }
            if (evicted == null) {
                unlisted++
                return
            }
            events.remove(evicted.key)
            unlisted++
        }
        events[key] = PageWatch.Event(nextSeq++, level, code, text, 1, now)
    }

    /** A main-frame decision by the core (§10.2–§10.4). */
    fun navigation(url: String, decision: NavigationDecision) {
        val host = hostOf(url)
        when (decision) {
            is NavigationDecision.Block -> when (decision.reason.code) {
                "known-malicious" -> record(Level.DANGER, "known-malicious-address", host,
                    "Blocked $host: the threat database lists this address as malicious.")
                "scheme-not-allowed" -> record(Level.WARNING, "app-link", decision.displayUrl.take(MAX_SUBJECT),
                    "A page tried to open another app. ${decision.reason.text}")
                // The rest are about the device or the session, not the page.
                else -> {}
            }
            is NavigationDecision.Confirm -> {
                decision.reasons.forEach { record(Level.WARNING, it.code, host, "$host: ${it.text}") }
                notes(host, decision.notes)
            }
            is NavigationDecision.Proceed -> notes(host, decision.notes)
        }
    }

    private fun notes(host: String, notes: List<Fact>) {
        // The database's own state is shown as coverage, not as page activity.
        notes.filterNot { it.code.startsWith("intel-") }.forEach { record(Level.NOTE, it.code, host, "$host: ${it.text}") }
    }

    /** Something the engine refused that only it sees; `kind` and `origin` come from the browser app. */
    fun attempt(kind: String, origin: String) {
        val host = hostOf(origin)
        when (kind) {
            PageWatch.Attempt.LOCATION -> record(Level.WARNING, kind, host,
                "$host asked for your location. Denied: the browser app has no location permission, and Rift answers no.")
            PageWatch.Attempt.CAMERA -> record(Level.WARNING, kind, host,
                "$host asked for the camera. Denied: the browser app has no camera permission, and Rift answers no.")
            PageWatch.Attempt.MICROPHONE -> record(Level.WARNING, kind, host,
                "$host asked for the microphone. Denied: the browser app has no microphone permission, and Rift answers no.")
            PageWatch.Attempt.MIDI -> record(Level.WARNING, kind, host, "$host asked for full access to MIDI devices. Denied.")
            PageWatch.Attempt.PROTECTED_MEDIA -> record(Level.NOTE, kind, host,
                "$host asked for a protected-media (DRM) identifier for this device. Denied.")
            PageWatch.Attempt.FILES -> record(Level.WARNING, kind, host,
                "$host asked you to choose a file to upload. Rift does not allow uploads, so no file was shared.")
            PageWatch.Attempt.FULLSCREEN -> record(Level.NOTE, kind, host,
                "$host asked for fullscreen, which would hide Rift's bar. Refused.")
        }
    }

    /** New refusals by this session's proxy (by sequence number, so each is seen once). */
    @Synchronized
    fun egress(stats: EgressStats?) {
        val recent = stats?.recent ?: return
        val fresh = recent.filter { it.seq.toLong() > lastDenial }
        if (fresh.isEmpty()) return
        if (fresh.first().seq.toLong() > lastDenial + 1) {
            record(Level.NOTE, "proxy-unlisted", "", "Rift's proxy refused more connections than it keeps a record of; the oldest are not listed.")
        }
        lastDenial = fresh.last().seq.toLong()
        for (denial in fresh) {
            when (denial.code) {
                "known-malicious" -> record(Level.DANGER, "known-malicious-request", denial.destination,
                    "Part of a page tried to load from ${denial.destination}, which the threat database lists as malicious. Rift's proxy refused it.")
                "local-address" -> record(Level.WARNING, "local-network", denial.destination,
                    "A page tried to reach ${denial.destination}, on your local network or this device. Rift's proxy refused it.")
                // Names that do not resolve and unreachable hosts are ordinary web failures.
                else -> {}
            }
        }
    }

    /** New destinations the network lock dropped in this session ([NetworkLock.newSession]). */
    @Synchronized
    fun lock(dropped: NetworkLock.Dropped) {
        if (dropped.epoch != lockEpoch) return
        for (destination in dropped.destinations) {
            if (!lockSeen.add(destination) || NetworkLock.isBackground(destination)) continue
            record(Level.WARNING, "direct-connection", destination,
                "Something in the browser tried to connect to $destination directly, around Rift's proxy " +
                    "(WebRTC does this, and it can reveal your addresses). The network lock dropped it.")
        }
    }

    fun downloaded(name: String) =
        record(Level.NOTE, "download", name, "A page started a download: $name. Rift fetched it into encrypted quarantine and is scanning it.")

    fun downloadRefused(url: String, why: String) =
        record(Level.NOTE, "download-refused", url.take(MAX_SUBJECT), "A download was not captured: $why.")

    fun verdict(name: String, verdict: Verdict) = when (verdict.status) {
        ScanStatus.KNOWN_MALICIOUS -> record(Level.DANGER, "file-known-malicious", name,
            "The download $name is known malicious. It stays in encrypted quarantine and is deleted with the session unless you keep it.")
        ScanStatus.SUSPICIOUS -> record(Level.WARNING, "file-suspicious", name,
            "The download $name is suspicious (${verdict.findings.size} findings). It stays in encrypted quarantine.")
        ScanStatus.NOT_FULLY_SCANNED -> record(Level.NOTE, "file-not-fully-scanned", name,
            "The download $name could not be fully scanned: ${verdict.gaps.joinToString(" ")}")
        ScanStatus.NOT_FLAGGED -> record(Level.NOTE, "file-not-flagged", name,
            "The download $name was not flagged by the checks that ran. That does not make it safe.")
    }

    @Synchronized
    fun snapshot(coverage: List<String>): PageWatch {
        val listed = events.values.sortedWith(compareBy<PageWatch.Event> { it.level }.thenByDescending { it.lastSeen })
        val extra = if (unlisted == 0) emptyList() else listOf(
            PageWatch.Event(0, Level.NOTE, "unlisted", "$unlisted more kinds of activity are not listed.", unlisted, SystemClock.elapsedRealtime()),
        )
        return PageWatch(listed + extra, coverage)
    }

    private fun hostOf(url: String): String =
        displaySafe(android.net.Uri.parse(url).host?.takeIf { it.isNotEmpty() } ?: "a page").take(MAX_SUBJECT)

    private companion object {
        const val MAX_EVENTS = 64
        const val MAX_COUNT = 9_999
        const val MAX_SUBJECT = 120
    }
}
