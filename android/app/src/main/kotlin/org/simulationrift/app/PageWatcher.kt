package org.simulationrift.app

import android.os.SystemClock
import org.simulationrift.bridge.Fact
import org.simulationrift.bridge.NavigationDecision
import org.simulationrift.bridge.PageWatch
import org.simulationrift.bridge.PageWatch.Level
import org.simulationrift.core.AppLinkRisk
import org.simulationrift.core.EgressStats
import org.simulationrift.core.PageFact
import org.simulationrift.core.ScanStatus
import org.simulationrift.core.Verdict
import org.simulationrift.core.displaySafe
import org.simulationrift.core.explainAppLink
import org.simulationrift.core.trackerFor

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
 *
 * `tally` hears of each event the first time it is seen in the session,
 * listed or not, for the weekly summary ([WeeklyStats]).
 */
internal class PageWatcher(private val lockEpoch: Long, private val tally: (Tally) -> Unit = {}) {
    private val events = LinkedHashMap<String, PageWatch.Event>()
    private var nextSeq = 1L
    private var unlisted = 0
    private var lastDenial = 0L
    private var lastRemark = 0L
    private val lockSeen = HashSet<String>()
    private val trackersSeen = HashSet<String>()

    /**
     * `counted` is what the weekly summary counts the event as: by default
     * nothing for a note, a flagged file for a file, and anything else at
     * warning or danger is something Rift stopped.
     */
    @Synchronized
    fun record(level: Level, code: String, subject: String, text: String, counted: Tally? = defaultTally(level, code)) {
        val key = "$code\u0000$subject"
        val now = SystemClock.elapsedRealtime()
        events[key]?.let { seen ->
            events[key] = seen.copy(count = (seen.count + 1).coerceAtMost(MAX_COUNT), lastSeen = now)
            return
        }
        counted?.let(tally)
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
                "scheme-not-allowed" -> {
                    // Which app, and what the link asked it to do (§10.15).
                    val link = explainAppLink(url)
                    val level = if (link?.risk == AppLinkRisk.DANGER) Level.DANGER else Level.WARNING
                    val what = link?.let { " ${it.does}" + it.details.joinToString("") { d -> " $d" } }.orEmpty()
                    record(level, "app-link", decision.displayUrl.take(MAX_SUBJECT),
                        "A page tried to open ${link?.app ?: "another app"}.$what ${decision.reason.text}")
                }
                // The rest are about the device or the session, not the page.
                else -> {}
            }
            is NavigationDecision.Confirm -> {
                // A warning the user may click through, not something stopped.
                decision.reasons.forEach { record(Level.WARNING, it.code, host, "$host: ${it.text}", Tally.WARNED) }
                notes(host, decision.notes)
            }
            is NavigationDecision.Proceed -> if (decision.notes.any { it.code == NavigationDecision.OPENED_LISTED }) {
                record(Level.DANGER, "opened-known-malicious", host,
                    "You opened $host, which the threat database lists as malicious. Its page runs in this sealed session only.")
            } else {
                notes(host, decision.notes)
            }
        }
    }

    private fun notes(host: String, notes: List<Fact>) {
        // The database's own state is shown as coverage, not as page activity.
        notes.filterNot { it.code.startsWith("intel-") }.forEach { record(Level.NOTE, it.code, host, "$host: ${it.text}") }
    }

    /** Whether this session's pages get decoys (null until the browser says). */
    @Volatile private var decoys: Boolean? = null

    /** Something the engine refused that only it sees; `kind` and `origin` come from the browser app. */
    fun attempt(kind: String, origin: String) {
        val host = hostOf(origin)
        // With decoys in place the engine is only asked by a page that got past them.
        val how = if (decoys == true) "asked the browser engine directly, past Rift's decoys, for" else "asked for"
        when (kind) {
            PageWatch.Attempt.LOCATION -> record(Level.WARNING, kind, host,
                "$host $how your location. Denied: the browser app has no location permission, and Rift answers no.")
            PageWatch.Attempt.CAMERA -> record(Level.WARNING, kind, host,
                "$host $how the camera. Denied: the browser app has no camera permission, and Rift answers no.")
            PageWatch.Attempt.MICROPHONE -> record(Level.WARNING, kind, host,
                "$host $how the microphone. Denied: the browser app has no microphone permission, and Rift answers no.")
            PageWatch.Attempt.MIDI -> record(Level.WARNING, kind, host, "$host asked for full access to MIDI devices. Denied.")
            PageWatch.Attempt.PROTECTED_MEDIA -> record(Level.NOTE, kind, host,
                "$host asked for a protected-media (DRM) identifier for this device. Denied.")
            PageWatch.Attempt.FILES -> record(Level.WARNING, kind, host,
                "$host asked you to choose a file to upload. Rift does not allow uploads, so no file was shared.")
            PageWatch.Attempt.FULLSCREEN -> record(Level.NOTE, kind, host,
                "$host asked for fullscreen, which would hide Rift's bar. Refused.")
            PageWatch.Attempt.DOWNLOAD -> record(Level.WARNING, kind, host,
                "$host started a download by itself during the test-open. It was not fetched.")
            PageWatch.Attempt.DIALOG -> record(Level.NOTE, kind, host,
                "$host tried to show a dialog box (an alert, a question, or \u201cLeave this page?\u201d). Rift dismissed it unseen.")
        }
    }

    /**
     * A page was given a decoy (§10.5). `kind` was checked against
     * [PageWatch.Decoy] by the core; `detail` is the page's own text, so it
     * is made safe to show and quoted, never trusted.
     */
    fun decoy(kind: String, origin: String, detail: String) {
        val host = hostOf(origin)
        val said = displaySafe(detail).take(MAX_QUOTE)
        val quoted = if (said.isBlank()) "" else " (\u201c$said${if (detail.length > MAX_QUOTE) "\u2026" else ""}\u201d)"
        when (kind) {
            PageWatch.Decoy.ACTIVE -> decoys = true
            PageWatch.Decoy.UNAVAILABLE -> decoys = false
            PageWatch.Decoy.CAMERA -> record(Level.WARNING, kind, host,
                "$host turned on the camera. Rift gave it a made-up video; your camera was not used.")
            PageWatch.Decoy.MICROPHONE -> record(Level.WARNING, kind, host,
                "$host turned on the microphone. Rift gave it made-up silence; your microphone was not used.")
            PageWatch.Decoy.SCREEN -> record(Level.WARNING, kind, host,
                "$host asked to record your screen. Rift gave it a made-up video.")
            PageWatch.Decoy.DEVICES -> record(Level.NOTE, kind, host,
                "$host listed this device's cameras and microphones. Rift listed made-up ones.")
            PageWatch.Decoy.LOCATION -> record(Level.WARNING, kind, host,
                "$host asked where you are. Rift gave it a made-up location; your real location was not used.")
            PageWatch.Decoy.PERMISSION_CHECK -> PERMISSION_NAMES[detail]?.let { name ->
                record(Level.NOTE, kind, "$host $detail", "$host checked whether it may use $name. Rift told it yes, for the decoy.")
            }
            PageWatch.Decoy.NOTIFICATION -> record(Level.NOTE, kind, host,
                "$host tried to send you notifications$quoted. Rift told it yes and showed nothing.")
            PageWatch.Decoy.CLIPBOARD_READ -> record(Level.WARNING, kind, host,
                "$host tried to read your clipboard. Rift gave it nothing.")
            PageWatch.Decoy.CLIPBOARD_WRITE -> record(Level.WARNING, kind, host,
                "$host tried to put text on your clipboard$quoted. Rift told it that worked and left your clipboard unchanged.")
            PageWatch.Decoy.MOTION -> record(Level.NOTE, kind, host,
                "$host read the motion sensors. Rift gave it a phone lying still; the real sensors' readings never reached it.")
            PageWatch.Decoy.BATTERY -> record(Level.NOTE, kind, host,
                "$host read the battery level. Rift gave it a made-up one.")
            PageWatch.Decoy.VIBRATE -> record(Level.NOTE, kind, host,
                "$host tried to vibrate the phone. Nothing happened.")
            PageWatch.Decoy.FILES -> record(Level.WARNING, kind, host,
                "$host asked you to choose a file$quoted. Rift gave it a made-up file; none of your files was shared.")
        }
    }

    /** What the decoys cover, for the watch's coverage list. */
    private fun decoyCoverage(): String? = when (decoys) {
        true -> "Decoys: a page that asks for the camera, microphone, screen, location, files, notifications, clipboard, " +
            "motion sensors or battery gets something made up, and is listed here. Nothing real is given. " +
            "A page can tell it is a decoy if it looks closely, and can add made-up decoy reports about itself."
        false -> "Decoys are not available with this device's browser engine: those requests are refused instead."
        null -> null
    }

    /** New refusals by this session's proxy (by sequence number, so each is seen once). */
    @Synchronized
    fun egress(stats: EgressStats?) {
        stats ?: return
        // Rift AI's remarks on connections let through (§16: noted, not refused).
        for (remark in stats.remarks.filter { it.seq.toLong() > lastRemark }) {
            record(Level.WARNING, "ai-request", remark.destination, "Part of a page connected to ${remark.destination}. ${remark.text}", Tally.WARNED)
            lastRemark = remark.seq.toLong()
        }
        // Trackers the proxy let through: the core's own record, not the page's (§10.14).
        for (destination in stats.contacted) {
            val host = destination.substringBeforeLast(':').removePrefix("[").removeSuffix("]")
            if (!trackersSeen.add(host)) continue
            val tracker = trackerFor(host, "") ?: continue
            val stop = if (ContentFilter.active()) "Your content filter lists did not block it; add EasyPrivacy in the Filters tab."
                else "To block it, turn on content filters with EasyPrivacy in the Filters tab."
            record(Level.NOTE, "tracker", tracker.name,
                "${tracker.name} (${tracker.kind.lowercase()}, ${tracker.company}) is tracking visitors of this page. ${tracker.explanation} $stop")
        }
        val recent = stats.recent
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
                // An address padded past what can be checked is how a listed path would be hidden.
                "not-checked" -> record(Level.WARNING, "unchecked-request", denial.destination,
                    "Part of a page asked ${denial.destination} for an address too long to check against the threat database. Rift's proxy refused it.")
                // Names that do not resolve and unreachable hosts are ordinary web failures.
                else -> {}
            }
        }
    }

    /** A request the content filters blocked; named if it is a tracker Rift knows. */
    fun filtered(url: String) {
        val uri = android.net.Uri.parse(url)
        val tracker = trackerFor(uri.host ?: return, uri.path ?: "") ?: return
        record(Level.NOTE, "tracker-blocked", tracker.name,
            "Rift's content filters blocked ${tracker.name} (${tracker.kind.lowercase()}, ${tracker.company}). ${tracker.explanation}")
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

    /** What a page asks for and calls itself (Navigator.assessPage); the texts are the core's. */
    fun page(url: String, facts: List<PageFact>) {
        val host = hostOf(url)
        facts.forEach { record(if (it.warn) Level.WARNING else Level.NOTE, it.code, host, it.text, if (it.warn) Tally.WARNED else null) }
    }

    fun downloaded(name: String) =
        record(Level.NOTE, "download", name, "A page started a download: $name. Rift fetched it into encrypted quarantine and is scanning it.")

    fun downloadRefused(url: String, why: String) =
        record(Level.NOTE, "download-refused", url.take(MAX_SUBJECT), "A download was not captured: $why.")

    fun verdict(name: String, verdict: Verdict) = when (verdict.status) {
        ScanStatus.KNOWN_MALICIOUS -> record(Level.DANGER, "file-known-malicious", name,
            "The download $name is known malicious. It stays in encrypted quarantine and is deleted with the session.")
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
        return PageWatch(listed + extra, coverage + listOfNotNull(decoyCoverage()))
    }

    private fun defaultTally(level: Level, code: String): Tally? = when {
        level == Level.NOTE -> null
        code.startsWith("file-") -> Tally.FLAGGED_FILE
        else -> Tally.BLOCKED
    }

    private fun hostOf(url: String): String =
        displaySafe(android.net.Uri.parse(url).host?.takeIf { it.isNotEmpty() } ?: "a page").take(MAX_SUBJECT)

    private companion object {
        const val MAX_EVENTS = 64
        const val MAX_COUNT = 9_999
        const val MAX_SUBJECT = 120
        const val MAX_QUOTE = 60

        /** The permissions decoys.js answers for, as the watch names them. */
        val PERMISSION_NAMES = mapOf(
            "camera" to "the camera", "microphone" to "the microphone", "geolocation" to "your location",
            "notifications" to "notifications", "push" to "push notifications", "clipboard-read" to "your clipboard",
            "clipboard-write" to "your clipboard", "accelerometer" to "the motion sensors", "gyroscope" to "the motion sensors",
            "magnetometer" to "the compass",
        )
    }
}
