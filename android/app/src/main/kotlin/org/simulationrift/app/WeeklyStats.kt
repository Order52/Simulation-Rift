package org.simulationrift.app

import android.content.Context
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.time.LocalDate
import java.util.TreeMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** What the weekly summary counts. The order is the file's column order: only append. */
enum class Tally {
    /** Something Rift stopped: a listed address or request, an app link, a local-network request, a direct connection, a permission. */
    BLOCKED,

    /** An address Rift warned about before loading (a lookalike, a shortener, …). */
    WARNED,

    /** A download found known malicious or suspicious. */
    FLAGGED_FILE,

    /** A main-frame address the core decided on. */
    LINK_CHECKED,

    /** A download scanned to a verdict. */
    FILE_SCANNED,
}

/** One local day's counts. */
data class DayCounts(val epochDay: Long, private val counts: IntArray) {
    operator fun get(tally: Tally): Int = counts.getOrElse(tally.ordinal) { 0 }
    override fun equals(other: Any?) = other is DayCounts && other.epochDay == epochDay && other.counts.contentEquals(counts)
    override fun hashCode() = 31 * epochDay.hashCode() + counts.contentHashCode()
}

/** The last seven days, oldest first, ending today. */
data class Week(val days: List<DayCounts>) {
    fun total(tally: Tally): Int = days.fold(0) { sum, day -> saturated(sum.toLong() + day[tally]) }
}

/**
 * Per-day counts and their file format: a header line, then one line per
 * day, "<epoch day> <count per Tally, in order>". Only days in the window
 * [today - KEPT_DAYS + 1, today] are kept, so a clock set back for a
 * while drops the days it puts in the future.
 */
class Tallies {
    private val days = TreeMap<Long, IntArray>()

    @Synchronized
    fun add(today: Long, tally: Tally) {
        val counts = days.getOrPut(today) { IntArray(Tally.entries.size) }
        counts[tally.ordinal] = saturated(counts[tally.ordinal].toLong() + 1)
        prune(today)
    }

    /** Adds `other`'s counts to these (a file read after counting began). */
    @Synchronized
    fun merge(other: Tallies, today: Long) {
        for ((day, theirs) in other.snapshot()) {
            val ours = days.getOrPut(day) { IntArray(Tally.entries.size) }
            for (i in ours.indices) ours[i] = saturated(ours[i].toLong() + theirs[i])
        }
        prune(today)
    }

    @Synchronized
    fun week(today: Long): Week = Week((today - 6..today).map { DayCounts(it, days[it]?.copyOf() ?: IntArray(Tally.entries.size)) })

    @Synchronized
    fun serialize(): String = buildString {
        append(HEADER).append('\n')
        for ((day, counts) in days) append(day).append(' ').append(counts.joinToString(" ")).append('\n')
    }

    @Synchronized
    private fun snapshot(): Map<Long, IntArray> = days.mapValues { it.value.copyOf() }

    private fun prune(today: Long) {
        days.keys.removeAll { it > today || it <= today - KEPT_DAYS }
    }

    companion object {
        const val HEADER = "rift-stats 1"
        const val KEPT_DAYS = 14

        /**
         * Reads `text`, written by [serialize]. Lines that do not parse are
         * skipped and counted; a missing column (a file from before a
         * [Tally] was added) is zero, and an extra one is ignored.
         */
        fun parse(text: String, today: Long): Pair<Tallies, Int> {
            val tallies = Tallies()
            var bad = 0
            val lines = text.lines().filter { it.isNotBlank() }
            if (lines.firstOrNull() != HEADER) return tallies to lines.size
            for (line in lines.drop(1)) {
                val fields = line.split(' ').map { it.toLongOrNull() }
                val day = fields.firstOrNull()
                if (day == null || fields.size < 2 || fields.any { it == null || it < 0 }) {
                    bad++
                    continue
                }
                val counts = IntArray(Tally.entries.size) { i -> fields.getOrNull(i + 1)?.let(::saturated) ?: 0 }
                tallies.days[day] = counts
            }
            tallies.prune(today)
            return tallies to bad
        }
    }
}

private fun saturated(n: Long): Int = n.coerceIn(0, Int.MAX_VALUE.toLong()).toInt()

/**
 * The home screen's summary of the last seven days: how much Rift checked,
 * warned about and stopped. Kept in files/rift/stats, Rift's own state (on
 * the browser disposal's allowlist), and only as counts per local day: no
 * addresses, names, hosts or times of day.
 *
 * The live watch counts each kind of event once per session and subject
 * (the same address blocked twice in one session is one), so these are
 * distinct events, not requests.
 */
object WeeklyStats {
    private val tallies = Tallies()
    private val _week = MutableStateFlow(tallies.week(today()))
    val week: StateFlow<Week> = _week

    // Writes, one at a time and coalesced: a burst of events is one write.
    private val writer = Executors.newSingleThreadExecutor { Thread(it, "rift-stats") }
    private val pending = AtomicBoolean(false)
    @Volatile private var file: File? = null

    fun open(app: Context) {
        val stats = File(app.filesDir, "rift/stats")
        writer.execute {
            if (stats.exists()) {
                try {
                    val (read, bad) = Tallies.parse(stats.readText(), today())
                    if (bad > 0) Log.w(TAG, "weekly stats: $bad unreadable lines skipped")
                    tallies.merge(read, today())
                } catch (e: IOException) {
                    Log.e(TAG, "weekly stats unreadable; counting from zero", e)
                }
            }
            file = stats
            refresh()
            save()
        }
    }

    fun count(tally: Tally) {
        tallies.add(today(), tally)
        refresh()
        save()
    }

    /** Moves the window to today (the date may have changed since the last count). */
    fun refresh() {
        _week.value = tallies.week(today())
    }

    private fun save() {
        val target = file ?: return
        if (!pending.compareAndSet(false, true)) return
        writer.execute {
            pending.set(false)
            val temp = File(target.path + ".tmp")
            try {
                target.parentFile?.mkdirs()
                FileOutputStream(temp).use { out ->
                    out.write(tallies.serialize().toByteArray())
                    out.fd.sync()
                }
                if (!temp.renameTo(target)) throw IOException("rename to ${target.name} failed")
            } catch (e: IOException) {
                Log.e(TAG, "weekly stats not saved", e)
                temp.delete()
            }
        }
    }

    private fun today(): Long = LocalDate.now().toEpochDay()
}
