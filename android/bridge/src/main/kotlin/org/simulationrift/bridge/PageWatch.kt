package org.simulationrift.bridge

import android.os.Bundle

/**
 * What the current session's pages have tried, as Rift's enforcement points
 * saw it (§10.5): the core's navigation checks, its proxy, the network lock,
 * download scans, and the browser engine's own permission callbacks. Pages
 * cannot write to it: no script is injected and nothing a page says is read.
 * Plain Kotlin, so the browser can show it without the Rust library.
 */
data class PageWatch(val events: List<Event>, val coverage: List<String>) {

    /** Highest first, so a list sorted by level shows dangers on top. */
    enum class Level { DANGER, WARNING, NOTE }

    /**
     * One kind of activity, from one place. `text` is a sentence safe for
     * trusted UI; `count` is how often it was seen; `lastSeen` is
     * SystemClock.elapsedRealtime() (the same clock in every process).
     */
    data class Event(val seq: Long, val level: Level, val code: String, val text: String, val count: Int, val lastSeen: Long)

    /** The session's status: the highest level seen, or null if nothing was. */
    val level: Level? get() = events.minOfOrNull { it.level }

    fun toBundle(): Bundle = Bundle().apply {
        putLongArray(SEQ, events.map { it.seq }.toLongArray())
        putStringArrayList(LEVEL, ArrayList(events.map { it.level.name }))
        putStringArrayList(CODE, ArrayList(events.map { it.code }))
        putStringArrayList(TEXT, ArrayList(events.map { it.text }))
        putIntArray(COUNT, events.map { it.count }.toIntArray())
        putLongArray(LAST_SEEN, events.map { it.lastSeen }.toLongArray())
        putStringArrayList(COVERAGE, ArrayList(coverage))
    }

    /** What a page tried that only the browser engine sees, reported to the core by kind. */
    object Attempt {
        const val LOCATION = "location"
        const val CAMERA = "camera"
        const val MICROPHONE = "microphone"
        const val MIDI = "midi"
        const val PROTECTED_MEDIA = "protected-media"
        const val FILES = "files"
        const val FULLSCREEN = "fullscreen"

        val ALL = setOf(LOCATION, CAMERA, MICROPHONE, MIDI, PROTECTED_MEDIA, FILES, FULLSCREEN)
    }

    companion object {
        private const val SEQ = "seq"
        private const val LEVEL = "level"
        private const val CODE = "code"
        private const val TEXT = "text"
        private const val COUNT = "count"
        private const val LAST_SEEN = "lastSeen"
        private const val COVERAGE = "coverage"

        /** Null when the watch is unavailable or malformed: never shown as "nothing seen". */
        fun fromBundle(bundle: Bundle?): PageWatch? {
            bundle ?: return null
            val seq = bundle.getLongArray(SEQ) ?: return null
            val levels = bundle.getStringArrayList(LEVEL) ?: return null
            val codes = bundle.getStringArrayList(CODE) ?: return null
            val texts = bundle.getStringArrayList(TEXT) ?: return null
            val counts = bundle.getIntArray(COUNT) ?: return null
            val lastSeen = bundle.getLongArray(LAST_SEEN) ?: return null
            val coverage = bundle.getStringArrayList(COVERAGE) ?: return null
            val n = seq.size
            if (listOf(levels.size, codes.size, texts.size, counts.size, lastSeen.size).any { it != n }) return null
            val events = (0 until n).map { i ->
                val level = Level.entries.firstOrNull { it.name == levels[i] } ?: return null
                Event(seq[i], level, codes[i], texts[i], counts[i], lastSeen[i])
            }
            return PageWatch(events, coverage)
        }
    }
}
