package org.simulationrift.app

import android.content.Context
import android.util.Log
import java.io.File
import java.io.IOException
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import org.json.JSONException
import org.json.JSONObject
import org.simulationrift.bridge.PageHiding
import org.simulationrift.core.ContentFilters
import org.simulationrift.core.FilterFetchFailure
import org.simulationrift.core.fetchFilterList

/**
 * Content filters (§10.9): ad, tracker and annoyance lists taken from their
 * upstream projects (EasyList, uBlock Origin, Fanboy), matched by the Rust
 * core in this process. The browser app only asks whether to block a request
 * and what to hide. Rift writes no rules of its own; the user may add some.
 *
 * Lists are downloaded when the user asks (nothing is scheduled, §17), by
 * the core's checked fetcher, and kept in Rift's files with the user's
 * choices: they are settings, not browsing data, so a reset does not touch
 * them.
 */
object ContentFilter {

    class Source(val id: String, val title: String, val about: String, val url: String, val defaultOn: Boolean)

    /** The upstream lists on offer, most used first. */
    val catalog = listOf(
        Source("easylist", "EasyList", "Ads on most websites.", "https://easylist.to/easylist/easylist.txt", true),
        Source("easyprivacy", "EasyPrivacy", "Trackers and analytics.", "https://easylist.to/easylist/easyprivacy.txt", true),
        Source(
            "ubo-filters", "uBlock filters", "Ads, trackers and video ads, from uBlock Origin.",
            "https://ublockorigin.github.io/uAssetsCDN/filters/filters.min.txt", true,
        ),
        Source(
            "ubo-annoyances", "uBlock annoyances",
            "Cookie banners, pop-ups, overlays, newsletter nags and “Sign in with Google” prompts.",
            "https://ublockorigin.github.io/uAssetsCDN/filters/annoyances.min.txt", true,
        ),
        Source(
            "fanboy-social", "Fanboy social", "Like and share buttons, and Facebook and other social sign-in widgets.",
            "https://easylist.to/easylist/fanboy-social.txt", true,
        ),
        Source(
            "fanboy-cookie", "Cookie notices", "The EasyList cookie banner list.",
            "https://secure.fanboy.co.nz/fanboy-cookiemonster.txt", true,
        ),
        Source(
            "ubo-privacy", "uBlock privacy", "More trackers, and tracking links.",
            "https://ublockorigin.github.io/uAssetsCDN/filters/privacy.min.txt", true,
        ),
        Source(
            "ubo-badware", "Badware and scams", "Sites known for scams, fake downloads and malware.",
            "https://ublockorigin.github.io/uAssetsCDN/filters/badware.min.txt", true,
        ),
        Source(
            "ubo-unbreak", "Site fixes", "Lets through what the lists above break on some sites.",
            "https://ublockorigin.github.io/uAssetsCDN/filters/unbreak.min.txt", true,
        ),
        Source(
            "ubo-quickfixes", "Quick fixes", "Same-day fixes for new ads and broken sites.",
            "https://ublockorigin.github.io/uAssetsCDN/filters/quick-fixes.min.txt", true,
        ),
        Source(
            "fanboy-annoyance", "Fanboy annoyances", "Even more pop-ups and widgets. Can break some sites.",
            "https://secure.fanboy.co.nz/fanboy-annoyance.txt", false,
        ),
    )

    /** One list as the Filters tab shows it. */
    data class ListState(val on: Boolean, val downloaded: Boolean, val rules: Int, val updated: Long?)

    data class State(
        val enabled: Boolean = true,
        val lists: Map<String, ListState> = emptyMap(),
        val custom: String = "",
        /** Set while a download or a rebuild runs. */
        val busy: String? = null,
        val message: String? = null,
        /** The engine holds the lists now. */
        val ready: Boolean = false,
        /** Requests blocked since Rift started. */
        val blocked: Long = 0,
    )

    private const val TAG = "RiftFilters"
    private const val DIR = "rift/filters"
    private const val SETTINGS = "settings.json"
    private const val CUSTOM = "custom.txt"
    private const val MAX_CUSTOM_CHARS = 100_000
    private const val MAX_PAGE_NAMES = 1_500
    private const val MAX_NAME_CHARS = 100
    private const val MAX_URL_CHARS = 8_192

    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state

    private val work = Executors.newSingleThreadExecutor { Thread(it, "rift-filters") }
    private val blockedTotal = AtomicLong()

    /** Created on first use: it needs the native library, which Core has loaded by then. */
    private val engine by lazy { ContentFilters() }

    private lateinit var dir: File

    /** From Core.ensureStarted (main thread): reads the choices, then builds the engine off it. */
    fun init(context: Context) {
        dir = File(context.filesDir, DIR).apply { mkdirs() }
        _state.value = read()
        work.execute { rebuild() }
    }

    fun setEnabled(on: Boolean) {
        update { it.copy(enabled = on) }
        work.execute { rebuild() }
    }

    /** Turns one list on or off; turning one on that is not downloaded downloads it. */
    fun setList(id: String, on: Boolean) {
        val before = _state.value.lists[id] ?: return
        update { it.copy(lists = it.lists + (id to before.copy(on = on))) }
        if (on && !before.downloaded) download(listOf(id)) else work.execute { rebuild() }
    }

    fun setCustom(text: String) {
        val bounded = text.take(MAX_CUSTOM_CHARS)
        try {
            File(dir, CUSTOM).writeText(bounded)
        } catch (e: IOException) {
            _state.update { it.copy(message = "Your rules could not be saved: ${e.message}") }
            return
        }
        _state.update { it.copy(custom = bounded) }
        work.execute { rebuild() }
    }

    /** Downloads every list that is on (the ones that are not yet downloaded as well). */
    fun updateAll() = download(catalog.filter { _state.value.lists[it.id]?.on == true }.map { it.id })

    private fun download(ids: List<String>) {
        if (ids.isEmpty()) return
        _state.update { it.copy(busy = "Starting…", message = null) }
        work.execute {
            var failed = 0
            ids.forEachIndexed { i, id ->
                val source = catalog.firstOrNull { it.id == id } ?: return@forEachIndexed
                _state.update { it.copy(busy = "Downloading ${source.title} (${i + 1} of ${ids.size})") }
                try {
                    val text = fetchFilterList(source.url)
                    val file = File(dir, "$id.txt")
                    File(dir, "$id.tmp").apply { writeText(text) }.renameTo(file)
                } catch (e: FilterFetchFailure) {
                    failed++
                    Log.w(TAG, "${source.title}: ${e.message}")
                } catch (e: IOException) {
                    failed++
                    Log.w(TAG, "${source.title}: ${e.message}")
                }
            }
            _state.update { it.copy(lists = read().lists) }
            rebuild()
            _state.update {
                it.copy(
                    busy = null,
                    message = if (failed == 0) "Lists updated." else "$failed of ${ids.size} lists could not be downloaded. Are you online?",
                )
            }
        }
    }

    /** On [work]: compiles what is on, or nothing if filtering is off. */
    private fun rebuild() {
        val now = _state.value
        _state.update { it.copy(busy = it.busy ?: "Applying the lists…") }
        val texts = if (!now.enabled) {
            emptyList()
        } else {
            catalog.filter { now.lists[it.id]?.on == true }.mapNotNull { read(File(dir, "${it.id}.txt")) } +
                listOfNotNull(now.custom.takeIf { it.isNotBlank() })
        }
        try {
            engine.load(texts)
        } catch (e: Exception) {
            Log.e(TAG, "the filter engine could not load the lists", e)
            _state.update { it.copy(busy = null, ready = false, message = "The lists could not be loaded: ${e.message}") }
            return
        }
        _state.update { it.copy(busy = if (it.busy == "Applying the lists…") null else it.busy, ready = texts.isNotEmpty()) }
        Log.i(TAG, "filters ${if (texts.isEmpty()) "off" else "loaded: ${texts.size} lists"}")
    }

    // ---- Asked by the browser app (CoreService); never on the main thread ----

    /**
     * The engine is native code reading text from the network and the browser
     * app. A failure inside it (a Rust panic arrives as an exception) must not
     * end the controller, which holds the session: the filters then do
     * nothing for that call, and it is logged. Filtering only takes things
     * away from pages, so doing nothing never lets more through than Rift's
     * own checks allow.
     */
    private fun <T> guarded(what: String, otherwise: T, call: () -> T): T = try {
        call()
    } catch (e: Exception) {
        Log.e(TAG, "the filter engine failed in $what; the filters do nothing for this call", e)
        otherwise
    }

    fun active(): Boolean = guarded("active", false) { engine.isLoaded() }

    fun blocks(url: String, page: String, kind: String): Boolean {
        if (url.length > MAX_URL_CHARS || page.length > MAX_URL_CHARS) return false
        val blocked = guarded("blocks", false) { engine.blocks(url, page, kind.take(MAX_NAME_CHARS)) }
        if (blocked) {
            val total = blockedTotal.incrementAndGet()
            if (total % COUNT_PUBLISH_EVERY == 1L) _state.update { it.copy(blocked = total) }
        }
        return blocked
    }

    fun hiding(url: String): PageHiding {
        if (url.length > MAX_URL_CHARS) return PageHiding.NONE
        return guarded("hiding", PageHiding.NONE) {
            val found = engine.hiding(url)
            PageHiding(found.css, found.exceptions, found.genericHidden)
        }
    }

    fun generic(classes: List<String>, ids: List<String>, exceptions: List<String>): String {
        val bound = { names: List<String> -> names.asSequence().filter { it.length <= MAX_NAME_CHARS }.take(MAX_PAGE_NAMES).toList() }
        return guarded("generic", "") { engine.genericCss(bound(classes), bound(ids), bound(exceptions)) }
    }

    /** The count as the Filters tab shows it, without waiting for the next publish. */
    fun countNow() {
        _state.update { it.copy(blocked = blockedTotal.get()) }
    }

    // ---- Settings on disk ----

    private fun update(change: (State) -> State) {
        _state.update(change)
        save()
    }

    private fun save() {
        val now = _state.value
        val json = JSONObject().put("enabled", now.enabled).put("lists", JSONObject().also { o -> now.lists.forEach { (id, s) -> o.put(id, s.on) } })
        try {
            File(dir, SETTINGS).writeText(json.toString())
        } catch (e: IOException) {
            Log.e(TAG, "settings not saved", e)
        }
    }

    private fun read(): State {
        val saved = try {
            JSONObject(File(dir, SETTINGS).readText())
        } catch (e: IOException) {
            null
        } catch (e: JSONException) {
            null
        }
        val on = saved?.optJSONObject("lists")
        return State(
            enabled = saved?.optBoolean("enabled", true) ?: true,
            lists = catalog.associate { s ->
                val file = File(dir, "${s.id}.txt")
                s.id to ListState(
                    on = on?.optBoolean(s.id, s.defaultOn) ?: s.defaultOn,
                    downloaded = file.isFile,
                    rules = if (file.isFile) ruleCount(file) else 0,
                    updated = file.lastModified().takeIf { file.isFile },
                )
            },
            custom = read(File(dir, CUSTOM)).orEmpty(),
            blocked = blockedTotal.get(),
        )
    }

    private fun read(file: File): String? = try {
        file.takeIf { it.isFile }?.readText()
    } catch (e: IOException) {
        null
    }

    /** Lines that are rules: not empty, not comments, not section headers. */
    private fun ruleCount(file: File): Int = try {
        file.useLines { lines -> lines.count { it.isNotBlank() && !it.startsWith("!") && !it.startsWith("[") } }
    } catch (e: IOException) {
        0
    }

    private const val COUNT_PUBLISH_EVERY = 25L
}
