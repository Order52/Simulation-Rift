package org.simulationrift.app

import android.content.Context
import android.util.Log
import java.io.File
import java.io.IOException
import java.util.concurrent.Executors
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import org.json.JSONException
import org.json.JSONObject
import org.simulationrift.core.FilterFetchFailure
import org.simulationrift.core.ThreatListText
import org.simulationrift.core.fetchThreatList
import org.simulationrift.core.ThreatLists as LoadedLists

/**
 * Threat lists for Check (§10.12): community lists of dangerous hosts, which
 * Check names when a link's host is on one. Rift writes none of them. Like
 * the filter lists, the first download is the user's tap, by the core's
 * checked fetcher; then they are downloaded again with the filters' "Keep the
 * lists up to date". Kept in Rift's files as a setting, so a reset leaves them.
 */
object ThreatLists {

    /**
     * [danger]: a host on it is called dangerous; otherwise it is a warning sign.
     * [kind]: what the list says a host on it is, after "lists this site as".
     */
    data class Source(
        val id: String, val name: String, val about: String, val url: String, val wildcard: Boolean, val danger: Boolean,
        val kind: String,
    )

    val catalog = listOf(
        Source(
            "hagezi-tif", "HaGeZi Threat Intelligence Feeds", "Malware, phishing, scam and crypto-mining hosts, updated several times a day (medium edition, GPL v3).",
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.medium-onlydomains.txt", wildcard = true, danger = true,
            kind = "malware, phishing or a scam",
        ),
        Source(
            "phishing-army", "Phishing Army", "Phishing hosts from PhishTank, OpenPhish, CERT.PL and others, updated every few hours.",
            "https://phishing.army/download/phishing-army-domains.txt", wildcard = false, danger = true,
            kind = "phishing",
        ),
        Source(
            "ubo-badware", "uBlock Origin badware", "Sites that push fake downloads, scareware and scams (GPL v3).",
            "https://ublockorigin.github.io/uAssets/filters/badware.min.txt", wildcard = true, danger = false,
            kind = "a site that pushes fake downloads, scareware or scams",
        ),
        Source(
            "stevenblack", "StevenBlack hosts", "Ad, tracker and malware hosts, the list URLCheck uses (MIT).",
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", wildcard = false, danger = false,
            kind = "an ad, tracker or malware host",
        ),
    )

    data class ListState(val on: Boolean = true, val updated: Long? = null, val hosts: Long = 0, val error: String? = null)

    data class State(
        val lists: Map<String, ListState> = emptyMap(),
        val busy: Boolean = false,
        val message: String? = null,
    ) {
        val downloaded: Boolean get() = lists.values.any { it.updated != null }
    }

    private const val TAG = "RiftLists"
    private const val DIR = "rift/lists"
    private const val SETTINGS = "settings.json"

    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state

    private val work = Executors.newSingleThreadExecutor { Thread(it, "rift-lists") }
    private lateinit var dir: File

    /** From Core.ensureStarted (main thread): the lists are read and loaded on the worker. */
    fun init(context: Context) {
        dir = File(context.filesDir, DIR).apply { mkdirs() }
        work.execute {
            _state.value = read()
            rebuild()
        }
    }

    fun source(id: String): Source? = catalog.firstOrNull { it.id == id }

    /** Downloads every list that is on (the first time, the user's tap). */
    fun download() {
        val ids = catalog.filter { _state.value.lists[it.id]?.on != false }.map { it.id }
        work.execute { fetch(ids) }
    }

    fun setList(id: String, on: Boolean) {
        work.execute {
            _state.update { it.copy(lists = it.lists + (id to (it.lists[id] ?: ListState()).copy(on = on))) }
            save()
            if (on && _state.value.lists[id]?.updated == null && _state.value.downloaded) fetch(listOf(id)) else rebuild()
        }
    }

    /** Installs [text] as list [id], as a download would (tests: no network). */
    internal fun install(id: String, text: String) {
        work.execute {
            File(dir, "$id.txt").writeText(text)
            rebuild()
        }
    }

    fun remove() {
        work.execute {
            catalog.forEach { File(dir, "${it.id}.txt").delete() }
            _state.update { s -> s.copy(lists = s.lists.mapValues { (_, l) -> ListState(on = l.on) }, message = "Lists removed.") }
            rebuild()
        }
    }

    /** With the filters' "Keep the lists up to date": downloads again those on and older than [staleMs], once any was downloaded. */
    fun refreshIfStale(staleMs: Long) {
        work.execute {
            val now = _state.value
            if (now.busy || !now.downloaded) return@execute
            val due = catalog.filter { source ->
                val list = now.lists[source.id] ?: ListState()
                list.on && System.currentTimeMillis() - (list.updated ?: 0) > staleMs
            }.map { it.id }
            if (due.isNotEmpty()) {
                Log.i(TAG, "updating ${due.size} lists by themselves")
                fetch(due)
            }
        }
    }

    /** On [work]. */
    private fun fetch(ids: List<String>) {
        _state.update { it.copy(busy = true, message = null) }
        val failed = mutableListOf<String>()
        for (id in ids) {
            val source = source(id) ?: continue
            try {
                val text = fetchThreatList(source.url)
                File(dir, "$id.txt.tmp").apply { writeText(text) }.renameTo(File(dir, "$id.txt"))
            } catch (e: FilterFetchFailure) {
                Log.w(TAG, "$id: ${e.message}")
                failed += source.name
            } catch (e: IOException) {
                Log.w(TAG, "$id not saved: ${e.message}")
                failed += source.name
            }
        }
        rebuild()
        _state.update {
            it.copy(busy = false, message = if (failed.isEmpty()) "Lists updated." else "Not downloaded: ${failed.joinToString(", ")}. Are you online?")
        }
    }

    /** On [work]: loads the lists that are on and downloaded, and hands them to Check. */
    private fun rebuild() {
        val now = _state.value
        val texts = catalog.mapNotNull { source ->
            val file = File(dir, "${source.id}.txt")
            if (now.lists[source.id]?.on == false || !file.isFile) return@mapNotNull null
            try {
                ThreatListText(source.id, file.readText(), source.wildcard)
            } catch (e: IOException) {
                Log.w(TAG, "${source.id} unreadable: ${e.message}")
                null
            }
        }
        val loaded = LoadedLists.load(texts)
        Core.useThreatLists(if (texts.isEmpty()) null else loaded)
        val results = loaded.loaded().associateBy { it.id }
        _state.update { s ->
            s.copy(lists = catalog.associate { source ->
                val file = File(dir, "${source.id}.txt")
                val result = results[source.id]
                source.id to (s.lists[source.id] ?: ListState()).copy(
                    updated = file.takeIf { it.isFile }?.lastModified(),
                    hosts = result?.hosts?.toLong() ?: 0,
                    error = result?.error,
                )
            })
        }
        Log.i(TAG, "threat lists: ${results.values.joinToString { "${it.id} ${it.hosts}" }}")
    }

    private fun save() {
        val json = JSONObject().put("lists", JSONObject().also { o -> _state.value.lists.forEach { (id, s) -> o.put(id, s.on) } })
        try {
            File(dir, SETTINGS).writeText(json.toString())
        } catch (e: IOException) {
            Log.e(TAG, "settings not saved", e)
        }
    }

    private fun read(): State {
        val saved = try {
            JSONObject(File(dir, SETTINGS).readText()).optJSONObject("lists")
        } catch (e: IOException) {
            null
        } catch (e: JSONException) {
            null
        }
        return State(lists = catalog.associate { it.id to ListState(on = saved?.optBoolean(it.id, true) ?: true) })
    }
}
