package org.simulationrift.app

import android.content.Context
import android.util.Log
import java.io.File
import java.io.IOException
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
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

    /** `walls`: one of the lists "Skip sign-ins and pop-ups" turns on and off together. */
    class Source(val id: String, val title: String, val about: String, val url: String, val defaultOn: Boolean, val walls: Boolean = false)

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
            "https://ublockorigin.github.io/uAssetsCDN/filters/annoyances.min.txt", true, walls = true,
        ),
        Source(
            "fanboy-social", "Fanboy social", "Like and share buttons, and Facebook and other social sign-in widgets.",
            "https://easylist.to/easylist/fanboy-social.txt", true, walls = true,
        ),
        Source(
            "adguard-popups", "AdGuard pop-ups", "Pop-ups, overlays and \u201Clog in to continue\u201D walls on Facebook, Instagram, X and others.",
            "https://filters.adtidy.org/extension/ublock/filters/19.txt", true, walls = true,
        ),
        Source(
            "adguard-social", "AdGuard social media", "Social buttons, widgets and sign-in prompts from Facebook, Instagram, X and more.",
            "https://filters.adtidy.org/extension/ublock/filters/4.txt", true, walls = true,
        ),
        Source(
            "no-login", "Browse without logging in", "\u201CLog in to read more\u201D walls, from Dandelion Sprout.",
            "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/BrowseWebsitesWithoutLoggingIn.txt", true, walls = true,
        ),
        Source(
            "no-login-ubo", "Browse without logging in (more)", "Its part for uBlock-style blockers: more sites, from Dandelion Sprout.",
            "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/uBO%20list%20extensions/BrowseWebsitesWithoutLoggingIn-uBOExtension.txt",
            true, walls = true,
        ),
        Source(
            "adguard-other", "AdGuard other annoyances", "Sign-up nags, blur and scroll locks, and other annoyances the lists above miss.",
            "https://filters.adtidy.org/extension/ublock/filters/21.txt", true, walls = true,
        ),
        Source(
            "adguard-appbanners", "AdGuard app banners", "\u201COpen in the app\u201D and \u201CGet the app\u201D banners.",
            "https://filters.adtidy.org/extension/ublock/filters/20.txt", true,
        ),
        Source(
            "adguard-widgets", "AdGuard widgets", "Chat boxes, floating buttons and other page widgets.",
            "https://filters.adtidy.org/extension/ublock/filters/22.txt", true,
        ),
        Source(
            "fanboy-antifacebook", "Anti-Facebook", "Facebook's own trackers and widgets on other sites.",
            "https://secure.fanboy.co.nz/fanboy-antifacebook.txt", true,
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
    data class ListState(
        val on: Boolean,
        val downloaded: Boolean,
        val rules: Int,
        /** When Rift downloaded it. */
        val updated: Long?,
        /** The list's own date or version, from its header: how fresh upstream's copy was. */
        val upstream: String? = null,
    )

    data class State(
        val enabled: Boolean = true,
        /** "Skip sign-ins and pop-ups": the [Source.walls] lists, and pages' dialog boxes dismissed unseen. */
        val skipWalls: Boolean = true,
        /** Lists downloaded once are downloaded again when [STALE_MS] old, while Rift runs. */
        val autoUpdate: Boolean = true,
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

    /** [State.busy] while the lists already downloaded are applied: switches stay usable meanwhile. */
    const val APPLYING = "Applying the lists…"

    private const val TAG = "RiftFilters"
    private const val DIR = "rift/filters"
    private const val SETTINGS = "settings.json"
    private const val CUSTOM = "custom.txt"
    private const val COUNTS = "counts.json"
    private const val ENGINE_FILE = "engine.bin"
    private const val ENGINE_KEY_FILE = "engine.key"
    private const val MAX_CUSTOM_CHARS = 100_000
    private const val MAX_PAGE_NAMES = 1_500
    private const val MAX_NAME_CHARS = 100
    private const val MAX_URL_CHARS = 8_192

    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state

    private val work = Executors.newSingleThreadExecutor { Thread(it, "rift-filters") }
    /** Only wakes [refreshIfStale] up; the work itself runs on [work]. */
    private val timer = Executors.newSingleThreadScheduledExecutor { Thread(it, "rift-filters-timer").apply { isDaemon = true } }
    private val blockedTotal = AtomicLong()
    /** A rebuild is waiting on [work]: changes made before it starts are all in it. */
    private val rebuildQueued = AtomicBoolean()

    /** Created on first use: it needs the native library, which Core has loaded by then. */
    private val engine by lazy { ContentFilters() }

    private lateinit var dir: File

    /** Rift's install time: a new install compiles the lists again, whatever format the engine keeps. */
    private var appVersion = 0L

    /** From Core.ensureStarted (main thread): returns at once; the choices are read and the engine loaded on the worker. */
    fun init(context: Context) {
        dir = File(context.filesDir, DIR).apply { mkdirs() }
        appVersion = context.packageManager.getPackageInfo(context.packageName, 0).lastUpdateTime
        // Reading the lists to count their rules takes a while: never on the main thread.
        work.execute {
            _state.value = read()
            rebuild()
        }
        timer.scheduleWithFixedDelay({ work.execute(::refreshIfStale) }, START_CHECK_MS, CHECK_MS, java.util.concurrent.TimeUnit.MILLISECONDS)
    }

    fun setEnabled(on: Boolean) {
        update { it.copy(enabled = on) }
        requestRebuild()
    }

    /** Turns every sign-in and pop-up list on or off at once, downloading those not yet downloaded. */
    fun setSkipWalls(on: Boolean) {
        val walls = catalog.filter { it.walls }.map { it.id }
        val missing = walls.filter { _state.value.lists[it]?.downloaded == false }
        update { now -> now.copy(skipWalls = on, lists = now.lists.mapValues { (id, list) -> if (id in walls) list.copy(on = on) else list }) }
        if (on && missing.isNotEmpty()) download(missing) else requestRebuild()
    }

    fun setAutoUpdate(on: Boolean) {
        update { it.copy(autoUpdate = on) }
        if (on) refreshIfStale()
    }

    /** Whether the browser dismisses pages' dialog boxes: with "Skip sign-ins and pop-ups" and the filters on. */
    fun quietDialogs(): Boolean = _state.value.let { it.enabled && it.skipWalls }

    /**
     * Downloads again the lists that are on and older than [STALE_MS] (upstream's own lists ask
     * for a few days), and those switched on but missing, once any list has been downloaded:
     * the first download is still the user's tap. Called at start and every [CHECK_MS].
     */
    private fun refreshIfStale() {
        val now = _state.value
        if (!now.autoUpdate) return
        // Check's link-cleaning rules follow the same switch, filters on or off.
        LinkCleaning.refreshIfStale(STALE_MS)
        ThreatLists.refreshIfStale(STALE_LISTS_MS)
        if (!now.enabled || now.busy != null && now.busy != APPLYING) return
        if (now.lists.values.none { it.downloaded }) return
        val due = catalog.filter { source ->
            val list = now.lists[source.id] ?: return@filter false
            list.on && (!list.downloaded || System.currentTimeMillis() - (list.updated ?: 0) > STALE_MS)
        }.map { it.id }
        if (due.isNotEmpty()) {
            Log.i(TAG, "updating ${due.size} lists by themselves")
            download(due)
        }
    }

    /** Turns one list on or off; turning one on that is not downloaded downloads it. */
    fun setList(id: String, on: Boolean) {
        val before = _state.value.lists[id] ?: return
        update { it.copy(lists = it.lists + (id to before.copy(on = on))) }
        if (on && !before.downloaded) download(listOf(id)) else requestRebuild()
    }

    fun setCustom(text: String) {
        val bounded = text.take(MAX_CUSTOM_CHARS)
        work.execute {
            try {
                File(dir, CUSTOM).writeText(bounded)
            } catch (e: IOException) {
                _state.update { it.copy(message = "Your rules could not be saved: ${e.message}") }
                return@execute
            }
            _state.update { it.copy(custom = bounded) }
            rebuild()
        }
    }

    /** Several switches flipped in a row cost one rebuild, not one each. */
    private fun requestRebuild() {
        if (rebuildQueued.compareAndSet(false, true)) {
            work.execute {
                rebuildQueued.set(false)
                rebuild()
            }
        }
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

    /**
     * On [work]: has the engine hold what is on, or nothing if filtering is off. Compiling the
     * lists takes seconds on a phone, so the compiled engine is kept in a file (`engine.bin`)
     * with a key made of Rift's version and each list's size and date, and loaded from it while
     * the key still matches; a damaged or foreign file is refused by the engine and the lists are
     * compiled again.
     */
    private fun rebuild() {
        val now = _state.value
        _state.update { it.copy(busy = it.busy ?: APPLYING) }
        val on = if (now.enabled) catalog.filter { now.lists[it.id]?.on == true && File(dir, "${it.id}.txt").isFile } else emptyList()
        val custom = now.custom.takeIf { now.enabled && it.isNotBlank() }
        val started = android.os.SystemClock.elapsedRealtime()
        val loaded = try {
            if (on.isEmpty() && custom == null) {
                engine.load(emptyList())
                false
            } else {
                val key = cacheKey(on, custom)
                val cache = File(dir, ENGINE_FILE)
                val keyFile = File(dir, ENGINE_KEY_FILE)
                if (read(keyFile) == key && engine.loadSaved(cache.path)) {
                    Log.i(TAG, "filters loaded from the saved engine in ${android.os.SystemClock.elapsedRealtime() - started} ms")
                } else {
                    keyFile.delete()
                    engine.load(on.mapNotNull { read(File(dir, "${it.id}.txt")) } + listOfNotNull(custom))
                    Log.i(TAG, "filters compiled: ${on.size} lists in ${android.os.SystemClock.elapsedRealtime() - started} ms")
                    if (engine.save(cache.path)) keyFile.writeText(key) else Log.w(TAG, "the compiled engine could not be saved")
                }
                true
            }
        } catch (e: Exception) {
            Log.e(TAG, "the filter engine could not load the lists", e)
            _state.update { it.copy(busy = null, ready = false, message = "The lists could not be loaded: ${e.message}") }
            return
        }
        _state.update { it.copy(busy = if (it.busy == APPLYING) null else it.busy, ready = loaded) }
        if (!loaded) Log.i(TAG, "filters off")
    }

    /** What the compiled engine was made from: Rift's own version, and each list's size and date, and the user's rules. */
    private fun cacheKey(on: List<Source>, custom: String?): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        digest.update("$appVersion".toByteArray())
        for (source in on) File(dir, "${source.id}.txt").let { digest.update("${source.id} ${it.length()} ${it.lastModified()}".toByteArray()) }
        digest.update((custom ?: "").toByteArray())
        return digest.digest().joinToString("") { "%02x".format(it) }
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

    /**
     * Whether the lists name [url]'s server itself as an ad or tracker server: a rule that blocks
     * it as a whole page, which host rules such as EasyPrivacy's `||tracker.example^` do. Not
     * counted as a block. Check uses it to tell the user before the link is opened.
     */
    fun listsAddress(url: String): Boolean {
        if (url.length > MAX_URL_CHARS) return false
        return guarded("listsAddress", false) { engine.isLoaded() && engine.blocks(url, "", "document") }
    }

    fun hiding(url: String): PageHiding {
        if (url.length > MAX_URL_CHARS) return PageHiding.NONE
        return guarded("hiding", PageHiding.NONE) {
            val found = engine.hiding(url)
            PageHiding(found.css, found.exceptions, found.genericHidden, found.actions)
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

    /** Changes the choices at once; they are written to disk on [work]. */
    private fun update(change: (State) -> State) {
        _state.update(change)
        work.execute { save() }
    }

    private fun save() {
        val now = _state.value
        val json = JSONObject().put("enabled", now.enabled).put("skipWalls", now.skipWalls).put("autoUpdate", now.autoUpdate).put("lists", JSONObject().also { o -> now.lists.forEach { (id, s) -> o.put(id, s.on) } })
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
            skipWalls = saved?.optBoolean("skipWalls", true) ?: true,
            autoUpdate = saved?.optBoolean("autoUpdate", true) ?: true,
            lists = catalog.associate { s ->
                val file = File(dir, "${s.id}.txt")
                s.id to ListState(
                    on = on?.optBoolean(s.id, s.defaultOn) ?: s.defaultOn,
                    downloaded = file.isFile,
                    rules = if (file.isFile) cachedRuleCount(s.id, file) else 0,
                    updated = file.lastModified().takeIf { file.isFile },
                    upstream = if (file.isFile) upstreamVersion(file) else null,
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

    /**
     * The rule count of a list, counted once per version of the file: the size is the key, kept in
     * `counts.json`, so starting Rift does not read ten megabytes to print a number.
     */
    private fun cachedRuleCount(id: String, file: File): Int {
        val known = try {
            JSONObject(read(File(dir, COUNTS)) ?: "{}")
        } catch (e: JSONException) {
            JSONObject()
        }
        known.optJSONArray(id)?.let { if (it.optLong(0) == file.length()) return it.optInt(1) }
        val count = ruleCount(file)
        try {
            known.put(id, org.json.JSONArray().put(file.length()).put(count))
            File(dir, COUNTS).writeText(known.toString())
        } catch (e: IOException) {
            Log.w(TAG, "rule counts not saved", e)
        }
        return count
    }

    /** A list states its own freshness in a comment near the top (`! Last modified:` or `! Version:`). */
    private fun upstreamVersion(file: File): String? = try {
        file.useLines { lines ->
            lines.take(40).mapNotNull { line ->
                UPSTREAM_DATE.find(line)?.groupValues?.get(1)?.trim()
            }.firstOrNull()?.take(40)
        }
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
    /** Upstream lists say "Expires: 3 days" to "7 days"; four is the middle. */
    private const val STALE_MS = 4L * 24 * 60 * 60 * 1000
    /** Threat lists change within hours; a day old is old enough to fetch again. */
    private const val STALE_LISTS_MS = 24L * 60 * 60 * 1000
    private const val START_CHECK_MS = 60_000L
    private const val CHECK_MS = 6L * 60 * 60 * 1000
    private val UPSTREAM_DATE = Regex("^!\\\\s*(?:Last modified|Version|TimeUpdated)\\\\s*:\\\\s*(.+)$", RegexOption.IGNORE_CASE)
}
