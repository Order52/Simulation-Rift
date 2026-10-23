package org.simulationrift.app

import android.content.Context
import android.util.Log
import java.io.File
import java.io.IOException
import java.util.concurrent.Executors
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import org.simulationrift.core.CleanFailure
import org.simulationrift.core.CleanedLink
import org.simulationrift.core.FilterFetchFailure
import org.simulationrift.core.LinkCleaner
import org.simulationrift.core.fetchFilterList

/**
 * Link cleaning (§10.10): the ClearURLs project's rules for tracking
 * parameters and redirect links, which Check applies to a link. Rift writes
 * none of them. Like the filter lists, they are downloaded when the user
 * asks, by the core's checked fetcher, and kept in Rift's files as a
 * setting, so a reset does not touch them.
 */
object LinkCleaning {

    /** Where the ClearURLs extension itself gets its rules. */
    const val SOURCE = "https://rules2.clearurls.xyz/data.minify.json"

    data class State(
        /** When Rift downloaded the rules; null if it has none. */
        val updated: Long? = null,
        val providers: Int = 0,
        val busy: Boolean = false,
        val message: String? = null,
    )

    private const val TAG = "RiftClean"
    private const val DIR = "rift/clean"
    private const val FILE = "clearurls.json"

    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state

    private val work = Executors.newSingleThreadExecutor { Thread(it, "rift-clean") }
    @Volatile private var cleaner: LinkCleaner? = null
    private lateinit var file: File

    /** From Core.ensureStarted (main thread): the rules are compiled on the worker. */
    fun init(context: Context) {
        file = File(File(context.filesDir, DIR).apply { mkdirs() }, FILE)
        work.execute {
            if (!file.isFile) return@execute
            try {
                use(LinkCleaner.load(file.readText()))
            } catch (e: CleanFailure) {
                Log.w(TAG, "the saved rules are unusable: ${e.message}")
            } catch (e: IOException) {
                Log.w(TAG, "the saved rules could not be read: ${e.message}")
            }
        }
    }

    /** Downloads the rules, and uses them once they compile. */
    fun download() {
        _state.update { it.copy(busy = true, message = null) }
        work.execute {
            val text = try {
                fetchFilterList(SOURCE)
            } catch (e: FilterFetchFailure) {
                Log.w(TAG, "download: ${e.message}")
                _state.update { it.copy(busy = false, message = "The rules could not be downloaded. Are you online?") }
                return@execute
            }
            install(text)
        }
    }

    /** On [work] (or a test's thread): compiles [text], keeps it and uses it; unusable rules leave the current ones. */
    internal fun install(text: String) {
        val message = try {
            val compiled = LinkCleaner.load(text)
            File(file.parentFile, "$FILE.tmp").apply { writeText(text) }.renameTo(file)
            use(compiled)
            "Rules updated."
        } catch (e: CleanFailure) {
            "The downloaded rules are unusable: ${e.message}"
        } catch (e: IOException) {
            "The rules could not be saved: ${e.message}"
        }
        _state.update { it.copy(busy = false, message = message) }
    }

    fun remove() {
        work.execute {
            file.delete()
            cleaner = null
            _state.value = State(message = "Rules removed.")
        }
    }

    /** [address] cleaned; null without rules. */
    fun clean(address: String): CleanedLink? = cleaner?.clean(address)

    private fun use(compiled: LinkCleaner) {
        cleaner = compiled
        if (compiled.skipped() > 0u) Log.i(TAG, "${compiled.skipped()} patterns left out")
        _state.update { it.copy(updated = file.lastModified(), providers = compiled.providers().toInt()) }
    }
}
