package org.simulationrift.poc

import android.content.Context
import android.util.Log
import java.io.File

const val TAG = "RiftPoC"

/** Port of the fixture server; the host maps it with `adb reverse`. */
const val FIXTURE_PORT = 8765
const val FIXTURE_ORIGIN = "http://localhost:$FIXTURE_PORT"

/** Results are plain `key=value` text files the host collects with `run-as`. */
object Results {
    fun write(context: Context, name: String, text: String) {
        file(context, "$name.txt").writeText(text)
        Log.i(TAG, "result $name:\n$text")
    }

    /** A file in the results directory, which `pm clear` removes between runs. */
    fun file(context: Context, name: String): File =
        File(File(context.filesDir, "results").apply { mkdirs() }, name)
}

/**
 * Browser-session generation. `:browser` uses it as its WebView data-directory
 * suffix, so a reset can switch to a fresh directory before deleting the old one.
 */
object Generation {
    private fun file(context: Context) = File(context.filesDir, "generation")

    fun read(context: Context): Int = file(context).takeIf { it.exists() }?.readText()?.trim()?.toIntOrNull() ?: 1

    fun write(context: Context, value: Int) = file(context).writeText(value.toString())

    fun suffix(generation: Int) = "s$generation"
}

/** Runs a probe and reports `ALLOWED …` or `DENIED <exception>` — never throws. */
inline fun attempt(block: () -> String): String =
    try {
        "ALLOWED " + block()
    } catch (e: Throwable) {
        "DENIED ${e.javaClass.simpleName}: ${e.message}"
    }

/** Every file below [root], relative, with sizes — for before/after disposal diffs. */
fun inventory(root: File): String =
    root.walkTopDown()
        .filter { it.isFile }
        .map { "${it.relativeTo(root).path} ${it.length()}" }
        .sorted()
        .joinToString("\n")
