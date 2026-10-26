package org.simulationrift.app

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.simulationrift.bridge.Appearance
import java.io.File

/**
 * Light, dark or with the system, for Rift's screens and, through the
 * session grant, the browser's bar and pages. Kept in one small file; with
 * no file it follows the system.
 */
object AppearanceChoice {
    private const val FILE = "appearance"

    private val _state = MutableStateFlow(Appearance.SYSTEM)
    val state: StateFlow<Appearance> = _state
    private var file: File? = null

    /** Idempotent: the theme calls it before Core has started. */
    @Synchronized
    fun init(context: Context) {
        if (file != null) return
        val f = File(context.applicationContext.filesDir, FILE)
        file = f
        val saved = try { f.readText().trim() } catch (e: java.io.IOException) { "" }
        _state.value = Appearance.entries.firstOrNull { it.name == saved } ?: Appearance.SYSTEM
    }

    @Synchronized
    fun set(context: Context, appearance: Appearance) {
        init(context)
        val f = file ?: return
        if (appearance == Appearance.SYSTEM) f.delete() else f.writeText(appearance.name)
        _state.value = appearance
    }
}
