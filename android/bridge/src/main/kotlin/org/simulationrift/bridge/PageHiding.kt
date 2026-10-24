package org.simulationrift.bridge

import android.os.Bundle

/**
 * What the content filters (§10.9) hide on a page: style rules the core
 * built itself, one per selector, so the browser injects them as they are,
 * and the changes a style sheet cannot make (`actions`, JSON the core
 * checked and wrote), which the browser's fixed script applies.
 * Plain Kotlin, so the browser can use it without the Rust library.
 */
data class PageHiding(val css: String, val exceptions: List<String>, val genericHidden: Boolean, val actions: String = "") {

    fun toBundle(): Bundle = Bundle().apply {
        putString(CSS, css)
        putStringArrayList(EXCEPTIONS, ArrayList(exceptions))
        putBoolean(GENERIC_HIDDEN, genericHidden)
        putString(ACTIONS, actions)
    }

    companion object {
        private const val CSS = "css"
        private const val EXCEPTIONS = "exceptions"
        private const val GENERIC_HIDDEN = "genericHidden"
        private const val ACTIONS = "actions"

        /** Rules are bounded by the core; an over-long answer is dropped here too. */
        private const val MAX_CSS_CHARS = 250_000
        private const val MAX_ACTIONS_CHARS = 120_000

        val NONE = PageHiding("", emptyList(), false)

        fun fromBundle(bundle: Bundle?): PageHiding {
            if (bundle == null) return NONE
            val css = bundle.getString(CSS)?.takeIf { it.length <= MAX_CSS_CHARS } ?: return NONE
            val actions = bundle.getString(ACTIONS)?.takeIf { it.length <= MAX_ACTIONS_CHARS }.orEmpty()
            return PageHiding(css, bundle.getStringArrayList(EXCEPTIONS).orEmpty(), bundle.getBoolean(GENERIC_HIDDEN), actions)
        }
    }
}
