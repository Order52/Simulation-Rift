package org.simulationrift.bridge

import android.os.Bundle

/**
 * What the content filters (§10.9) hide on a page: style rules the core
 * built itself, one per selector, so the browser injects them as they are.
 * Plain Kotlin, so the browser can use it without the Rust library.
 */
data class PageHiding(val css: String, val exceptions: List<String>, val genericHidden: Boolean) {

    fun toBundle(): Bundle = Bundle().apply {
        putString(CSS, css)
        putStringArrayList(EXCEPTIONS, ArrayList(exceptions))
        putBoolean(GENERIC_HIDDEN, genericHidden)
    }

    companion object {
        private const val CSS = "css"
        private const val EXCEPTIONS = "exceptions"
        private const val GENERIC_HIDDEN = "genericHidden"

        /** Rules are bounded by the core; an over-long answer is dropped here too. */
        private const val MAX_CSS_CHARS = 250_000

        val NONE = PageHiding("", emptyList(), false)

        fun fromBundle(bundle: Bundle?): PageHiding {
            if (bundle == null) return NONE
            val css = bundle.getString(CSS)?.takeIf { it.length <= MAX_CSS_CHARS } ?: return NONE
            return PageHiding(css, bundle.getStringArrayList(EXCEPTIONS).orEmpty(), bundle.getBoolean(GENERIC_HIDDEN))
        }
    }
}
