package org.simulationrift.bridge

import android.os.Bundle

/** One explainable fact; `text` is already safe to show in trusted UI. */
data class Fact(val code: String, val text: String)

/**
 * A navigation decision as it crosses from the core to the browser. Plain
 * Kotlin on purpose: the browser never loads the Rust library.
 */
sealed interface NavigationDecision {
    data class Proceed(val notes: List<Fact>) : NavigationDecision
    /** `displayUrl` is the address with hidden and reordering characters escaped by the core. */
    data class Confirm(val reasons: List<Fact>, val notes: List<Fact>, val displayUrl: String) : NavigationDecision
    data class Block(val reason: Fact, val inspectAnyway: Boolean, val displayUrl: String) : NavigationDecision

    fun toBundle(): Bundle = Bundle().apply {
        when (val d = this@NavigationDecision) {
            is Proceed -> {
                putString(KIND, PROCEED)
                putFacts(NOTES, d.notes)
            }
            is Confirm -> {
                putString(KIND, CONFIRM)
                putFacts(REASONS, d.reasons)
                putFacts(NOTES, d.notes)
                putString(DISPLAY_URL, d.displayUrl)
            }
            is Block -> {
                putString(KIND, BLOCK)
                putFacts(REASONS, listOf(d.reason))
                putBoolean(INSPECT_ANYWAY, d.inspectAnyway)
                putString(DISPLAY_URL, d.displayUrl)
            }
        }
    }

    companion object {
        private const val KIND = "kind"
        private const val PROCEED = "proceed"
        private const val CONFIRM = "confirm"
        private const val BLOCK = "block"
        private const val REASONS = "reasons"
        private const val NOTES = "notes"
        private const val INSPECT_ANYWAY = "inspectAnyway"
        private const val DISPLAY_URL = "displayUrl"

        /** Anything that does not decode is a block: never fail open. */
        fun fromBundle(bundle: Bundle?): NavigationDecision {
            val malformed = Block(Fact("decision-unavailable", "The safety check did not answer, so the page was not loaded."), false, "")
            bundle ?: return malformed
            val reasons = bundle.facts(REASONS)
            val notes = bundle.facts(NOTES)
            val displayUrl = bundle.getString(DISPLAY_URL).orEmpty()
            return when (bundle.getString(KIND)) {
                PROCEED -> Proceed(notes)
                CONFIRM -> if (reasons.isEmpty()) malformed else Confirm(reasons, notes, displayUrl)
                BLOCK -> reasons.singleOrNull()?.let { Block(it, bundle.getBoolean(INSPECT_ANYWAY), displayUrl) } ?: malformed
                else -> malformed
            }
        }

        private fun Bundle.putFacts(key: String, facts: List<Fact>) {
            putStringArrayList("$key.code", ArrayList(facts.map { it.code }))
            putStringArrayList("$key.text", ArrayList(facts.map { it.text }))
        }

        private fun Bundle.facts(key: String): List<Fact> {
            val codes = getStringArrayList("$key.code") ?: return emptyList()
            val texts = getStringArrayList("$key.text") ?: return emptyList()
            if (codes.size != texts.size) return emptyList()
            return codes.zip(texts) { code, text -> Fact(code, text) }
        }
    }
}
