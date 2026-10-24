package org.simulationrift.bridge

import android.os.Bundle

/**
 * What a test-open saw (§10.11), written by the core: a summary, then
 * sections of sentences already safe to show in trusted UI. Plain Kotlin,
 * so the browser can show it without the Rust library.
 */
data class TestReport(val level: PageWatch.Level?, val summary: String, val sections: List<Section>) {

    data class Section(val title: String, val items: List<String>)

    fun toBundle(): Bundle = Bundle().apply {
        putString(LEVEL, level?.name)
        putString(SUMMARY, summary)
        putStringArrayList(TITLES, ArrayList(sections.map { it.title }))
        sections.forEachIndexed { i, section -> putStringArrayList("$ITEMS$i", ArrayList(section.items)) }
    }

    companion object {
        private const val LEVEL = "level"
        private const val SUMMARY = "summary"
        private const val TITLES = "titles"
        private const val ITEMS = "items"

        /** Null when there is no report or it is malformed: never shown as "nothing seen". */
        fun fromBundle(bundle: Bundle?): TestReport? {
            bundle ?: return null
            val summary = bundle.getString(SUMMARY) ?: return null
            val titles = bundle.getStringArrayList(TITLES) ?: return null
            val level = bundle.getString(LEVEL)?.let { name -> PageWatch.Level.entries.firstOrNull { it.name == name } ?: return null }
            val sections = titles.mapIndexed { i, title -> Section(title, bundle.getStringArrayList("$ITEMS$i") ?: return null) }
            return TestReport(level, summary, sections)
        }
    }
}
