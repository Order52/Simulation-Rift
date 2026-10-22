package org.simulationrift.app

import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import java.text.DateFormat
import java.util.Date

/**
 * The Filters tab (§10.9): ad, tracker and annoyance lists from their
 * upstream projects, one switch for all of it, one for each list, and the
 * user's own rules. Rift writes no rules of its own.
 */
@Composable
internal fun FiltersTab() {
    val state by ContentFilter.state.collectAsState()
    val downloaded = state.lists.filterKeys { id -> ContentFilter.catalog.any { it.id == id } }.values.count { it.downloaded }
    val onCount = state.lists.values.count { it.on }
    val rules = state.lists.values.filter { it.on && it.downloaded }.sumOf { it.rules }

    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text("Filters", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 8.dp))

        Card(
            Modifier.fillMaxWidth().animateContentSize().testTag("filters-card"),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
        ) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Block ads and annoyances", style = MaterialTheme.typography.titleMedium)
                        Text(
                            "Ads, trackers, cookie banners, pop-ups and “Sign in with Google or Facebook” prompts, in the sealed browser.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Spacer(Modifier.width(12.dp))
                    Switch(checked = state.enabled, onCheckedChange = ContentFilter::setEnabled, modifier = Modifier.testTag("filters-switch"))
                }
                val summary = when {
                    !state.enabled -> "Off. Pages load as they are."
                    state.busy != null -> state.busy
                    downloaded == 0 -> "No lists yet. Download them once to start filtering."
                    !state.ready -> "Starting…"
                    else -> "On: $onCount lists, ${format(rules)} rules. ${format(state.blocked.toInt())} requests blocked since Rift started."
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (state.busy != null) {
                        CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                        Spacer(Modifier.width(10.dp))
                    }
                    Text(summary.orEmpty(), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("filters-status"))
                }
                state.message?.let { Text(it, style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("filters-message")) }
                Button(
                    onClick = ContentFilter::updateAll,
                    enabled = state.enabled && state.busy == null && onCount > 0,
                    modifier = Modifier.fillMaxWidth().height(52.dp).testTag("filters-download"),
                ) { Text(if (downloaded == 0) "Download the lists" else "Update the lists") }
                Text(
                    "Downloaded from the lists' own websites when you tap, never by itself. New settings apply from the next page you open.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        Card(
            Modifier.fillMaxWidth().testTag("filter-lists"),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
        ) {
            Column(Modifier.padding(horizontal = 20.dp, vertical = 12.dp)) {
                Text("Lists", style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(vertical = 8.dp))
                ContentFilter.catalog.forEachIndexed { i, source ->
                    val list = state.lists[source.id] ?: return@forEachIndexed
                    if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                    Row(Modifier.padding(vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(source.title, style = MaterialTheme.typography.titleSmall)
                            Text(source.about, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Text(
                                if (list.downloaded) "${format(list.rules)} rules, updated ${list.updated?.let { DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(it)) }}"
                                else "Not downloaded",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.testTag("filter-info-${source.id}"),
                            )
                        }
                        Spacer(Modifier.width(12.dp))
                        Switch(
                            checked = list.on,
                            onCheckedChange = { ContentFilter.setList(source.id, it) },
                            enabled = state.enabled && state.busy == null,
                            modifier = Modifier.testTag("filter-list-${source.id}"),
                        )
                    }
                }
            }
        }

        CustomRules(state.custom, state.enabled)

        Text(
            "The lists are EasyList and Fanboy's lists (GPL v3 or CC BY-SA 3.0) and uBlock Origin's (GPL v3), by their volunteers. " +
                "They only remove things from pages: they can never allow what Rift's own checks refuse. " +
                "A filter does not make a page safe, and a list can be wrong: if a site breaks, turn a list off.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun CustomRules(saved: String, enabled: Boolean) {
    var text by remember(saved) { mutableStateOf(saved) }
    Card(
        Modifier.fillMaxWidth().testTag("custom-card"),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
    ) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("Your own rules", style = MaterialTheme.typography.titleMedium)
            Text(
                "One per line. ||ads.example.com^ blocks a site. example.com##.popup hides an element on a site. " +
                    "! starts a comment. The same rules uBlock Origin and AdBlock understand.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = text,
                onValueChange = { text = it },
                minLines = 4,
                maxLines = 10,
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false, keyboardType = KeyboardType.Ascii),
                modifier = Modifier.noAutofill().fillMaxWidth().testTag("custom-rules"),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { ContentFilter.setCustom(text) }, enabled = enabled && text != saved, modifier = Modifier.testTag("custom-save")) { Text("Save rules") }
                OutlinedButton(onClick = { text = saved }, enabled = text != saved) { Text("Undo") }
            }
            val lines = saved.lines().count { it.isNotBlank() && !it.startsWith("!") }
            Text(
                if (lines == 0) "No rules of your own yet." else "$lines saved ${if (lines == 1) "rule" else "rules"}.",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.testTag("custom-count"),
            )
        }
    }
}
