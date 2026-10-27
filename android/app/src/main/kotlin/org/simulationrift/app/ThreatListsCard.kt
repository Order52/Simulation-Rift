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
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import java.text.DateFormat
import java.text.NumberFormat
import java.util.Date

/** The threat lists Check consults (§10.12), on the Security tab. */
@Composable
internal fun ThreatListsCard() {
    val state by ThreatLists.state.collectAsState()
    Card(
        Modifier.fillMaxWidth().animateContentSize().testTag("lists-card"),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
    ) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Threat lists for Check", style = MaterialTheme.typography.titleMedium)
            Text(
                "Check also looks a link's site up in these community lists of dangerous sites, on this phone: nothing is sent to them. " +
                    "After your first download they update by themselves once a day while Rift runs (with the Filters tab's \"Keep the lists up to date\"). " +
                    "Lists can be wrong; they only ever add a warning.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            ThreatLists.catalog.forEach { source ->
                val list = state.lists[source.id] ?: ThreatLists.ListState()
                Row(
                    Modifier.fillMaxWidth()
                        .toggleable(list.on, enabled = !state.busy, role = Role.Switch) { ThreatLists.setList(source.id, it) }
                        .padding(vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(source.name, style = MaterialTheme.typography.titleSmall)
                        Text(source.about, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        val updated = list.updated
                        Text(
                            when {
                                list.error != null -> "Unusable: ${list.error}"
                                updated == null -> "Not downloaded"
                                else -> "${NumberFormat.getIntegerInstance().format(list.hosts)} sites, downloaded " +
                                    DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(updated))
                            },
                            style = MaterialTheme.typography.labelSmall,
                            modifier = Modifier.testTag("lists-status-${source.id}"),
                        )
                    }
                    Spacer(Modifier.width(12.dp))
                    Switch(checked = list.on, onCheckedChange = null, enabled = !state.busy, modifier = Modifier.testTag("lists-${source.id}"))
                }
                list.held?.let { held ->
                    val count = NumberFormat.getIntegerInstance()
                    Text(
                        "The latest download keeps only ${count.format(held.kept.toLong())} of the ${count.format(held.before.toLong())} sites in use " +
                            "and has ${count.format(held.after.toLong())} in all. Lists change a little each day, so Rift is still using the copy it had. " +
                            "A change this large can be a broken list, or its server in other hands.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.testTag("lists-held-${source.id}"),
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        TextButton(onClick = { ThreatLists.decideHeld(source.id, use = false) }, enabled = !state.busy, modifier = Modifier.testTag("lists-keep-${source.id}")) {
                            Text("Keep the copy in use")
                        }
                        TextButton(onClick = { ThreatLists.decideHeld(source.id, use = true) }, enabled = !state.busy, modifier = Modifier.testTag("lists-use-${source.id}")) {
                            Text("Use the new one")
                        }
                    }
                }
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (state.busy) {
                    CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.width(10.dp))
                    Text("Downloading the lists…", style = MaterialTheme.typography.bodyMedium)
                }
            }
            state.message?.let { Text(it, style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("lists-message")) }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                Button(onClick = ThreatLists::download, enabled = !state.busy, modifier = Modifier.weight(1f).height(52.dp).testTag("lists-download")) {
                    Text(if (state.downloaded) "Update now" else "Download the lists", maxLines = 1)
                }
                if (state.downloaded) {
                    TextButton(onClick = ThreatLists::remove, enabled = !state.busy, modifier = Modifier.testTag("lists-remove")) { Text("Remove", maxLines = 1) }
                }
            }
        }
    }
}
