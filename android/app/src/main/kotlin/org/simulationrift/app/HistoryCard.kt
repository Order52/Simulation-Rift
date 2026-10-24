package org.simulationrift.app

import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import java.text.DateFormat
import java.util.Date

/** Check's history (§10.13), on the Activity tab: off until switched on. Tapping a link checks it again. */
@Composable
internal fun HistoryCard(onCheck: (String) -> Unit) {
    val state by CheckHistory.state.collectAsState()
    val status = LocalStatusColors.current
    Card(
        Modifier.fillMaxWidth().animateContentSize().testTag("history-card"),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
    ) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(
                Modifier.fillMaxWidth().toggleable(state.on, role = Role.Switch, onValueChange = CheckHistory::setOn),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f)) {
                    Text("Remember checked links", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "Off by default: Rift keeps nothing. On, the last 200 links you check are kept on this phone, " +
                            "encrypted with a key that never leaves it. Turning it off deletes them and the key.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Spacer(Modifier.width(12.dp))
                Switch(checked = state.on, onCheckedChange = null, modifier = Modifier.testTag("history-switch"))
            }
            if (state.on) {
                if (state.entries.isEmpty()) {
                    Text("No links checked yet.", style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("history-empty"))
                }
                state.entries.forEachIndexed { i, entry ->
                    Column(Modifier.fillMaxWidth().clickable { onCheck(entry.address) }.padding(vertical = 4.dp).testTag("history-$i")) {
                        Text(entry.address, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace,
                            maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(
                            "${entry.verdict} · ${DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(entry.time))}",
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = if (entry.severity >= 2) FontWeight.SemiBold else null,
                            color = when {
                                entry.severity >= 2 -> MaterialTheme.colorScheme.error
                                entry.severity == 1 -> status.onWarningContainer
                                else -> MaterialTheme.colorScheme.onSurfaceVariant
                            },
                        )
                    }
                }
                if (state.entries.isNotEmpty()) {
                    TextButton(onClick = CheckHistory::clear, modifier = Modifier.testTag("history-clear")) { Text("Clear the history") }
                }
            }
        }
    }
}
