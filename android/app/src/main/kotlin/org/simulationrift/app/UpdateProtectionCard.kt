package org.simulationrift.app

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
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp

/**
 * One button for everything that keeps Check current: the threat lists, the
 * link-cleaning rules, and a look for a newer Rift release, which is how a
 * retrained Rift AI (address model, page model, protected brands) arrives.
 * and the signed threat database that can carry a newer Rift AI model without
 * a new release (§13.1, §16; the model must pass the update canary). It
 * starts the same downloads the cards below and About already have, so
 * nothing new is fetched and nothing is sent: it only saves visiting each.
 * An update that is found is still installed from About or the update
 * dialog, after the signature and SHA-256 checks of §8.11.
 */
@Composable
internal fun UpdateProtectionCard() {
    val lists by ThreatLists.state.collectAsState()
    val rules by LinkCleaning.state.collectAsState()
    val app by SelfUpdate.state.collectAsState()
    val pack by Core.intelMessage.collectAsState()
    val busy = lists.busy || rules.busy || app is SelfUpdate.State.Checking || app is SelfUpdate.State.Downloading
    Card(
        Modifier.fillMaxWidth().testTag("update-protection-card"),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
    ) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Keep Check up to date", style = MaterialTheme.typography.titleMedium)
            Text(
                "Downloads the newest threat lists and link-cleaning rules, and looks for a newer Rift. " +
                    "A new Rift release carries Rift AI as it was retrained that week. Nothing about your links is sent.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (busy) {
                    CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.width(10.dp))
                }
                Text(summary(lists, rules, app), style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("update-protection-status"))
            }
            pack?.let { Text("Threat database: $it", style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("update-protection-pack")) }
            Button(
                onClick = {
                    ThreatLists.download()
                    LinkCleaning.download()
                    SelfUpdate.checkNow()
                    // The signed database, with Rift AI's newer model if it carries one.
                    Core.updateSource()?.let { Core.updateIntelOnline(it) }
                },
                enabled = !busy,
                modifier = Modifier.fillMaxWidth().height(52.dp).testTag("update-protection"),
            ) { Text("Update protection now", maxLines = 1) }
        }
    }
}

/** One line on where the three updates stand. */
private fun summary(lists: ThreatLists.State, rules: LinkCleaning.State, app: SelfUpdate.State): String = when {
    lists.busy || rules.busy -> "Downloading the lists…"
    app is SelfUpdate.State.Checking -> "Looking for a newer Rift…"
    app is SelfUpdate.State.Downloading -> "Downloading Rift ${app.version}…"
    app is SelfUpdate.State.Available -> "Rift ${app.release.version} is available: install it from About, under Updates."
    app is SelfUpdate.State.Ready -> "Rift ${app.version} is ready: install it from About, under Updates."
    app is SelfUpdate.State.Failed -> "Rift's own check failed: ${app.reason}."
    else -> lists.message ?: updateStatus(app, automatic = true)
}
