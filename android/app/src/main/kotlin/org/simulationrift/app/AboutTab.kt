package org.simulationrift.app

import android.content.Context
import android.content.pm.PackageManager
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Switch
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.simulationrift.bridge.Appearance
import org.simulationrift.bridge.Rift
import java.text.DateFormat
import java.util.Date
import org.simulationrift.core.IntelStatus

/** The About tab: who made Rift, what it does and does not do, and which versions are running. */
@Composable
internal fun AboutTab(onLicences: () -> Unit) {
    val context = LocalContext.current
    val intel by Core.intel.collectAsState()
    val filters by ContentFilter.state.collectAsState()

    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Row(Modifier.fillMaxWidth().padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Image(painterResource(org.simulationrift.bridge.R.drawable.rift_mark), contentDescription = null, modifier = Modifier.size(56.dp))
            Spacer(Modifier.width(16.dp))
            Column {
                Text("Rift", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
                Text("Open any link. Keep nothing.", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }

        AboutCard("Made by") {
            Text("Ali Alakber and Teeba Nazar", style = MaterialTheme.typography.titleMedium, modifier = Modifier.testTag("about-authors"))
        }

        AppearanceCard()

        UpdatesCard()

        AboutCard("What it does") {
            Point("Opens a link in a sealed browser: a separate app with its own Android user, so a page cannot reach Rift's files or the rest of your phone.")
            Point("Checks a link before it opens, with Rift AI on your phone and a threat database. Nothing about the link is sent anywhere.")
            Point("Watches the open page live: what it asks for (camera, microphone, location, files), and gives it made-up answers instead.")
            Point("Scans downloaded files in isolated workers and previews images and PDFs without opening them in an app.")
            Point("Blocks ads, trackers, cookie banners and sign-in pop-ups with the lists on the Filters tab.")
            Point("Keeps nothing: every reset wipes the browser, and Android checks that nothing is left.")
        }

        AboutCard("What it does not do") {
            Point("It is not audited, and no software is perfectly isolated or free of flaws.")
            Point("Rift AI is advice, not a guarantee: a page it does not flag may still be harmful.")
            Point("It does not hide your address from the sites you visit.")
        }

        AboutCard("This install") {
            Detail("Rift", versionOf(context, context.packageName))
            Detail("Sealed browser", versionOf(context, Rift.BROWSER_PACKAGE))
            Detail(
                "Threat database",
                when (val i = intel) {
                    is IntelStatus.Installed -> i.snapshot + if (i.demo) " (demo)" else ""
                    else -> "none installed"
                },
            )
            Detail("Filter lists", if (!filters.enabled) "off" else "${filters.lists.values.count { it.on && it.downloaded }} downloaded")
            Detail("Sends data by itself", "only to fetch updates: Rift's own, and the lists you turned on")
        }

        OutlinedButton(onClick = onLicences, modifier = Modifier.fillMaxWidth().testTag("notices-open")) { Text("Open-source licences") }
    }
}

@Composable
private fun AppearanceCard() {
    val context = LocalContext.current
    val appearance by AppearanceChoice.state.collectAsState()
    AboutCard("Appearance") {
        SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth().testTag("appearance")) {
            val choices = listOf(Appearance.SYSTEM to "System", Appearance.LIGHT to "Light", Appearance.DARK to "Dark")
            choices.forEachIndexed { i, (choice, label) ->
                SegmentedButton(
                    selected = appearance == choice,
                    onClick = { AppearanceChoice.set(context, choice) },
                    shape = SegmentedButtonDefaults.itemShape(i, choices.size),
                    modifier = Modifier.testTag("appearance-${choice.name.lowercase()}"),
                ) { Text(label) }
            }
        }
        Text(
            "For Rift and its sealed browser. In dark, pages without a dark style of their own are darkened too.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun UpdatesCard() {
    val update by SelfUpdate.state.collectAsState()
    AboutCard("Updates") {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("Update Rift by itself", style = MaterialTheme.typography.bodyLarge)
                Text(
                    "Once a day Rift asks GitHub for its latest release, and installs it only if it is signed with Rift's own key. " +
                        "The first time, Android asks you; after that Rift updates while you are not using it.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.width(12.dp))
            Switch(
                checked = update != SelfUpdate.State.Off && update != SelfUpdate.State.DebugBuild,
                onCheckedChange = { SelfUpdate.setEnabled(it) },
                enabled = update != SelfUpdate.State.DebugBuild,
                modifier = Modifier.testTag("self-update-switch"),
            )
        }
        val status = when (val u = update) {
            SelfUpdate.State.Off -> "Off: updates only by hand, from the Releases page."
            SelfUpdate.State.DebugBuild -> "A test build: it is updated with the build tools, not from releases."
            SelfUpdate.State.Idle -> "Checks within a day."
            SelfUpdate.State.Checking -> "Checking…"
            is SelfUpdate.State.UpToDate -> "Up to date (checked ${DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(u.checkedAt))})."
            is SelfUpdate.State.Downloading -> "Downloading Rift ${u.version}…"
            is SelfUpdate.State.Ready -> "Rift ${u.version} is ready." + (u.problem?.let { " Not installed: $it." } ?: "")
            SelfUpdate.State.Installing -> "Installing…"
            is SelfUpdate.State.Failed -> "Could not update: ${u.reason}."
        }
        Text(status, style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("self-update-status"))
        when (update) {
            is SelfUpdate.State.Ready -> Button(onClick = SelfUpdate::install, modifier = Modifier.fillMaxWidth().testTag("self-update-install")) { Text("Install now") }
            is SelfUpdate.State.UpToDate, is SelfUpdate.State.Failed, SelfUpdate.State.Idle ->
                OutlinedButton(onClick = SelfUpdate::checkNow, modifier = Modifier.fillMaxWidth().testTag("self-update-check")) { Text("Check now") }
            else -> Unit
        }
    }
}

@Composable
private fun AboutCard(title: String, content: @Composable () -> Unit) {
    Card(
        Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
    ) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            content()
        }
    }
}

@Composable
private fun Point(text: String) {
    Row {
        Text("•", modifier = Modifier.width(16.dp))
        Text(text, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun Detail(label: String, value: String) {
    Column {
        Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.width(12.dp))
            Text(value, style = MaterialTheme.typography.bodyMedium)
        }
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
    }
}

@Composable
private fun versionOf(context: Context, packageName: String): String = remember(packageName) {
    try {
        context.packageManager.getPackageInfo(packageName, 0).versionName ?: "unknown"
    } catch (e: PackageManager.NameNotFoundException) {
        "not installed"
    }
}
