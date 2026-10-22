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
import org.simulationrift.bridge.Rift
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
            Detail("Sends data by itself", "never: updates run only when you ask")
        }

        OutlinedButton(onClick = onLicences, modifier = Modifier.fillMaxWidth().testTag("notices-open")) { Text("Open-source licences") }
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
