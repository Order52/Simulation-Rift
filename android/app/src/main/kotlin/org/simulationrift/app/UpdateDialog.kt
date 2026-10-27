package org.simulationrift.app

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId

/**
 * A newer release found when Rift opened (§8.11): one tap on Update
 * downloads it, checks it and hands it to Android's installer. The dialog
 * stays open to show how that goes; Android's own screen takes over to
 * confirm the install where it asks.
 */
@Composable
fun UpdateDialog() {
    val open by SelfUpdate.dialog.collectAsState()
    val update by SelfUpdate.state.collectAsState()
    val automatic by SelfUpdate.automatic.collectAsState()
    if (!open) return
    val context = LocalContext.current
    val version = when (val u = update) {
        is SelfUpdate.State.Available -> u.release.version
        is SelfUpdate.State.Ready -> u.version
        else -> null
    }
    val busy = update is SelfUpdate.State.Checking || update is SelfUpdate.State.Downloading || update == SelfUpdate.State.Installing
    val needsPermission = !SelfUpdate.mayInstall.collectAsState().value
    AlertDialog(
        onDismissRequest = SelfUpdate::dismiss,
        // Its own window: the home screen's test tags do not reach it.
        modifier = Modifier.semantics { testTagsAsResourceId = true }.testTag("update-dialog"),
        title = { Text(if (version != null) "Rift $version is available" else "Updating Rift") },
        text = {
            Text(
                when {
                    version != null && needsPermission && update !is SelfUpdate.State.Failed ->
                        "Rift needs Android's permission to install apps (Install unknown apps). It installs only an update signed with Rift's own key."
                    version != null && (update as? SelfUpdate.State.Ready)?.problem == null ->
                        "It is installed only if it matches the checksum published with it and is signed with Rift's own key. Android may ask you to confirm."
                    else -> updateStatus(update, automatic)
                },
            )
        },
        confirmButton = {
            when {
                version != null && needsPermission -> Button(
                    onClick = {
                        context.startActivity(
                            Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${context.packageName}")),
                        )
                    },
                    modifier = Modifier.testTag("update-dialog-permission"),
                ) { Text("Allow") }
                version != null -> Button(onClick = SelfUpdate::install, modifier = Modifier.testTag("update-dialog-update")) {
                    Text(if ((update as? SelfUpdate.State.Ready)?.problem != null) "Try again" else "Update")
                }
                update is SelfUpdate.State.Failed -> Button(onClick = SelfUpdate::checkNow, modifier = Modifier.testTag("update-dialog-retry")) { Text("Try again") }
                else -> Unit
            }
        },
        dismissButton = {
            if (!busy) TextButton(onClick = SelfUpdate::dismiss, modifier = Modifier.testTag("update-dialog-later")) {
                Text(if (version != null) "Later" else "Close")
            }
        },
    )
}
