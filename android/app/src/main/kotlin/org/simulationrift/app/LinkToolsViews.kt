package org.simulationrift.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.simulationrift.core.AiLevel
import org.simulationrift.core.LinkCheck
import org.simulationrift.core.LinkTrace
import org.simulationrift.core.Navigation
import org.simulationrift.core.TraceHop
import org.simulationrift.core.TraceOutcome
import org.simulationrift.core.TrackingParam
import org.simulationrift.core.linkTracking
import org.simulationrift.core.linkWithHttps
import org.simulationrift.core.explainAppLink
import org.simulationrift.core.linkWithoutQuery
import org.simulationrift.core.linkWithoutTracking

/*
 * What Check offers beyond its verdict (§10.10), on the home screen and in
 * the share sheet: edit the link, take its trackers off and unwrap redirect
 * links (ClearURLs' rules), find where it goes by following its redirects
 * with every hop checked, and copy, share or open it elsewhere. Each changed
 * address is checked again from the start; nothing here opens a page.
 */

/**
 * The tools for [check]. [onAddress] checks another address in its place
 * (the user's edit, the clean link, where it goes); [onUndo] goes back to
 * the one before. [trace] is where it goes, once found; [onTrace] sets it.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
internal fun LinkTools(
    check: LinkCheck,
    trace: LinkTrace?,
    onTrace: (LinkTrace) -> Unit,
    onAddress: (String) -> Unit,
    onUndo: (() -> Unit)?,
) {
    val context = LocalContext.current
    val navigation = check.navigation
    val listed = navigation is Navigation.Block && navigation.reason.code == "known-malicious"
    // Not a web address: there is nothing to clean or follow, only to edit.
    val web = navigation !is Navigation.Block || listed
    var editing by remember(check.address) { mutableStateOf(false) }
    var leaving by remember(check.address) { mutableStateOf(false) }

    Column(verticalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.testTag("link-tools")) {
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        if (editing) {
            EditAddress(check.address, onDone = { editing = false; if (it.isNotBlank() && it != check.address) onAddress(it) })
        }
        // An app link's web fallback is an address like any other: check it.
        check.appLink?.fallback?.let { fallback ->
            TextButton(onClick = { onAddress(fallback) }, modifier = Modifier.testTag("tools-fallback")) {
                Text("Check the web address it uses without the app")
            }
        }
        if (web) Cleaning(check.address, onAddress)
        if (web && !listed) {
            QuickFixes(check.address, onAddress)
            Where(check, trace, onTrace, onAddress)
        }
        if (leaving) {
            Text(
                "Another app opens it as it is: outside Rift's sealed browser and network lock, with that app's cookies and " +
                    "your phone's permissions. Rift's checks no longer apply there.",
                style = MaterialTheme.typography.bodySmall,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.testTag("tools-leave-warning"),
            )
        }
        FlowRow(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            if (!editing) TextButton(onClick = { editing = true }, modifier = Modifier.testTag("tools-edit")) { Text("Edit") }
            onUndo?.let { TextButton(onClick = it, modifier = Modifier.testTag("tools-undo")) { Text("Undo") } }
            TextButton(onClick = { copy(context, check.address) }, modifier = Modifier.testTag("tools-copy")) { Text("Copy") }
            TextButton(onClick = { share(context, check.address) }, modifier = Modifier.testTag("tools-share")) { Text("Share") }
            if (web && !listed) {
                TextButton(
                    onClick = { if (leaving) openElsewhere(context, check.address) else leaving = true },
                    modifier = Modifier.testTag("tools-elsewhere"),
                ) { Text(if (leaving) "Open in another app anyway" else "Open in another app") }
            }
        }
    }
}

@Composable
private fun EditAddress(address: String, onDone: (String) -> Unit) {
    var text by remember(address) { mutableStateOf(address) }
    OutlinedTextField(
        value = text,
        onValueChange = { text = it },
        label = { Text("Link") },
        textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, imeAction = ImeAction.Done, autoCorrectEnabled = false),
        keyboardActions = KeyboardActions(onDone = { onDone(text) }),
        modifier = Modifier.noAutofill().fillMaxWidth().testTag("tools-edit-field"),
    )
    Row {
        OutlinedButton(onClick = { onDone(text) }, modifier = Modifier.testTag("tools-edit-check")) { Text("Check this") }
        Spacer(Modifier.width(8.dp))
        TextButton(onClick = { onDone(address) }) { Text("Cancel") }
    }
}

/** Trackers and redirect links, by the ClearURLs rules if the user downloaded them. */
@Composable
private fun Cleaning(address: String, onAddress: (String) -> Unit) {
    val rules by LinkCleaning.state.collectAsState()
    val cleaned = remember(address, rules.updated) { LinkCleaning.clean(address) }
    val filters by ContentFilter.state.collectAsState()
    val listed = remember(address, filters.ready) { ContentFilter.listsAddress(address) }
    // Rift's own short list, explained; it works without the ClearURLs rules (§10.14).
    val tracking = remember(address) { linkTracking(address) }
    TrackingExplained(tracking)
    if (listed) {
        Text(
            "Your content filters list this server as an ad or tracker server (EasyPrivacy and the other lists).",
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.testTag("tools-tracker-server"),
        )
    }
    if (cleaned == null) {
        val withoutTracking = remember(address) { linkWithoutTracking(address) }
        withoutTracking?.let {
            OutlinedButton(onClick = { onAddress(it) }, modifier = Modifier.testTag("tools-tracking-remove")) { Text("Remove the tracking") }
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                if (rules.busy) "Downloading the ClearURLs rules…"
                else "Rift can take trackers off links and unwrap redirect links with the ClearURLs project's rules.",
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.weight(1f),
            )
            if (!rules.busy) TextButton(onClick = LinkCleaning::download, modifier = Modifier.testTag("tools-clean-download")) { Text("Get them") }
        }
        rules.message?.let { Text(it, style = MaterialTheme.typography.labelSmall) }
        return
    }
    Column(verticalArrangement = Arrangement.spacedBy(4.dp), modifier = Modifier.testTag("tools-clean")) {
        when {
            cleaned.trackerOnly -> Text(
                "This whole address is a tracker's: it is there to count the click (ClearURLs).",
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.testTag("tools-clean-tracker"),
            )
            !cleaned.changed -> Text("No trackers in this link.", style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("tools-clean-none"))
        }
        if (cleaned.unwrapped.isNotEmpty()) {
            Text(
                "This is a redirect link. It takes you to:",
                style = MaterialTheme.typography.bodySmall,
                fontWeight = FontWeight.SemiBold,
            )
            Text(cleaned.unwrapped.last(), style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace,
                maxLines = 3, overflow = TextOverflow.Ellipsis, modifier = Modifier.testTag("tools-clean-unwrapped"))
        }
        val unexplained = cleaned.removed.filter { name -> tracking.none { it.name.equals(name, ignoreCase = true) } }
        if (unexplained.isNotEmpty()) {
            Text(
                (if (tracking.isEmpty()) "Trackers in it: " else "Other trackers in it (ClearURLs): ") + unexplained.joinToString(", "),
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.testTag("tools-clean-removed"),
            )
        }
        if (cleaned.changed) {
            OutlinedButton(onClick = { onAddress(cleaned.address) }, modifier = Modifier.testTag("tools-clean-use")) {
                Text(if (cleaned.unwrapped.isNotEmpty()) "Check where it takes you" else "Use the clean link")
            }
        }
    }
}

/** Each tracking parameter Rift knows in the link: who adds it and what it lets them know. */
@Composable
private fun TrackingExplained(tracking: List<TrackingParam>) {
    if (tracking.isEmpty()) return
    Column(verticalArrangement = Arrangement.spacedBy(4.dp), modifier = Modifier.testTag("tools-tracking")) {
        Text(
            if (tracking.size == 1) "This link carries a tracker. Remove it before you open or share the link:"
            else "This link carries ${tracking.size} trackers. Remove them before you open or share the link:",
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.SemiBold,
        )
        for (param in tracking) {
            Text("${param.name} (${param.who}): ${param.what}", style = MaterialTheme.typography.bodySmall)
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun QuickFixes(address: String, onAddress: (String) -> Unit) {
    val noQuery = remember(address) { linkWithoutQuery(address)?.takeIf { it != address } }
    val https = remember(address) { linkWithHttps(address) }
    if (noQuery == null && https == null) return
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        https?.let { OutlinedButton(onClick = { onAddress(it) }, modifier = Modifier.testTag("tools-https")) { Text("Use HTTPS") } }
        noQuery?.let { OutlinedButton(onClick = { onAddress(it) }, modifier = Modifier.testTag("tools-no-query")) { Text("Remove everything after ?") } }
    }
}

/** Find where it goes: the redirects, each hop with its own check. */
@Composable
private fun Where(check: LinkCheck, trace: LinkTrace?, onTrace: (LinkTrace) -> Unit, onAddress: (String) -> Unit) {
    val scope = rememberCoroutineScope()
    var tracing by remember(check.address) { mutableStateOf(false) }
    if (trace == null) {
        OutlinedButton(
            onClick = {
                tracing = true
                scope.launch {
                    onTrace(withContext(Dispatchers.IO) { Core.trace(check.address) })
                    tracing = false
                }
            },
            enabled = !tracing,
            modifier = Modifier.testTag("tools-trace"),
        ) {
            if (tracing) {
                CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(8.dp))
            }
            Text(if (tracing) "Following its redirects…" else "Find where it goes")
        }
        Text(
            "Rift asks each address where it leads, and opens no page. The link's servers see a request from this phone, " +
                "and a one-time link (a sign-in or reset link) may stop working once followed.",
            style = MaterialTheme.typography.labelSmall,
        )
        return
    }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.testTag("tools-trace-result")) {
        Text("Where it goes", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
        Text(explain(trace), style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("tools-trace-summary"))
        trace.hops.forEachIndexed { i, hop -> Hop(i, hop) }
        Text(ending(trace), style = MaterialTheme.typography.labelSmall, modifier = Modifier.testTag("tools-trace-end"))
        val last = trace.hops.lastOrNull()
        if (trace.outcome is TraceOutcome.Arrived && last != null && trace.hops.size > 1) {
            OutlinedButton(onClick = { onAddress(last.address) }, modifier = Modifier.testTag("tools-trace-use")) { Text("Check where it ends instead") }
        }
    }
}

@Composable
private fun Hop(index: Int, hop: TraceHop) {
    val verdict = verdictOf(hop.check)
    Column(Modifier.testTag("tools-hop-$index")) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                hop.status?.let { "${index + 1}. HTTP $it" } ?: "${index + 1}. not contacted",
                style = MaterialTheme.typography.labelMedium,
                modifier = Modifier.weight(1f),
            )
            Text(
                verdict.title + (hop.check.ai?.takeIf { !it.abstained }?.let { " · AI ${it.score}/100" } ?: ""),
                style = MaterialTheme.typography.labelMedium,
                fontWeight = if (severity(hop.check) > 0) FontWeight.SemiBold else FontWeight.Normal,
                color = if (severity(hop.check) > 0) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.testTag("tools-hop-verdict-$index"),
            )
        }
        Text(hop.check.address, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace,
            maxLines = 2, overflow = TextOverflow.Ellipsis)
    }
}

/**
 * The trace in a sentence, worst first: which hop the risk is at, and what
 * Rift AI saw there, so a harmless-looking short link that leads somewhere
 * else is called out as such.
 */
private fun explain(trace: LinkTrace): String {
    val hops = trace.hops
    val first = hops.firstOrNull() ?: return "Rift could not follow this link."
    if (hops.size == 1) return if (trace.outcome is TraceOutcome.Arrived) "It does not redirect: this is where it goes." else ""
    val worstAt = hops.indices.fold(0) { w, i -> if (severity(hops[i].check) > severity(hops[w].check)) i else w }
    val worst = hops[worstAt]
    val ai = worst.check.ai
    val because = ai?.takeIf { it.level != AiLevel.LOW && !it.abstained }?.let { view ->
        " Rift AI rates it ${view.score}/100" + (view.signals.firstOrNull()?.let { ": $it." } ?: ".")
    } ?: ""
    val where = if (worstAt == hops.lastIndex) "where it ends" else "step ${worstAt + 1} of ${hops.size}"
    return when {
        severity(worst.check) == 0 -> {
            val top = hops.mapNotNull { h -> h.check.ai?.takeIf { !it.abstained }?.score?.toInt() }.maxOrNull()
            "It goes through ${hops.size - 1} redirect${if (hops.size > 2) "s" else ""}, and nothing along the way was flagged." +
                (top?.let { " Rift AI's highest score on the way: $it/100." } ?: "")
        }
        worstAt > 0 && severity(first.check) < severity(worst.check) ->
            "The link itself ${if (severity(first.check) == 0) "looks ordinary" else "has fewer warning signs"}, " +
                "but $where (${host(worst.address)}): ${TITLES[severity(worst.check)]}." + because
        else -> "The worst along the way is $where (${host(worst.address)}): ${TITLES[severity(worst.check)]}." + because
    }
}

/** [verdictOf]'s titles by [severity]. */
private val TITLES = listOf("No known threats found", "Warning signs", "Looks dangerous", "Rift won't open this", "Known malicious")

private fun ending(trace: LinkTrace): String = when (val outcome = trace.outcome) {
    is TraceOutcome.Arrived ->
        "That is where its redirects lead. A page's own scripts can send you further; Rift ran none of them."
    is TraceOutcome.Stopped -> "Rift stopped before the last address and did not contact it."
    is TraceOutcome.LeavesTheWeb -> "Then it tries to open ${outcome.address}, outside the web (an app)." +
        (explainAppLink(outcome.address)?.let { " ${it.does}" } ?: "") + " Rift did not follow it."
    is TraceOutcome.Failed -> "Rift could not go further: ${outcome.reason}."
}

private fun host(address: String): String = Uri.parse(address).host ?: address

private fun copy(context: Context, address: String) {
    context.getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("Link", address))
}

private fun share(context: Context, address: String) {
    val send = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, address)
    context.startActivity(
        Intent.createChooser(send, "Share the link")
            .putExtra(Intent.EXTRA_EXCLUDE_COMPONENTS, arrayOf(ComponentName(context, ShareActivity::class.java))),
    )
}

/** Hands the link to another app, never back to Rift. */
private fun openElsewhere(context: Context, address: String) {
    val view = Intent(Intent.ACTION_VIEW, Uri.parse(address)).addCategory(Intent.CATEGORY_BROWSABLE)
    context.startActivity(
        Intent.createChooser(view, "Open in another app")
            .putExtra(Intent.EXTRA_EXCLUDE_COMPONENTS, arrayOf(ComponentName(context, MainActivity::class.java))),
    )
}
