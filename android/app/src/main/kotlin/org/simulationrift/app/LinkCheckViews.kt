package org.simulationrift.app

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.simulationrift.core.AiLevel
import org.simulationrift.core.AiView
import org.simulationrift.core.Fact
import org.simulationrift.core.LinkCheck
import org.simulationrift.core.Navigation

/*
 * What a link check found, as the home screen's Check and the share popup
 * (ShareActivity) both show it: a verdict, then the threat database, the
 * address checks and Rift AI's score with its reasons. A link with nothing
 * found is never called safe.
 */

/** The headline of a check, most serious finding first. */
internal data class CheckVerdict(
    val container: Color,
    val content: Color,
    val icon: Int,
    val title: String,
    val summary: String,
    /** Whether Rift would load it at all: false for a listed or refused address. */
    val openable: Boolean,
)

@Composable
internal fun verdictOf(check: LinkCheck): CheckVerdict {
    val status = LocalStatusColors.current
    val scheme = MaterialTheme.colorScheme
    val navigation = check.navigation
    val listed = navigation is Navigation.Block && navigation.reason.code == "known-malicious"
    val refused = navigation is Navigation.Block && !listed
    return when {
        listed -> CheckVerdict(scheme.errorContainer, scheme.onErrorContainer, R.drawable.ic_bug, "Known malicious",
            "This link is in the threat database. Rift will not open it.", openable = false)
        refused -> CheckVerdict(status.warningContainer, status.onWarningContainer, R.drawable.ic_warning, "Rift won't open this",
            (navigation as Navigation.Block).reason.text, openable = false)
        check.ai?.level == AiLevel.HIGH -> CheckVerdict(scheme.errorContainer, scheme.onErrorContainer, R.drawable.ic_warning, "Looks dangerous",
            "It looks like the phishing and malware links Rift AI learned from. Do not sign in or pay there.", openable = true)
        navigation is Navigation.Confirm || check.ai?.level == AiLevel.ELEVATED ->
            CheckVerdict(status.warningContainer, status.onWarningContainer, R.drawable.ic_warning, "Warning signs",
                // The main finding, where the address checks made one.
                (navigation as? Navigation.Confirm)?.reasons?.firstOrNull { !it.code.startsWith("ai-") }?.text
                    ?: "Rift AI found things in this address that phishing and malware links share.", openable = true)
        else -> CheckVerdict(scheme.surfaceContainerHigh, scheme.onSurface, R.drawable.ic_info, "No known threats found",
            "Nothing suspicious was found. No check can prove a link is safe.", openable = true)
    }
}

/** The verdict's icon and title. */
@Composable
internal fun CheckHeadline(verdict: CheckVerdict) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(painterResource(verdict.icon), contentDescription = null, modifier = Modifier.size(22.dp))
        Spacer(Modifier.width(10.dp))
        Text(verdict.title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold,
            modifier = Modifier.weight(1f).testTag("check-title"))
    }
}

/** The address, what the address checks and the database found, and Rift AI's meter. */
@Composable
internal fun CheckDetails(check: LinkCheck, verdict: CheckVerdict) {
    val navigation = check.navigation
    val listed = navigation is Navigation.Block && navigation.reason.code == "known-malicious"
    val refused = navigation is Navigation.Block && !listed
    val findings: List<String> = when (navigation) {
        is Navigation.Block -> listOf(navigation.reason.text)
        // The AI's own reason is shown by its meter below.
        is Navigation.Confirm -> navigation.reasons.filterNot { it.code.startsWith("ai-") }.map { it.text } +
            navigation.notes.filterNot { it.code.startsWith("ai-") || it.code.startsWith("intel-") }.map { it.text }
        is Navigation.Proceed -> navigation.notes.filterNot { it.code.startsWith("ai-") || it.code.startsWith("intel-") }.map { it.text }
    }
    val database = when {
        listed -> "Listed in the threat database."
        navigation.notes().any { it.code == "intel-missing" } -> "No threat database is installed, so this link was not looked up in one."
        navigation.notes().any { it.code == "intel-stale" } -> "Not in the threat database, which is out of date."
        else -> "Not in the threat database."
    }
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(check.address, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace,
            maxLines = 3, overflow = TextOverflow.Ellipsis, modifier = Modifier.testTag("check-address"))
        findings.forEachIndexed { i, text ->
            Text("• $text", style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("check-finding-$i"))
        }
        Text(database, style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("check-database"))
        // A refused address is not a web address: there is nothing to score.
        if (check.ai != null || !refused) AiMeter(check.ai)
        Text(
            "Checked on this device in ${formatMicros(check.micros)}. Nothing was opened or sent anywhere." +
                if (verdict.title == "No known threats found") " No check can prove a link is safe: open it in Rift, not your usual browser." else "",
            style = MaterialTheme.typography.labelSmall,
        )
    }
}

/** Rift AI's risk score as a bar, with what raised it. */
@Composable
private fun AiMeter(ai: AiView?) {
    val status = LocalStatusColors.current
    if (ai == null) {
        Text(Core.aiStatus.collectAsState().value?.text ?: "Rift AI is unavailable.", style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.testTag("check-ai-unavailable"))
        return
    }
    if (ai.abstained) {
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("Rift AI", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
            Text(
                "Not scored: this is one of the 10,000 most visited sites, where fakes and real pages look alike to a model of addresses. " +
                    "The threat database still checks every page on it.",
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.testTag("check-ai-abstained"),
            )
        }
        return
    }
    val (color, label) = when (ai.level) {
        AiLevel.HIGH -> MaterialTheme.colorScheme.error to "high risk"
        AiLevel.ELEVATED -> status.warning to "some risk"
        AiLevel.LOW -> status.safe to "nothing it recognises"
    }
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Rift AI", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
            Text("${ai.score}/100 · $label", style = MaterialTheme.typography.labelLarge, modifier = Modifier.testTag("check-ai-score"))
        }
        val track = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.12f)
        Canvas(Modifier.fillMaxWidth().height(8.dp).semantics { contentDescription = "Rift AI risk ${ai.score} of 100" }) {
            val radius = CornerRadius(size.height / 2, size.height / 2)
            drawRoundRect(track, cornerRadius = radius)
            val filled = size.width * (ai.score.toInt().coerceIn(2, 99) / 100f)
            drawRoundRect(color, size = size.copy(width = filled), cornerRadius = radius)
        }
        ai.signals.forEachIndexed { i, signal ->
            Text("• $signal", style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("check-ai-signal-$i"))
        }
        Text(
            "A model of known phishing and malware links, run on this device. A resemblance score, not proof either way.",
            style = MaterialTheme.typography.labelSmall,
        )
    }
}

private fun formatMicros(micros: ULong): String =
    if (micros < 1000u) "$micros µs" else "%.1f ms".format(micros.toDouble() / 1000)

private fun Navigation.notes(): List<Fact> = when (this) {
    is Navigation.Proceed -> notes
    is Navigation.Confirm -> notes
    is Navigation.Block -> emptyList()
}
