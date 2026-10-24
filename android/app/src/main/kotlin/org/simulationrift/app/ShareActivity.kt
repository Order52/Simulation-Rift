package org.simulationrift.app

import android.content.ClipData
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.MutableTransitionState
import androidx.compose.animation.fadeIn
import androidx.compose.animation.slideInVertically
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.IntentCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.simulationrift.bridge.WindowGuard
import org.simulationrift.core.LinkCheck
import org.simulationrift.core.LinkTrace

/**
 * Rift's share target (§10.1). A link shared to Rift is checked at once, on
 * the device, and the verdict is shown in a sheet over the app it came
 * from: what was found, on request, and "Open safely", which hands it to
 * the home screen to open in a session's sealed browser. Nothing is loaded
 * before that. A shared file goes to the home screen, which quarantines it.
 */
class ShareActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        Core.ensureStarted(this)
        // No overlays, autofill, non-tool accessibility services or recents snapshot.
        WindowGuard.apply(this)
        receive(intent)
    }

    /** Another share while the sheet is up replaces it. */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        receive(intent)
    }

    private fun receive(intent: Intent) {
        val file = IntentCompat.getParcelableExtra(intent, Intent.EXTRA_STREAM, Uri::class.java)
        if (file != null) {
            // The read grant goes with it: the home screen takes the file in
            // once a session is active, after this activity has gone.
            startActivity(
                Intent(this, MainActivity::class.java)
                    .setAction(Intent.ACTION_SEND)
                    .setType(intent.type)
                    .putExtra(Intent.EXTRA_STREAM, file)
                    .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    .apply { clipData = ClipData.newRawUri(null, file) },
            )
            finish()
            return
        }
        val text = intent.getStringExtra(Intent.EXTRA_TEXT).orEmpty()
        setContent { RiftTheme { NoPersonalizedLearning { Sheet(text) } } }
    }

    private fun open(address: String) {
        startActivity(Intent(this, MainActivity::class.java).setAction(Intent.ACTION_VIEW).setData(Uri.parse(address)))
        finish()
    }

    /**
     * A sheet drawn in this activity's own window, not a dialog's, so the
     * window guard (no overlays over it) covers the verdict too.
     */
    @Composable
    private fun Sheet(text: String) {
        // The link tools can put another address in place of the shared one (§10.10).
        var input by remember(text) { mutableStateOf(text) }
        val earlier = remember(text) { mutableStateListOf<String>() }
        var trace by remember(input) { mutableStateOf<LinkTrace?>(null) }
        val check by produceState<LinkCheck?>(null, input) {
            value = null
            value = withContext(Dispatchers.Default) { Core.checkWhenOpened(input) }
        }
        var details by rememberSaveable { mutableStateOf(false) }
        val shown = remember { MutableTransitionState(false).apply { targetState = true } }
        Box(
            Modifier.fillMaxSize().background(Color.Black.copy(alpha = 0.32f))
                .pointerInput(Unit) { detectTapGestures { finish() } }
                .semantics { testTagsAsResourceId = true },
            contentAlignment = Alignment.BottomCenter,
        ) {
            AnimatedVisibility(shown, enter = slideInVertically { it } + fadeIn()) {
                Surface(
                    shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp),
                    color = MaterialTheme.colorScheme.surfaceContainerLow,
                    // Taps on the sheet stay on it.
                    modifier = Modifier.fillMaxWidth().pointerInput(Unit) { detectTapGestures { } }.testTag("share-sheet"),
                ) {
                    Column(
                        Modifier.fillMaxWidth().navigationBarsPadding().verticalScroll(rememberScrollState())
                            .padding(start = 20.dp, end = 20.dp, top = 12.dp, bottom = 20.dp),
                        verticalArrangement = Arrangement.spacedBy(14.dp),
                    ) {
                        Box(
                            Modifier.align(Alignment.CenterHorizontally).size(width = 32.dp, height = 4.dp).clip(CircleShape)
                                .background(MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f)),
                        )
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Image(painterResource(org.simulationrift.bridge.R.drawable.rift_mark), contentDescription = null, modifier = Modifier.size(28.dp))
                            Spacer(Modifier.width(10.dp))
                            Text("Rift link check", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                        }
                        val current = check
                        if (current == null) {
                            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.testTag("share-checking")) {
                                CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                                Spacer(Modifier.width(12.dp))
                                Text("Checking on this device…", style = MaterialTheme.typography.bodyMedium)
                            }
                            return@Column
                        }
                        val worst = worstOf(current, trace)
                        val verdict = verdictOf(worst)
                        Surface(
                            color = verdict.container,
                            contentColor = verdict.content,
                            shape = RoundedCornerShape(20.dp),
                            modifier = Modifier.fillMaxWidth().testTag("share-verdict"),
                        ) {
                            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                CheckHeadline(verdict)
                                Text(
                                    if (worst !== current) "Where it goes: ${verdict.summary}" else verdict.summary,
                                    style = MaterialTheme.typography.bodyMedium,
                                    modifier = Modifier.testTag("share-summary"),
                                )
                                if (!details) {
                                    Text(current.address, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace,
                                        maxLines = 2, overflow = TextOverflow.Ellipsis)
                                }
                            }
                        }
                        if (details) {
                            Surface(
                                color = MaterialTheme.colorScheme.surfaceContainerHigh,
                                shape = RoundedCornerShape(20.dp),
                                modifier = Modifier.fillMaxWidth().animateContentSize().testTag("share-details"),
                            ) {
                                Column(Modifier.padding(16.dp)) { CheckDetails(current, verdictOf(current)) }
                            }
                        }
                        val worrying = verdict.title != "No known threats found"
                        TextButton(onClick = { details = !details }, modifier = Modifier.testTag("share-why")) {
                            Text(
                                when {
                                    details -> "Hide details"
                                    worrying -> "See what's wrong"
                                    else -> "See what was checked"
                                },
                            )
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            OutlinedButton(onClick = ::finish, modifier = Modifier.weight(1f).height(52.dp).testTag("share-close")) { Text("Close") }
                            if (verdict.openable) {
                                Button(
                                    onClick = { open(current.address) },
                                    modifier = Modifier.weight(1.3f).height(52.dp).testTag("share-open"),
                                ) {
                                    Icon(painterResource(R.drawable.ic_lock), contentDescription = null, modifier = Modifier.size(18.dp))
                                    Spacer(Modifier.width(8.dp))
                                    Text(verdict.openLabel, maxLines = 1)
                                }
                            }
                        }
                        Text(
                            if (verdict.openable) "${verdict.openLabel} loads it in Rift's sealed browser, in a fresh session, behind the network lock. Nothing has been opened yet."
                            else "Nothing has been opened.",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        // The tools come after the verdict's own buttons, which stay in view.
                        Surface(
                            color = MaterialTheme.colorScheme.surfaceContainerHigh,
                            shape = RoundedCornerShape(20.dp),
                            modifier = Modifier.fillMaxWidth().animateContentSize(),
                        ) {
                            Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
                                LinkTools(
                                    current, trace, onTrace = { trace = it },
                                    onAddress = { earlier.add(input); input = it },
                                    onUndo = earlier.lastOrNull()?.let { before -> { earlier.removeAt(earlier.lastIndex); input = before } },
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
