package org.simulationrift.app

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.unit.dp

/** The trusted home screen (main process). */
class MainActivity : ComponentActivity() {

    /** A link handed to Rift by another app, opened once a session is active. */
    private var pendingLink by mutableStateOf<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Core.ensureStarted(this)
        pendingLink = linkFrom(intent)
        setContent { MaterialTheme { Home() } }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        linkFrom(intent)?.let { pendingLink = it }
    }

    /** ACTION_VIEW http(s) links and shared text (§8.2); the core checks them before loading. */
    private fun linkFrom(intent: Intent): String? = when (intent.action) {
        Intent.ACTION_VIEW -> intent.dataString
        Intent.ACTION_SEND -> intent.getStringExtra(Intent.EXTRA_TEXT)?.trim()?.takeIf { it.isNotEmpty() }
        else -> null
    }

    private fun browse(generation: Long, input: String?) {
        startActivity(
            Intent(this, BrowserActivity::class.java)
                .putExtra(BrowserActivity.EXTRA_GENERATION, generation)
                .apply { input?.let { putExtra(BrowserActivity.EXTRA_URL, it) } },
        )
    }

    @Composable
    private fun Home() {
        val state by Core.state.collectAsState()
        val sandbox by Core.sandbox.collectAsState()
        val link = pendingLink
        val active = state as? Core.State.Active
        if (active != null && link != null) {
            pendingLink = null
            browse(active.generation, link)
        }
        // Test tags double as resource ids so UI tests can find trusted controls.
        Surface(Modifier.fillMaxSize().semantics { testTagsAsResourceId = true }) {
            Column(
                Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Text("Simulation Rift", style = MaterialTheme.typography.headlineMedium)
                SessionCard(state)
                if (active != null) {
                    BrowseCard(active.generation)
                    DownloadsCard()
                }
                DiagnosticsCard(sandbox)
            }
        }
    }

    @Composable
    private fun SessionCard(state: Core.State) {
        Card(Modifier.fillMaxWidth().testTag("session")) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                when (state) {
                    Core.State.Opening -> Text("Preparing a fresh session…")
                    is Core.State.Active -> {
                        Text("Session ${state.generation} active", style = MaterialTheme.typography.titleMedium)
                        state.recovered?.let {
                            Text(
                                "Session $it was interrupted. Its browsing data was deleted before this session started.",
                                modifier = Modifier.testTag("recovered"),
                            )
                        }
                        OutlinedButton(onClick = { Core.reset(state.generation) }, modifier = Modifier.testTag("reset")) {
                            Text("Reset session")
                        }
                    }
                    is Core.State.Resetting -> Text("Destroying session ${state.generation}…")
                    is Core.State.Failed -> {
                        Text("Session cleanup failed", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.error)
                        Text(state.message, modifier = Modifier.testTag("failure"))
                        Text("No new session starts until cleanup succeeds.")
                        Button(onClick = Core::retry) { Text("Retry cleanup") }
                    }
                }
            }
        }
    }

    @Composable
    private fun BrowseCard(generation: Long) {
        var typed by remember { mutableStateOf("") }
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = typed,
                    onValueChange = { typed = it },
                    label = { Text("Address") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag("home-address"),
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { browse(generation, typed.takeIf { it.isNotBlank() }) }, modifier = Modifier.testTag("browse")) {
                        Text("Browse")
                    }
                }
            }
        }
    }

    @Composable
    private fun DownloadsCard() {
        val downloads by Core.downloads.collectAsState()
        val localHosts by Core.localHosts.collectAsState()
        val previews by Core.previews.collectAsState()
        var host by remember { mutableStateOf("") }
        Card(Modifier.fillMaxWidth().testTag("downloads")) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Quarantine (this session)", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Downloads are fetched again by Rift, encrypted with this session's key, and deleted at reset. " +
                        "Downloads created inside a page (blob: and data:) cannot be captured.",
                    style = MaterialTheme.typography.bodySmall,
                )
                if (downloads.isEmpty()) Text("No downloads yet.")
                downloads.forEach { d ->
                    val file = d.file
                    val text = when {
                        file != null -> "${file.displayName} · ${file.size} bytes · sha256 ${file.sha256.take(16)}…\nfrom ${file.source}" +
                            (file.contentType?.let { " · labelled $it" } ?: "")
                        d.failure != null -> "Not captured: ${d.failure}\n${d.url}"
                        else -> "Fetching ${d.url}…"
                    }
                    Text(text, modifier = Modifier.testTag("download-${d.key}"))
                    if (file != null) PreviewArea(file.id, file.displayName, previews[file.id])
                }
                Text("Local network hosts allowed for downloads in this session: " + localHosts.ifEmpty { listOf("none") }.joinToString())
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = host,
                        onValueChange = { host = it },
                        label = { Text("Host name") },
                        singleLine = true,
                        modifier = Modifier.weight(1f).testTag("local-host"),
                    )
                    OutlinedButton(onClick = {
                        Core.allowLocalHost(host)
                        host = ""
                    }) { Text("Allow") }
                }
            }
        }
    }

    @Composable
    private fun PreviewArea(fileId: String, name: String, preview: Core.Preview?) {
        val bitmap = preview?.bitmap
        when {
            preview == null -> OutlinedButton(onClick = { Core.preview(fileId) }, modifier = Modifier.testTag("preview-$fileId")) {
                Text("Preview")
            }
            preview.running -> Text("Rendering in an isolated worker…")
            bitmap != null -> {
                val image = remember(bitmap) { bitmap.asImageBitmap() }
                Image(
                    image,
                    contentDescription = "Preview of $name",
                    modifier = Modifier.fillMaxWidth().heightIn(max = 480.dp).testTag("preview-image-$fileId"),
                )
                Text(
                    "A picture rendered by an isolated worker: no scripts, links or network. ${bitmap.width}×${bitmap.height}.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            preview.text != null -> {
                Text(
                    preview.text,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.fillMaxWidth().heightIn(max = 320.dp).verticalScroll(rememberScrollState()).testTag("preview-text-$fileId"),
                )
                preview.note?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            }
            else -> Text("Preview unavailable: ${preview.failure}", modifier = Modifier.testTag("preview-failure-$fileId"))
        }
    }

    @Composable
    private fun DiagnosticsCard(sandbox: SandboxReport?) {
        Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("Protection coverage", style = MaterialTheme.typography.titleSmall)
                Text(
                    sandbox?.let { (if (it.verified) "Renderer sandbox confirmed: " else "Renderer sandbox NOT confirmed: ") + it.detail }
                        ?: "Renderer sandbox: checked when the browser starts.",
                    modifier = Modifier.testTag("sandbox"),
                )
                Text("Checked: addresses you type, links opened in Rift, and main-frame navigations the engine reports.")
                Text("Not checked: subresources, frames, WebSockets, WebRTC, service-worker fetches and form posts (§10.3).")
                Text("No threat database is installed yet; only the built-in address checks run.")
                Text("Safe Browsing is off, so no addresses or hashes are sent to Google.")
            }
        }
    }
}
