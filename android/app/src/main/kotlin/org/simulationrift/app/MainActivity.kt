package org.simulationrift.app

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.TextButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.simulationrift.bridge.PageWatch
import org.simulationrift.bridge.WindowGuard
import org.simulationrift.core.EgressStats
import org.simulationrift.core.IntelStatus
import org.simulationrift.core.ScanStatus
import org.simulationrift.core.VaultEntry
import org.simulationrift.core.VaultProtection
import org.simulationrift.core.Verdict

/** The trusted home screen (main process). */
class MainActivity : ComponentActivity() {

    /** A link handed to Rift by another app, opened once a session is active. */
    private var pendingLink by mutableStateOf<String?>(null)

    /** Android's one-time VPN consent for the network lock (§8.8). */
    private val consent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) NetworkLock.start(this, userAction = true)
    }

    /** A threat-database update the user chose (§13.2): read once, no lasting access to the folder. */
    private val chooseUpdate = registerForActivityResult(ActivityResultContracts.OpenDocumentTree()) { tree ->
        if (tree != null) Core.importIntel(IntelImport.DocumentTree(applicationContext, tree))
    }

    /** Whether the third-party notices (§25) are shown instead of the home screen. */
    private var showingNotices by mutableStateOf(false)

    /** The vault object being exported, while the user chooses where (§11.4). */
    private var exporting: String? = null

    private val exportTo = registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { target ->
        val id = exporting
        exporting = null
        if (id != null && target != null) Locker.export(id, target) else Locker.holding = false
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Core.ensureStarted(this)
        // Silently only if the user consented before and the lock was not
        // taken away since; otherwise the network card asks.
        NetworkLock.start(this, userAction = false)
        // Not when Android recreates the activity (after a crash or a kill):
        // a link handed over before then is not opened again without the user.
        if (savedInstanceState == null) pendingLink = linkFrom(intent)
        // No overlays, autofill, non-tool accessibility services or recents snapshot.
        WindowGuard.apply(this)
        setContent { MaterialTheme { NoPersonalizedLearning { Home() } } }
    }

    override fun onStop() {
        super.onStop()
        // §14.2: the vault locks when Rift goes to the background.
        if (!isChangingConfigurations) Locker.backgrounded()
    }

    private fun turnOnLock() {
        val request = VpnService.prepare(this)
        if (request == null) NetworkLock.start(this, userAction = true) else consent.launch(request)
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

    /** Starts the browser app's window for `generation` (Core.openWindow). */
    private fun browse(generation: Long, input: String?) = Core.openWindow(this, generation, input)

    @Composable
    private fun Home() {
        val state by Core.state.collectAsState()
        val sandbox by Core.sandbox.collectAsState()
        val lock by NetworkLock.state.collectAsState()
        val reduced by Core.reduced.collectAsState()
        // INV-12: while the vault is unlocked, its names and previews stay out
        // of screenshots, screen recordings and casting.
        val vaultOpen = Locker.state.collectAsState().value is Locker.State.Unlocked
        LaunchedEffect(vaultOpen) {
            if (vaultOpen) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE) else window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
        val link = pendingLink
        val active = state as? Core.State.Active
        val mayBrowse = active != null && (lock == NetworkLock.State.Active || reduced == active.generation)
        if (active != null && link != null && mayBrowse) {
            pendingLink = null
            browse(active.generation, link)
        }
        // Test tags double as resource ids so UI tests can find trusted controls.
        Surface(Modifier.fillMaxSize().semantics { testTagsAsResourceId = true }) {
            if (showingNotices) {
                NoticesScreen()
                return@Surface
            }
            Column(
                Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Text("Simulation Rift", style = MaterialTheme.typography.headlineMedium)
                NoticeCard()
                SessionCard(state)
                NetworkCard(lock, active?.generation, reduced)
                if (active != null) {
                    if (mayBrowse) BrowseCard(active.generation)
                    WatchCard(active.generation)
                    DownloadsCard()
                }
                VaultCard()
                IntelCard()
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

    /** The session's live page watch (§10.5), as the browser's bar shows it. */
    @Composable
    private fun WatchCard(generation: Long) {
        val watch by produceState<PageWatch?>(null, generation) {
            while (true) {
                value = withContext(Dispatchers.Default) { Core.pageWatch(generation) }
                delay(STATS_REFRESH_MS)
            }
        }
        val current = watch ?: return
        val level = current.level
        val colors = when (level) {
            PageWatch.Level.DANGER -> CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.error, contentColor = MaterialTheme.colorScheme.onError)
            PageWatch.Level.WARNING -> CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)
            else -> CardDefaults.cardColors()
        }
        Card(Modifier.fillMaxWidth().testTag("watch"), colors = colors) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(
                    when (level) {
                        PageWatch.Level.DANGER -> "Danger in this session"
                        PageWatch.Level.WARNING -> "Warnings in this session"
                        else -> "Nothing suspicious seen so far in this session"
                    },
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.testTag("watch-level"),
                )
                current.events.take(WATCH_SHOWN).forEach { event ->
                    Text((if (event.count > 1) "×${event.count} " else "") + event.text, style = MaterialTheme.typography.bodySmall)
                }
                if (current.events.size > WATCH_SHOWN) {
                    Text("${current.events.size - WATCH_SHOWN} more in the browser's live check.", style = MaterialTheme.typography.bodySmall)
                }
                if (level == PageWatch.Level.DANGER) Text("Reset the session to dispose of everything it holds.")
                current.coverage.forEach { Text(it, style = MaterialTheme.typography.labelSmall) }
            }
        }
    }

    @Composable
    private fun NoticeCard() {
        val notice by Core.notice.collectAsState()
        val text = notice ?: return
        Card(Modifier.fillMaxWidth().testTag("notice"), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(text)
                OutlinedButton(onClick = Core::dismissNotice) { Text("Dismiss") }
            }
        }
    }

    /**
     * The network lock (§8.8): what it is doing, and the user's choices when
     * it cannot run. Reduced isolation is offered only then, for one session.
     */
    @Composable
    private fun NetworkCard(lock: NetworkLock.State, generation: Long?, reduced: Long?) {
        val dropped by NetworkLock.dropped.collectAsState()
        var stats by remember { mutableStateOf<EgressStats?>(null) }
        LaunchedEffect(generation) {
            while (true) {
                // Off the UI thread: it takes the session lock, which a reset holds while it wipes the browser.
                stats = withContext(Dispatchers.IO) { Core.egressStats() }
                delay(STATS_REFRESH_MS)
            }
        }
        val isReduced = generation != null && reduced == generation
        Card(Modifier.fillMaxWidth().testTag("network")) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Browser network", style = MaterialTheme.typography.titleMedium)
                val (summary, problem) = when (lock) {
                    NetworkLock.State.Active -> "Network lock on. The browser has no route to any network; it reaches websites only " +
                        "through Rift's proxy, which refuses local and private addresses." to false
                    NetworkLock.State.Off, NetworkLock.State.Starting -> "Starting the network lock…" to false
                    NetworkLock.State.NeedsConsent -> "The network lock needs Android's VPN permission. Rift's VPN routes nothing " +
                        "anywhere: it only takes away the browser's direct network access, so its one way out is Rift's proxy." to true
                    is NetworkLock.State.Lost -> "The network lock stopped: ${lock.reason}." to true
                    is NetworkLock.State.Unavailable -> "The network lock cannot run: ${lock.reason}." to true
                }
                Text(summary, color = if (problem) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface, modifier = Modifier.testTag("lock-state"))
                if (isReduced) {
                    Text(
                        "This session runs with reduced isolation: pages can reach your local network through WebRTC, " +
                            "and a compromised browser is not limited to Rift's proxy.",
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.testTag("reduced-session"),
                    )
                }
                if (problem) {
                    Button(onClick = ::turnOnLock, modifier = Modifier.testTag("lock-on")) { Text("Turn on the network lock") }
                    if (generation != null && !isReduced) {
                        Text(
                            "If you need another VPN, you can browse this one session with reduced isolation instead.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                        OutlinedButton(onClick = { Core.useReducedIsolation(generation) }, modifier = Modifier.testTag("use-reduced")) {
                            Text("Reduced isolation for this session")
                        }
                    }
                }
                if (lock == NetworkLock.State.Active && dropped.packets > 0) {
                    Text(
                        "Dropped by the lock: ${dropped.packets} packets, to " + dropped.destinations.take(6).joinToString() +
                            (if (dropped.destinations.size > 6) ", …" else ""),
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.testTag("lock-dropped"),
                    )
                }
                stats?.let { s ->
                    Text(
                        "Proxy this session: ${s.allowed} connections allowed, ${s.denied} refused.",
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.testTag("egress"),
                    )
                    s.recent.takeLast(5).forEach { d -> Text("Refused ${d.destination}: ${d.reason}", style = MaterialTheme.typography.bodySmall) }
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
                    modifier = Modifier.noAutofill().fillMaxWidth().testTag("home-address"),
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
        val verdicts by Core.verdicts.collectAsState()
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
                    if (file != null) {
                        VerdictArea(file.id, verdicts.containsKey(file.id), verdicts[file.id])
                        PreviewArea(file.id, file.displayName, previews[file.id])
                        KeepArea(file.id)
                    }
                }
                Text("Local network hosts allowed for downloads in this session: " + localHosts.ifEmpty { listOf("none") }.joinToString())
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = host,
                        onValueChange = { host = it },
                        label = { Text("Host name") },
                        singleLine = true,
                        modifier = Modifier.noAutofill().weight(1f).testTag("local-host"),
                    )
                    OutlinedButton(onClick = {
                        Core.allowLocalHost(host)
                        host = ""
                    }) { Text("Allow") }
                }
            }
        }
    }

    /** Keeping a quarantined file after the session: only into an unlocked vault, and never automatically. */
    @Composable
    private fun KeepArea(fileId: String) {
        val vault by Locker.state.collectAsState()
        val kept by Locker.kept.collectAsState()
        when {
            fileId in kept -> Text("Kept in the vault.", style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("kept-$fileId"))
            vault is Locker.State.Unlocked -> OutlinedButton(onClick = { Core.keep(fileId) }, modifier = Modifier.testTag("keep-$fileId")) {
                Text("Keep in the vault")
            }
            else -> Text("To keep this file after the session, unlock the vault.", style = MaterialTheme.typography.bodySmall)
        }
    }

    /**
     * The Rift Vault (§14): create, unlock and lock it, and export or remove
     * what was kept. Export is warned and goes only where the user chooses.
     */
    @Composable
    private fun VaultCard() {
        val state by Locker.state.collectAsState()
        val message by Locker.message.collectAsState()
        var passphrase by remember { mutableStateOf("") }
        var deleting by remember { mutableStateOf(false) }
        // Compose keeps text as an immutable String, so this copy cannot be
        // overwritten; the field is cleared as soon as the passphrase is used.
        fun takePassphrase(): ByteArray = passphrase.encodeToByteArray().also { passphrase = "" }

        @Composable
        fun PassphraseField(label: String) = OutlinedTextField(
            value = passphrase,
            onValueChange = { passphrase = it },
            label = { Text(label) },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false),
            modifier = Modifier.noAutofill().fillMaxWidth().testTag("vault-passphrase"),
        )

        Card(Modifier.fillMaxWidth().testTag("vault")) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Vault", style = MaterialTheme.typography.titleMedium)
                when (val s = state) {
                    Locker.State.Opening -> Text("Opening…")
                    is Locker.State.Failed -> Text("The vault cannot be used: ${s.message}", color = MaterialTheme.colorScheme.error)
                    is Locker.State.Absent -> {
                        Text(
                            "Files you keep from a session are stored here, encrypted, after the session ends. " +
                                "They stay the original, untrusted files.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                        if (s.deviceSecure) {
                            Button(onClick = { Locker.createWithDeviceLock(this@MainActivity) }, modifier = Modifier.testTag("vault-create-device")) {
                                Text("Create, protected by the screen lock")
                            }
                            Text(
                                "The key stays in this device's keystore. If the screen lock is removed or new fingerprints " +
                                    "or faces are enrolled, Android deletes the key, and only a recovery passphrase (set after " +
                                    "creating the vault) can open it again.",
                                style = MaterialTheme.typography.bodySmall,
                            )
                            Text("Or protect it with a passphrase:", style = MaterialTheme.typography.bodySmall)
                        } else {
                            Text(
                                "This device has no secure screen lock, so the key cannot be kept in its keystore. " +
                                    "Choose a passphrase of at least 10 characters; without it the vault cannot be opened.",
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                        PassphraseField("New passphrase")
                        OutlinedButton(onClick = { Locker.createWithPassphrase(takePassphrase()) }, modifier = Modifier.testTag("vault-create-passphrase")) {
                            Text("Create with this passphrase")
                        }
                    }
                    is Locker.State.Locked -> {
                        Text("Locked.", modifier = Modifier.testTag("vault-locked"))
                        if (s.protection == VaultProtection.PLATFORM) {
                            Button(onClick = { Locker.unlockWithDeviceLock(this@MainActivity) }, modifier = Modifier.testTag("vault-unlock-device")) {
                                Text("Unlock")
                            }
                            if (s.recovery) {
                                PassphraseField("Recovery passphrase")
                                OutlinedButton(onClick = { Locker.unlockWithRecovery(takePassphrase()) }, modifier = Modifier.testTag("vault-unlock-recovery")) {
                                    Text("Unlock with the recovery passphrase")
                                }
                            }
                        } else {
                            PassphraseField("Passphrase")
                            Button(onClick = { Locker.unlockWithPassphrase(takePassphrase()) }, modifier = Modifier.testTag("vault-unlock-passphrase")) {
                                Text("Unlock")
                            }
                        }
                    }
                    is Locker.State.Unlocked -> {
                        val policy by Locker.policy.collectAsState()
                        Text(
                            "Unlocked" + (s.keyLevel?.let { " · key in $it" } ?: "") + ". Locks " +
                                (if (policy.onBackground) "when Rift goes to the background, or " else "") +
                                "after ${policy.idleMinutes} min without use.",
                            modifier = Modifier.testTag("vault-unlocked"),
                        )
                        if (s.protection == VaultProtection.PLATFORM) RecoveryArea(s, { PassphraseField(it) }, { takePassphrase() })
                        if (s.entries.isEmpty()) Text("Nothing kept yet.")
                        s.entries.forEach { VaultItem(it) }
                        OutlinedButton(onClick = { Locker.lock() }, modifier = Modifier.testTag("vault-lock")) { Text("Lock now") }
                        LockPolicyArea()
                    }
                }
                message?.let { Text(it, style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("vault-message")) }
                if (state is Locker.State.Locked || state is Locker.State.Unlocked) {
                    if (!deleting) {
                        OutlinedButton(onClick = { deleting = true }, modifier = Modifier.testTag("vault-delete")) { Text("Delete the vault…") }
                    } else {
                        Text(
                            "Delete the vault and every file in it? This cannot be undone.",
                            color = MaterialTheme.colorScheme.error,
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(onClick = {
                                deleting = false
                                Locker.destroy()
                            }, modifier = Modifier.testTag("vault-delete-confirm")) { Text("Delete") }
                            OutlinedButton(onClick = { deleting = false }) { Text("Cancel") }
                        }
                    }
                }
            }
        }
    }

    /** The recovery passphrase of a platform vault, and protecting it again after the key was lost (§8.7). */
    @Composable
    private fun RecoveryArea(s: Locker.State.Unlocked, field: @Composable (String) -> Unit, take: () -> ByteArray) {
        if (s.keyLevel == null) {
            Text(
                "This device's key for the vault is gone, so it was opened with the recovery passphrase.",
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.testTag("vault-key-gone"),
            )
            if (VaultKeystore.deviceSecure(this)) {
                Button(onClick = { Locker.protectAgain(this@MainActivity) }, modifier = Modifier.testTag("vault-protect-again")) {
                    Text("Protect with the screen lock again")
                }
            }
        }
        if (s.recovery) {
            Text("A recovery passphrase is set.", style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("vault-recovery-set"))
        } else {
            Text(
                "No recovery passphrase: if this device's key is lost, so is everything in the vault.",
                style = MaterialTheme.typography.bodySmall,
            )
            field("Recovery passphrase (at least 10 characters)")
            OutlinedButton(onClick = { Locker.setRecoveryPassphrase(take()) }, modifier = Modifier.testTag("vault-set-recovery")) {
                Text("Set a recovery passphrase")
            }
        }
    }

    @Composable
    private fun VaultItem(entry: VaultEntry) {
        var warning by remember { mutableStateOf(false) }
        val previews by Locker.previews.collectAsState()
        val rescanning by Locker.rescanning.collectAsState()
        val database by Core.intel.collectAsState()
        Column(Modifier.testTag("vault-entry-${entry.id}"), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                "${entry.displayName} · ${entry.size} bytes · sha256 ${entry.sha256.take(16)}…" +
                    (entry.sourceUrl?.let { "\nfrom $it" } ?: "") +
                    "\nkept ${java.text.DateFormat.getDateTimeInstance().format(java.util.Date(entry.createdUnix.toLong() * 1000))}",
                style = MaterialTheme.typography.bodySmall,
            )
            val scan = entry.scan
            Text(
                if (scan == null) {
                    "Not scanned yet."
                } else {
                    "Last scan, ${java.text.DateFormat.getDateTimeInstance().format(java.util.Date(scan.scannedUnix.toLong() * 1000))}: ${scan.label}" + (scan.findings.takeIf { it.isNotEmpty() }?.joinToString(prefix = " (", postfix = ")") ?: "") +
                        " · ${scan.snapshot?.let { "database $it" } ?: "no threat database"} · ${scan.engine}" +
                        (if (scan.demo) " · DEMO database, not real coverage" else "") +
                        ". A past result, not a current scan."
                },
                style = MaterialTheme.typography.bodySmall,
                color = when (scan?.status) {
                    ScanStatus.KNOWN_MALICIOUS, ScanStatus.SUSPICIOUS -> MaterialTheme.colorScheme.error
                    else -> MaterialTheme.colorScheme.onSurface
                },
                modifier = Modifier.testTag("vault-scan-${entry.id}"),
            )
            if (warning) {
                Text(
                    "The exported copy leaves Rift's protection. It is the original file, not made safe: " +
                        "opening it in another app is not isolated.",
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = {
                        warning = false
                        exporting = entry.id
                        Locker.holding = true
                        exportTo.launch(entry.displayName)
                    }, modifier = Modifier.testTag("vault-export-confirm-${entry.id}")) { Text("Export anyway") }
                    OutlinedButton(onClick = { warning = false }) { Text("Cancel") }
                }
            } else {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { warning = true }, modifier = Modifier.testTag("vault-export-${entry.id}")) { Text("Export…") }
                    OutlinedButton(onClick = { Locker.remove(entry.id) }, modifier = Modifier.testTag("vault-remove-${entry.id}")) { Text("Remove") }
                }
                when {
                    entry.id in rescanning -> Text("Checking in an isolated worker…", style = MaterialTheme.typography.bodySmall)
                    database is IntelStatus.Installed -> OutlinedButton(
                        onClick = { Locker.rescan(entry.id) },
                        modifier = Modifier.testTag("vault-rescan-${entry.id}"),
                    ) { Text("Scan with the current database") }
                }
            }
            PreviewArea(entry.id, entry.displayName, previews[entry.id]) { Locker.preview(entry.id) }
        }
    }

    /** §14.2: when the vault locks besides on request. Shown only while it is unlocked. */
    @Composable
    private fun LockPolicyArea() {
        val policy by Locker.policy.collectAsState()
        var open by remember { mutableStateOf(false) }
        if (!open) {
            TextButton(onClick = { open = true }, modifier = Modifier.testTag("vault-policy")) { Text("Lock settings…") }
            return
        }
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Switch(
                    checked = policy.onBackground,
                    onCheckedChange = { Locker.setPolicy(policy.copy(onBackground = it)) },
                    modifier = Modifier.testTag("vault-policy-background"),
                )
                Text("Lock when Rift goes to the background", style = MaterialTheme.typography.bodySmall)
            }
            if (!policy.onBackground) {
                Text(
                    "While Rift is in the background the vault stays unlocked until the time below, and anyone " +
                        "who opens Rift on this unlocked device in that time can read it.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            Text("Lock after this many minutes without a vault action:", style = MaterialTheme.typography.bodySmall)
            // Compact, so that four choices fit a small screen.
            val padding = PaddingValues(horizontal = 12.dp)
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                Locker.LockPolicy.IDLE_CHOICES.forEach { minutes ->
                    val choose = { Locker.setPolicy(policy.copy(idleMinutes = minutes)) }
                    val tag = Modifier.testTag("vault-policy-idle-$minutes")
                    if (minutes == policy.idleMinutes) Button(onClick = choose, modifier = tag, contentPadding = padding) { Text("$minutes") }
                    else OutlinedButton(onClick = choose, modifier = tag, contentPadding = padding) { Text("$minutes") }
                }
            }
        }
    }

    /** The scan result as rift-core decided it: never "safe", always with its coverage. */
    @Composable
    private fun VerdictArea(fileId: String, requested: Boolean, verdict: Verdict?) {
        when {
            !requested -> OutlinedButton(onClick = { Core.scan(fileId) }, modifier = Modifier.testTag("scan-$fileId")) { Text("Scan") }
            verdict == null -> Text("Checking in an isolated worker…", modifier = Modifier.testTag("scanning-$fileId"))
            else -> Column(Modifier.testTag("verdict-$fileId"), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                val color = when (verdict.status) {
                    ScanStatus.KNOWN_MALICIOUS, ScanStatus.SUSPICIOUS -> MaterialTheme.colorScheme.error
                    ScanStatus.NOT_FLAGGED, ScanStatus.NOT_FULLY_SCANNED -> MaterialTheme.colorScheme.onSurface
                }
                Text(verdict.label, style = MaterialTheme.typography.titleSmall, color = color, modifier = Modifier.testTag("verdict-label-$fileId"))
                verdict.findings.forEach { f ->
                    Text(
                        "${f.description} (${f.check}: ${f.id}, ${if (f.highConfidence) "high" else "low"} confidence, source ${f.source})",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                verdict.gaps.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
                val basis = verdict.snapshot?.let { "Database $it" + (if (verdict.stale) " (out of date)" else "") } ?: "No threat database"
                Text(
                    "$basis · ${verdict.engine}" + (if (verdict.demo) " · DEMO database, not real coverage" else "") +
                        (if (verdict.status == ScanStatus.NOT_FLAGGED) " · not flagged is not a guarantee that the file is safe" else ""),
                    style = MaterialTheme.typography.bodySmall,
                )
                OutlinedButton(onClick = { Core.scan(fileId) }) { Text("Scan again") }
            }
        }
    }

    @Composable
    private fun IntelCard() {
        val status by Core.intel.collectAsState()
        val message by Core.intelMessage.collectAsState()
        val canImport = remember { Core.trustedRoot() != null }
        val source = remember { Core.updateSource() }
        Card(Modifier.fillMaxWidth().testTag("intel")) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("Threat database", style = MaterialTheme.typography.titleMedium)
                Text(
                    when (val s = status) {
                        null -> "Opening…"
                        is IntelStatus.Missing -> "None installed. Files are checked for type only, and say what was not checked."
                        is IntelStatus.Damaged -> "The installed database is damaged and is not used: ${s.detail}"
                        is IntelStatus.Installed -> "${s.snapshot}" + (if (s.demo) " · DEMO, not real coverage" else "") +
                            (if (s.stale) " · out of date, still used offline" else "")
                    },
                    modifier = Modifier.testTag("intel-status"),
                )
                if ((status as? IntelStatus.Installed)?.clockBehind == true) {
                    Text(
                        "This device's clock reads earlier than the database was made, so its expiry dates cannot be checked. Check the date and time in Settings.",
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.testTag("intel-clock"),
                    )
                }
                (status as? IntelStatus.Installed)?.notices?.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
                message?.let { Text(it, style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("intel-message")) }
                if (canImport && source != null) {
                    OutlinedButton(onClick = { Core.updateIntelOnline(source) }, modifier = Modifier.testTag("intel-online")) {
                        Text("Check for an update")
                    }
                }
                if (canImport) {
                    OutlinedButton(onClick = { chooseUpdate.launch(null) }, modifier = Modifier.testTag("intel-import")) {
                        Text("Import an update folder…")
                    }
                } else {
                    Text("This build has no trusted root, so it cannot install updates.", style = MaterialTheme.typography.bodySmall)
                }
                if (Core.demoIntelAvailable()) {
                    OutlinedButton(onClick = { Core.installDemoIntel() }, modifier = Modifier.testTag("intel-demo")) {
                        Text("Install the signed demo database")
                    }
                }
            }
        }
    }

    @Composable
    private fun PreviewArea(fileId: String, name: String, preview: Core.Preview?, start: () -> Unit = { Core.preview(fileId) }) {
        val bitmap = preview?.bitmap
        when {
            preview == null -> OutlinedButton(onClick = start, modifier = Modifier.testTag("preview-$fileId")) {
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

    private companion object {
        const val STATS_REFRESH_MS = 1_000L
        const val WATCH_SHOWN = 5
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
                val network by Core.network.collectAsState()
                Text(
                    network?.let { "Browser network: ${it.detail}" } ?: "Browser network: checked when the browser starts.",
                    modifier = Modifier.testTag("network-report"),
                )
                Text("Checked: addresses you type, links opened in Rift, and main-frame navigations the engine reports.")
                Text("Not checked: subresources, frames, WebSockets, WebRTC, service-worker fetches and form posts (§10.3).")
                Text("All of those still go through Rift's proxy, which refuses local and private addresses.")
                Text("Address checks use a built-in list; the threat database is used for downloaded files.")
                Text("Safe Browsing is off, so no addresses or hashes are sent to Google.")
                TextButton(onClick = { showingNotices = true }, modifier = Modifier.testTag("notices-open")) {
                    Text("Open-source licences")
                }
            }
        }
    }

    /**
     * The third-party notices (§25): this APK's Android libraries, the Rust
     * crates in its native libraries, and the Apache License, as build.sh and
     * notices.gradle.kts wrote them into the assets. One item per line, so
     * the long texts are laid out only as they scroll into view.
     */
    @Composable
    private fun NoticesScreen() {
        BackHandler { showingNotices = false }
        val lines by produceState<List<String>?>(null) {
            value = withContext(Dispatchers.IO) {
                NOTICE_FILES.flatMap { name ->
                    val text = runCatching { assets.open("notices/$name").bufferedReader().use { it.readLines() } }
                    text.getOrElse { listOf("($name is missing from this build: build it with android/build.sh.)") } + listOf("", "")
                }
            }
        }
        LazyColumn(
            Modifier.fillMaxSize().safeDrawingPadding().padding(horizontal = 16.dp).testTag("notices"),
            contentPadding = PaddingValues(vertical = 16.dp),
        ) {
            item {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(onClick = { showingNotices = false }, modifier = Modifier.testTag("notices-close")) { Text("Back") }
                    Text("Open-source licences", style = MaterialTheme.typography.headlineSmall)
                    Text(
                        "Simulation-Rift is licensed under MIT OR Apache-2.0. It includes the third-party software below, " +
                            "under the licences shown.",
                    )
                }
            }
            items(lines ?: listOf("Loading…")) { line ->
                Text(line, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

/** The notice assets, in the order shown. */
private val NOTICE_FILES = listOf("android-libraries.txt", "rust-crates.txt", "apache-2.0.txt")
