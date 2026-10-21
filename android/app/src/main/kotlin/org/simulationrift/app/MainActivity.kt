package org.simulationrift.app

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.text.format.Formatter
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import java.text.NumberFormat
import java.time.LocalDate
import java.time.format.TextStyle
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.simulationrift.bridge.PageWatch
import org.simulationrift.bridge.WindowGuard
import org.simulationrift.core.EgressStats
import org.simulationrift.core.IntelStatus
import org.simulationrift.core.ScanStatus
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

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        Core.ensureStarted(this)
        // Silently only if the user consented before and the lock was not
        // taken away since; otherwise the home screen asks.
        NetworkLock.start(this, userAction = false)
        // Not when Android recreates the activity (after a crash or a kill):
        // a link handed over before then is not opened again without the user.
        if (savedInstanceState == null) pendingLink = linkFrom(intent)
        // No overlays, autofill, non-tool accessibility services or recents snapshot.
        WindowGuard.apply(this)
        setContent { RiftTheme { NoPersonalizedLearning { Home() } } }
    }

    override fun onResume() {
        super.onResume()
        // The week may have moved on while Rift was in the background.
        WeeklyStats.refresh()
    }

    private fun turnOnLock() {
        val request = VpnService.prepare(this)
        if (request == null) NetworkLock.start(this, userAction = true) else consent.launch(request)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        linkFrom(intent)?.let { pendingLink = it }
    }

    /**
     * ACTION_VIEW links and shared text (§8.2), as the address to load: the
     * first link in shared text, in the form the engine will load. The core
     * checks it before loading.
     */
    private fun linkFrom(intent: Intent): String? = when (intent.action) {
        Intent.ACTION_VIEW -> intent.dataString
        Intent.ACTION_SEND -> intent.getStringExtra(Intent.EXTRA_TEXT)
        else -> null
    }?.takeIf { it.isNotBlank() }?.let(Core::typed)

    /** Starts the browser app's window for `generation` (Core.openWindow). */
    private fun browse(generation: Long, input: String?) = Core.openWindow(this, generation, input)

    @Composable
    private fun Home() {
        val state by Core.state.collectAsState()
        val lock by NetworkLock.state.collectAsState()
        val reduced by Core.reduced.collectAsState()
        val link = pendingLink
        val active = state as? Core.State.Active
        val mayBrowse = active != null && (lock == NetworkLock.State.Active || reduced == active.generation)
        if (active != null && link != null && mayBrowse) {
            if (Core.hasBrowsed(active.generation)) {
                // A link from another app gets a new, wiped session, so it
                // shares nothing with the pages before it. It opens once
                // the new session is active.
                Core.reset(active.generation)
            } else {
                pendingLink = null
                browse(active.generation, link)
            }
        }
        // Test tags double as resource ids so UI tests can find trusted controls.
        Surface(Modifier.fillMaxSize().semantics { testTagsAsResourceId = true }, color = MaterialTheme.colorScheme.surface) {
            if (showingNotices) {
                NoticesScreen()
                return@Surface
            }
            Column(
                Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Header(state, lock, active != null && active.generation == reduced)
                NoticeCard()
                SessionCard(state, lock, mayBrowse, reduced)
                if (active != null) WatchCard(active.generation)
                DashboardCard()
                if (active != null) FilesCard()
                ProtectionCard(lock, active?.generation, reduced)
                IntelCard()
                TextButton(
                    onClick = { showingNotices = true },
                    modifier = Modifier.align(Alignment.CenterHorizontally).testTag("notices-open"),
                ) { Text("Open-source licences") }
            }
        }
    }

    /** The logo, the name, and one word on whether browsing is protected now. */
    @Composable
    private fun Header(state: Core.State, lock: NetworkLock.State, reduced: Boolean) {
        Row(Modifier.fillMaxWidth().padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Image(painterResource(org.simulationrift.bridge.R.drawable.rift_mark), contentDescription = null, modifier = Modifier.size(40.dp))
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text("Rift", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                Text("Open any link. Keep nothing.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            val status = LocalStatusColors.current
            val (label, container, content) = when {
                state is Core.State.Failed -> Triple("Stopped", MaterialTheme.colorScheme.errorContainer, MaterialTheme.colorScheme.onErrorContainer)
                state !is Core.State.Active -> Triple("Starting", MaterialTheme.colorScheme.surfaceContainerHigh, MaterialTheme.colorScheme.onSurface)
                lock == NetworkLock.State.Active -> Triple("Protected", status.safeContainer, status.onSafeContainer)
                reduced -> Triple("Reduced", status.warningContainer, status.onWarningContainer)
                else -> Triple("Not protected", MaterialTheme.colorScheme.errorContainer, MaterialTheme.colorScheme.onErrorContainer)
            }
            Pill(label, container, content, if (label == "Protected") R.drawable.ic_shield else R.drawable.ic_info)
        }
    }

    @Composable
    private fun Pill(label: String, container: Color, content: Color, icon: Int? = null, modifier: Modifier = Modifier) {
        Row(
            modifier.clip(CircleShape).background(container).padding(horizontal = 12.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (icon != null) {
                Icon(painterResource(icon), contentDescription = null, tint = content, modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(6.dp))
            }
            Text(label, color = content, style = MaterialTheme.typography.labelLarge)
        }
    }

    /**
     * The main card: the session, and the address field. Every link opens in
     * this session's sealed browser; "New session" wipes it.
     */
    @Composable
    private fun SessionCard(state: Core.State, lock: NetworkLock.State, mayBrowse: Boolean, reduced: Long?) {
        Card(
            Modifier.fillMaxWidth().animateContentSize().testTag("session"),
            shape = RoundedCornerShape(28.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.primaryContainer,
                contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
            ),
        ) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                when (state) {
                    Core.State.Opening -> Text("Preparing a fresh session…", style = MaterialTheme.typography.titleMedium)
                    is Core.State.Resetting -> Text("Destroying session ${state.generation}…", style = MaterialTheme.typography.titleMedium)
                    is Core.State.Failed -> {
                        Text("Session cleanup failed", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.error)
                        Text(state.message, modifier = Modifier.testTag("failure"))
                        Text("No new session starts until cleanup succeeds.", style = MaterialTheme.typography.bodySmall)
                        Button(onClick = Core::retry) { Text("Retry cleanup") }
                    }
                    is Core.State.Active -> {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                "Session ${state.generation}",
                                style = MaterialTheme.typography.labelLarge,
                                modifier = Modifier.weight(1f),
                            )
                            TextButton(onClick = { Core.reset(state.generation) }, modifier = Modifier.testTag("reset")) {
                                Icon(painterResource(R.drawable.ic_refresh), contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(6.dp))
                                Text("New session")
                            }
                        }
                        state.recovered?.let {
                            Text(
                                "Session $it was interrupted. Its browsing data was deleted before this session started.",
                                style = MaterialTheme.typography.bodySmall,
                                modifier = Modifier.testTag("recovered"),
                            )
                        }
                        Text("Open a link safely", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
                        if (mayBrowse) {
                            AddressField(state.generation)
                        } else if (lock == NetworkLock.State.Off || lock == NetworkLock.State.Starting) {
                            Text("Starting protection…", style = MaterialTheme.typography.bodyMedium)
                        } else {
                            Text(
                                "Rift opens pages only behind its network lock, so a page cannot reach your network or this device.",
                                style = MaterialTheme.typography.bodyMedium,
                            )
                            Button(onClick = ::turnOnLock, modifier = Modifier.fillMaxWidth().height(52.dp).testTag("lock-on")) {
                                Icon(painterResource(R.drawable.ic_lock), contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(8.dp))
                                Text("Turn on protection")
                            }
                            if (reduced != state.generation) {
                                TextButton(onClick = { Core.useReducedIsolation(state.generation) }, modifier = Modifier.testTag("use-reduced")) {
                                    Text("Using another VPN? Browse this session with reduced isolation")
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    @Composable
    private fun AddressField(generation: Long) {
        var typed by remember { mutableStateOf("") }
        val open = { browse(generation, typed.takeIf { it.isNotBlank() }) }
        OutlinedTextField(
            value = typed,
            onValueChange = { typed = it },
            placeholder = { Text("Paste or type a link") },
            leadingIcon = { Icon(painterResource(R.drawable.ic_link), contentDescription = null) },
            singleLine = true,
            shape = RoundedCornerShape(16.dp),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, imeAction = ImeAction.Go, autoCorrectEnabled = false),
            keyboardActions = KeyboardActions(onGo = { open() }),
            modifier = Modifier.noAutofill().fillMaxWidth().testTag("home-address"),
        )
        Button(onClick = open, modifier = Modifier.fillMaxWidth().height(52.dp).testTag("browse")) {
            Text("Open safely", style = MaterialTheme.typography.titleSmall)
            Spacer(Modifier.width(8.dp))
            Icon(painterResource(R.drawable.ic_arrow_forward), contentDescription = null, modifier = Modifier.size(18.dp))
        }
        Text(
            "Opens in a sealed browser with no access to your files, accounts or network. Everything is wiped with the session.",
            style = MaterialTheme.typography.bodySmall,
        )
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
        val status = LocalStatusColors.current
        val (container, content, icon) = when (level) {
            PageWatch.Level.DANGER -> Triple(MaterialTheme.colorScheme.error, MaterialTheme.colorScheme.onError, R.drawable.ic_bug)
            PageWatch.Level.WARNING -> Triple(status.warningContainer, status.onWarningContainer, R.drawable.ic_warning)
            else -> Triple(status.safeContainer, status.onSafeContainer, R.drawable.ic_check_circle)
        }
        Card(
            Modifier.fillMaxWidth().animateContentSize().testTag("watch"),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = container, contentColor = content),
        ) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(painterResource(icon), contentDescription = null, modifier = Modifier.size(24.dp))
                    Spacer(Modifier.width(12.dp))
                    Column {
                        Text("Live check", style = MaterialTheme.typography.labelMedium)
                        Text(
                            when (level) {
                                PageWatch.Level.DANGER -> "Danger in this session"
                                PageWatch.Level.WARNING -> "Warnings in this session"
                                else -> "Nothing suspicious seen so far in this session"
                            },
                            style = MaterialTheme.typography.titleMedium,
                            modifier = Modifier.testTag("watch-level"),
                        )
                    }
                }
                current.events.take(WATCH_SHOWN).forEach { event ->
                    Row(verticalAlignment = Alignment.Top) {
                        Text(if (event.count > 1) "×${event.count}" else "•", style = MaterialTheme.typography.labelMedium, modifier = Modifier.width(36.dp))
                        Text(event.text, style = MaterialTheme.typography.bodySmall)
                    }
                }
                if (current.events.size > WATCH_SHOWN) {
                    Text("${current.events.size - WATCH_SHOWN} more in the browser's live check.", style = MaterialTheme.typography.bodySmall)
                }
                if (level == PageWatch.Level.DANGER) {
                    Text("Start a new session to dispose of everything this one holds.", style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                }
                var coverage by remember { mutableStateOf(false) }
                if (coverage) current.coverage.forEach { Text(it, style = MaterialTheme.typography.labelSmall) }
                TextButton(
                    onClick = { coverage = !coverage },
                    colors = ButtonDefaults.textButtonColors(contentColor = content),
                    contentPadding = PaddingValues(0.dp),
                    modifier = Modifier.testTag("watch-coverage"),
                ) { Text(if (coverage) "Hide what it covers" else "What the live check sees") }
            }
        }
    }

    @Composable
    private fun NoticeCard() {
        val notice by Core.notice.collectAsState()
        val text = notice ?: return
        Card(
            Modifier.fillMaxWidth().testTag("notice"),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
        ) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(text)
                OutlinedButton(onClick = Core::dismissNotice) { Text("Dismiss") }
            }
        }
    }

    /** The last seven days (WeeklyStats): counts, and threats and warnings per day. */
    @Composable
    private fun DashboardCard() {
        val week by WeeklyStats.week.collectAsState()
        val status = LocalStatusColors.current
        Card(
            Modifier.fillMaxWidth().testTag("dashboard"),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
        ) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("This week", style = MaterialTheme.typography.titleMedium)
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    StatTile("Threats blocked", week.total(Tally.BLOCKED), R.drawable.ic_shield, MaterialTheme.colorScheme.error, "stat-blocked", Modifier.weight(1f))
                    StatTile("Dangerous files", week.total(Tally.FLAGGED_FILE), R.drawable.ic_bug, MaterialTheme.colorScheme.error, "stat-files", Modifier.weight(1f))
                }
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    StatTile("Warnings", week.total(Tally.WARNED), R.drawable.ic_warning, status.warning, "stat-warned", Modifier.weight(1f))
                    StatTile("Links checked", week.total(Tally.LINK_CHECKED), R.drawable.ic_link, MaterialTheme.colorScheme.primary, "stat-links", Modifier.weight(1f))
                }
                Text("Threats, dangerous files and warnings, per day", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                WeekChart(week)
                Text(
                    "${format(week.total(Tally.FILE_SCANNED))} files scanned. Counts only, kept on this device for two weeks: " +
                        "no addresses or file names.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }

    @Composable
    private fun StatTile(label: String, value: Int, icon: Int, accent: Color, tag: String, modifier: Modifier) {
        Row(
            modifier.clip(RoundedCornerShape(18.dp)).background(MaterialTheme.colorScheme.surfaceContainerHigh).padding(12.dp)
                .semantics(mergeDescendants = true) {}.testTag(tag),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(Modifier.size(36.dp).clip(CircleShape).background(accent.copy(alpha = 0.16f)), contentAlignment = Alignment.Center) {
                Icon(painterResource(icon), contentDescription = null, tint = accent, modifier = Modifier.size(20.dp))
            }
            Spacer(Modifier.width(12.dp))
            Column {
                Text(format(value), style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold, maxLines = 1)
                Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
    }

    /**
     * One series, seven bars, oldest first. The busiest day and today are
     * labelled; a tap labels any day. The whole chart reads as a list.
     */
    @Composable
    private fun WeekChart(week: Week) {
        val values = week.days.map { it[Tally.BLOCKED] + it[Tally.FLAGGED_FILE] + it[Tally.WARNED] }
        if (values.all { it == 0 }) {
            val status = LocalStatusColors.current
            Row(
                Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(status.safeContainer).padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(painterResource(R.drawable.ic_check_circle), contentDescription = null, tint = status.onSafeContainer, modifier = Modifier.size(20.dp))
                Spacer(Modifier.width(12.dp))
                Text("Nothing dangerous met in the last seven days.", style = MaterialTheme.typography.bodyMedium, color = status.onSafeContainer)
            }
            return
        }
        val names = week.days.map { LocalDate.ofEpochDay(it.epochDay).dayOfWeek.getDisplayName(TextStyle.SHORT, Locale.getDefault()) }
        var picked by remember { mutableIntStateOf(-1) }
        val busiest = values.indices.maxByOrNull { values[it] }?.takeIf { values[it] > 0 }
        val bar = MaterialTheme.colorScheme.primary
        val baseline = MaterialTheme.colorScheme.outlineVariant
        val described = names.zip(values).joinToString { (day, n) -> "$day $n" }
        Column(Modifier.semantics(mergeDescendants = true) { contentDescription = "Per day: $described" }) {
            Row(Modifier.fillMaxWidth()) {
                values.forEachIndexed { i, n ->
                    val shown = i == picked || i == busiest || i == values.lastIndex
                    Text(
                        if (shown) format(n) else "",
                        style = MaterialTheme.typography.labelSmall,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.weight(1f),
                    )
                }
            }
            Canvas(
                Modifier.fillMaxWidth().height(88.dp).pointerInput(values.size) {
                    detectTapGestures { offset -> picked = (offset.x / (size.width / values.size)).toInt().coerceIn(values.indices) }
                },
            ) {
                val slot = size.width / values.size
                val width = (slot * 0.5f).coerceAtMost(28.dp.toPx())
                val top = values.maxOrNull()?.coerceAtLeast(1) ?: 1
                val radius = 4.dp.toPx()
                values.forEachIndexed { i, n ->
                    if (n == 0) return@forEachIndexed
                    val height = (size.height - 2.dp.toPx()) * n / top
                    val left = slot * i + (slot - width) / 2
                    val path = Path().apply {
                        addRoundRect(
                            androidx.compose.ui.geometry.RoundRect(
                                left, size.height - height, left + width, size.height,
                                topLeftCornerRadius = CornerRadius(radius), topRightCornerRadius = CornerRadius(radius),
                            ),
                        )
                    }
                    drawPath(path, if (i == picked || picked == -1) bar else bar.copy(alpha = 0.45f))
                }
                drawLine(baseline, Offset(0f, size.height - 1), Offset(size.width, size.height - 1), strokeWidth = 1.dp.toPx())
            }
            Row(Modifier.fillMaxWidth().padding(top = 4.dp)) {
                names.forEachIndexed { i, day ->
                    Text(
                        if (i == names.lastIndex) "Today" else day,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                        maxLines = 1,
                        modifier = Modifier.weight(1f),
                    )
                }
            }
        }
    }

    /** Downloads of this session: in encrypted quarantine, scanned, and viewable in an isolated worker. */
    @Composable
    private fun FilesCard() {
        val downloads by Core.downloads.collectAsState()
        val previews by Core.previews.collectAsState()
        val verdicts by Core.verdicts.collectAsState()
        Card(
            Modifier.fillMaxWidth().animateContentSize().testTag("downloads"),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
        ) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Files", style = MaterialTheme.typography.titleMedium)
                if (downloads.isEmpty()) {
                    Text(
                        "Files you download while browsing land here: fetched again by Rift, encrypted, scanned, and viewable " +
                            "safely. They are deleted with the session.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                downloads.forEachIndexed { i, d ->
                    if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                    val file = d.file
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(painterResource(R.drawable.ic_file), contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(28.dp))
                        Spacer(Modifier.width(12.dp))
                        Text(
                            when {
                                file != null -> "${file.displayName}\n${Formatter.formatShortFileSize(LocalContext.current, file.size.toLong())} · " +
                                    "sha256 ${file.sha256.take(12)}…" + (file.contentType?.let { " · labelled $it" } ?: "") + "\nfrom ${file.source}"
                                d.failure != null -> "Not captured: ${d.failure}\n${d.url}"
                                else -> "Fetching ${d.url}…"
                            },
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.weight(1f).testTag("download-${d.key}"),
                        )
                    }
                    if (file != null) {
                        VerdictArea(file.id, verdicts.containsKey(file.id), verdicts[file.id])
                        PreviewArea(file.id, file.displayName, previews[file.id])
                    }
                }
                Text(
                    "Downloads created inside a page (blob: and data:) cannot be captured.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }

    /** The scan result as rift-core decided it: never "safe", always with its coverage. */
    @Composable
    private fun VerdictArea(fileId: String, requested: Boolean, verdict: Verdict?) {
        val status = LocalStatusColors.current
        when {
            !requested -> OutlinedButton(onClick = { Core.scan(fileId) }, modifier = Modifier.testTag("scan-$fileId")) { Text("Scan") }
            verdict == null -> Text("Scanning in an isolated worker…", style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("scanning-$fileId"))
            else -> Column(Modifier.testTag("verdict-$fileId"), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                val (container, content, icon) = when (verdict.status) {
                    ScanStatus.KNOWN_MALICIOUS -> Triple(MaterialTheme.colorScheme.error, MaterialTheme.colorScheme.onError, R.drawable.ic_bug)
                    ScanStatus.SUSPICIOUS -> Triple(status.warningContainer, status.onWarningContainer, R.drawable.ic_warning)
                    ScanStatus.NOT_FULLY_SCANNED -> Triple(MaterialTheme.colorScheme.surfaceContainerHighest, MaterialTheme.colorScheme.onSurface, R.drawable.ic_info)
                    ScanStatus.NOT_FLAGGED -> Triple(status.safeContainer, status.onSafeContainer, R.drawable.ic_check_circle)
                }
                Row(
                    Modifier.clip(RoundedCornerShape(12.dp)).background(container).padding(horizontal = 10.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Icon(painterResource(icon), contentDescription = null, tint = content, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(verdict.label, style = MaterialTheme.typography.labelLarge, color = content, modifier = Modifier.testTag("verdict-label-$fileId"))
                }
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
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }

    @Composable
    private fun PreviewArea(fileId: String, name: String, preview: Core.Preview?) {
        val bitmap = preview?.bitmap
        when {
            preview == null -> FilledTonalButton(onClick = { Core.preview(fileId) }, modifier = Modifier.testTag("preview-$fileId")) {
                Icon(painterResource(R.drawable.ic_eye), contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text("View safely")
            }
            preview.running -> Text("Rendering in an isolated worker…", style = MaterialTheme.typography.bodySmall)
            bitmap != null -> {
                val image = remember(bitmap) { bitmap.asImageBitmap() }
                Image(
                    image,
                    contentDescription = "Preview of $name",
                    modifier = Modifier.fillMaxWidth().heightIn(max = 480.dp).clip(RoundedCornerShape(12.dp)).testTag("preview-image-$fileId"),
                )
                Text(
                    "A picture drawn by an isolated worker: no scripts, links or network. ${bitmap.width}×${bitmap.height}.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            preview.text != null -> {
                Text(
                    preview.text,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.fillMaxWidth().heightIn(max = 320.dp).clip(RoundedCornerShape(12.dp))
                        .background(MaterialTheme.colorScheme.surfaceContainerHighest).padding(12.dp)
                        .verticalScroll(rememberScrollState()).testTag("preview-text-$fileId"),
                )
                preview.note?.let { Text(it, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
            }
            else -> Text("Preview unavailable: ${preview.failure}", style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("preview-failure-$fileId"))
        }
    }

    /**
     * How the browser is held (§8.8, §10.3): the network lock, the proxy's
     * refusals, the renderer sandbox, and what is and is not checked. Folded
     * unless something needs the user.
     */
    @Composable
    private fun ProtectionCard(lock: NetworkLock.State, generation: Long?, reduced: Long?) {
        val dropped by NetworkLock.dropped.collectAsState()
        val sandbox by Core.sandbox.collectAsState()
        val network by Core.network.collectAsState()
        var stats by remember { mutableStateOf<EgressStats?>(null) }
        LaunchedEffect(generation) {
            while (true) {
                // Off the UI thread: it takes the session lock, which a reset holds while it wipes the browser.
                stats = withContext(Dispatchers.IO) { Core.egressStats() }
                delay(STATS_REFRESH_MS)
            }
        }
        val isReduced = generation != null && reduced == generation
        val (summary, problem) = when (lock) {
            NetworkLock.State.Active -> "Network lock on. The browser has no route to any network; it reaches websites only " +
                "through Rift's proxy, which refuses local and private addresses." to false
            NetworkLock.State.Off, NetworkLock.State.Starting -> "Starting the network lock…" to false
            NetworkLock.State.NeedsConsent -> "The network lock needs Android's VPN permission. Rift's VPN routes nothing " +
                "anywhere: it only takes away the browser's direct network access, so its one way out is Rift's proxy." to true
            is NetworkLock.State.Lost -> "The network lock stopped: ${lock.reason}." to true
            is NetworkLock.State.Unavailable -> "The network lock cannot run: ${lock.reason}." to true
        }
        var open by remember { mutableStateOf(false) }
        val expanded = open || problem || isReduced
        Card(
            Modifier.fillMaxWidth().animateContentSize().testTag("network"),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
        ) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Protection", style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                    if (!problem && !isReduced) {
                        TextButton(onClick = { open = !open }, modifier = Modifier.testTag("protection-details")) {
                            Text(if (open) "Less" else "Details")
                        }
                    }
                }
                Text(
                    summary,
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (problem) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.testTag("lock-state"),
                )
                if (isReduced) {
                    Text(
                        "This session runs with reduced isolation: pages can reach your local network through WebRTC, " +
                            "and a compromised browser is not limited to Rift's proxy.",
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.testTag("reduced-session"),
                    )
                }
                stats?.let { s ->
                    Text(
                        "Proxy this session: ${s.allowed} connections allowed, ${s.denied} refused.",
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.testTag("egress"),
                    )
                }
                if (lock == NetworkLock.State.Active && dropped.packets > 0) {
                    Text(
                        "Dropped by the lock: ${dropped.packets} packets, to " + dropped.destinations.take(6).joinToString() +
                            (if (dropped.destinations.size > 6) ", …" else ""),
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.testTag("lock-dropped"),
                    )
                }
                if (expanded) {
                    stats?.recent?.takeLast(5)?.forEach { d -> Text("Refused ${d.destination}: ${d.reason}", style = MaterialTheme.typography.bodySmall) }
                    Text(
                        sandbox?.let { (if (it.verified) "Renderer sandbox confirmed: " else "Renderer sandbox NOT confirmed: ") + it.detail }
                            ?: "Renderer sandbox: checked when the browser starts.",
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.testTag("sandbox"),
                    )
                    Text(
                        network?.let { "Browser network: ${it.detail}" } ?: "Browser network: checked when the browser starts.",
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.testTag("network-report"),
                    )
                    listOf(
                        "Checked: addresses you type, links opened in Rift, and main-frame navigations the engine reports.",
                        "Not checked: subresources, frames, WebSockets, WebRTC, service-worker fetches and form posts (§10.3). " +
                            "All of those still go through Rift's proxy, which refuses local and private addresses.",
                        "Address checks use a built-in list; the threat database is used for downloaded files.",
                        "Safe Browsing is off, so no addresses or hashes are sent to Google.",
                        "No browser is immune to every attack: a flaw in the engine and in Android together could still escape. " +
                            "Rift limits what such an escape reaches, and wipes the session.",
                    ).forEach { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                }
            }
        }
    }

    @Composable
    private fun IntelCard() {
        val status by Core.intel.collectAsState()
        val message by Core.intelMessage.collectAsState()
        val canImport = remember { Core.trustedRoot() != null }
        val source = remember { Core.updateSource() }
        Card(
            Modifier.fillMaxWidth().animateContentSize().testTag("intel"),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
        ) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Threat database", style = MaterialTheme.typography.titleMedium)
                Text(
                    when (val s = status) {
                        null -> "Opening…"
                        is IntelStatus.Missing -> "None installed. Files are checked for type only, and say what was not checked."
                        is IntelStatus.Damaged -> "The installed database is damaged and is not used: ${s.detail}"
                        is IntelStatus.Installed -> "${s.snapshot}" + (if (s.demo) " · DEMO, not real coverage" else "") +
                            (if (s.stale) " · out of date, still used offline" else "")
                    },
                    style = MaterialTheme.typography.bodyMedium,
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
                val compact = PaddingValues(horizontal = 16.dp, vertical = 8.dp)
                if (canImport && source != null) {
                    FilledTonalButton(onClick = { Core.updateIntelOnline(source) }, contentPadding = compact, modifier = Modifier.testTag("intel-online")) {
                        Text("Check for an update")
                    }
                }
                if (canImport) {
                    OutlinedButton(onClick = { chooseUpdate.launch(null) }, contentPadding = compact, modifier = Modifier.testTag("intel-import")) {
                        Text("Import an update folder…")
                    }
                } else {
                    Text("This build has no trusted root, so it cannot install updates.", style = MaterialTheme.typography.bodySmall)
                }
                if (Core.demoIntelAvailable()) {
                    OutlinedButton(
                        onClick = { Core.installDemoIntel() },
                        contentPadding = compact,
                        modifier = Modifier.testTag("intel-demo"),
                    ) { Text("Install the signed demo database") }
                }
            }
        }
    }

    private companion object {
        const val STATS_REFRESH_MS = 1_000L
        const val WATCH_SHOWN = 5
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
                            "under the licences shown, and Google's Material icons, under the Apache License 2.0.",
                    )
                }
            }
            items(lines ?: listOf("Loading…")) { line ->
                Text(line, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

private fun format(n: Int): String = NumberFormat.getIntegerInstance().format(n)

/** The notice assets, in the order shown. */
private val NOTICE_FILES = listOf("android-libraries.txt", "rust-crates.txt", "apache-2.0.txt")
