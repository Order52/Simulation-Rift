package org.simulationrift.app

import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import android.provider.Settings
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
import androidx.compose.foundation.gestures.rememberTransformableState
import androidx.compose.foundation.gestures.transformable
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
import androidx.compose.foundation.ScrollState
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
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalConfiguration
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
import androidx.core.content.IntentCompat
import java.text.NumberFormat
import java.time.LocalDate
import java.time.format.TextStyle
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.simulationrift.bridge.PageWatch
import org.simulationrift.bridge.WindowGuard
import org.simulationrift.core.EgressStats
import org.simulationrift.core.LinkCheck
import org.simulationrift.core.IntelStatus
import org.simulationrift.core.ScanStatus
import org.simulationrift.core.Verdict

/** The trusted home screen (main process). */
class MainActivity : ComponentActivity() {

    /** A link handed to Rift by another app, opened once a session is active. */
    private var pendingLink by mutableStateOf<String?>(null)

    /** A file handed to Rift by another app, taken in once a session is active. */
    private var pendingFile by mutableStateOf<Uri?>(null)

    /** The quarantined file shown full screen, if any. */
    private var viewing by mutableStateOf<String?>(null)

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
        if (savedInstanceState == null) receive(intent)
        // No overlays, autofill, non-tool accessibility services or recents snapshot.
        WindowGuard.apply(this)
        setContent { RiftTheme { NoPersonalizedLearning { Home() } } }
    }

    override fun onResume() {
        super.onResume()
        // Back from Android's "install unknown apps" setting.
        if (BrowserSetup.state.value == BrowserSetup.State.NeedsPermission && packageManager.canRequestPackageInstalls()) {
            BrowserSetup.install(this)
        }
        // The week may have moved on while Rift was in the background.
        WeeklyStats.refresh()
    }

    private fun turnOnLock() {
        val request = VpnService.prepare(this)
        if (request == null) NetworkLock.start(this, userAction = true) else consent.launch(request)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        receive(intent)
    }

    /** What another app handed over: a file, or else a link. */
    private fun receive(intent: Intent) {
        val file = fileFrom(intent)
        if (file != null) pendingFile = file else linkFrom(intent)?.let { pendingLink = it }
    }

    /** A file opened with Rift (ACTION_VIEW of a `content:` URI) or shared to it (EXTRA_STREAM). */
    private fun fileFrom(intent: Intent): Uri? = when (intent.action) {
        Intent.ACTION_VIEW -> intent.data?.takeIf { it.scheme == "content" }
        Intent.ACTION_SEND -> IntentCompat.getParcelableExtra(intent, Intent.EXTRA_STREAM, Uri::class.java)
        else -> null
    }

    /**
     * ACTION_VIEW links and shared text (§8.2), as the address to load: the
     * first link in shared text, in the form the engine will load. The core
     * checks it before loading.
     */
    private fun linkFrom(intent: Intent): String? = when (intent.action) {
        Intent.ACTION_VIEW -> intent.dataString?.takeIf { intent.data?.scheme != "content" }
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
        // A file needs no network: it is taken in as soon as a session is active.
        val file = pendingFile
        if (active != null && file != null) {
            pendingFile = null
            Core.takeIn(file)
        }
        val handedOver by Core.handedOver.collectAsState()
        LaunchedEffect(handedOver) {
            handedOver?.let {
                viewing = it
                Core.handedOverShown()
            }
        }
        // Test tags double as resource ids so UI tests can find trusted controls.
        Surface(Modifier.fillMaxSize().semantics { testTagsAsResourceId = true }, color = MaterialTheme.colorScheme.surface) {
            if (showingNotices) {
                NoticesScreen()
                return@Surface
            }
            viewing?.let {
                FileScreen(it)
                return@Surface
            }
            // One screen for each part, instead of one long scroll.
            var tab by rememberSaveable { mutableStateOf(Tab.HOME) }
            Scaffold(
                containerColor = MaterialTheme.colorScheme.surface,
                bottomBar = {
                    NavigationBar(Modifier.testTag("tabs")) {
                        Tab.entries.forEach { entry ->
                            NavigationBarItem(
                                selected = tab == entry,
                                onClick = { tab = entry },
                                icon = { Icon(painterResource(entry.icon), contentDescription = null) },
                                label = { Text(entry.label, maxLines = 1) },
                                modifier = Modifier.testTag("tab-${entry.name.lowercase()}"),
                            )
                        }
                    }
                },
            ) { padding ->
                Column(
                    Modifier.fillMaxSize().padding(padding).verticalScroll(remember(tab) { ScrollState(0) }).padding(horizontal = 16.dp, vertical = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp),
                ) {
                    when (tab) {
                        Tab.HOME -> {
                            Header(state, lock, active != null && active.generation == reduced)
                            NoticeCard()
                            SessionCard(state, lock, mayBrowse, reduced)
                            if (active != null) WatchCard(active.generation)
                            if (active != null) FilesCard()
                        }
                        Tab.FILTERS -> FiltersTab()
                        Tab.ACTIVITY -> {
                            Text("Activity", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 8.dp))
                            DashboardCard()
                        }
                        Tab.SECURITY -> {
                            Text("Security", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 8.dp))
                            ProtectionCard(lock, active?.generation, reduced)
                            ExtraIsolationCard()
                            IntelCard()
                        }
                        Tab.ABOUT -> AboutTab(onLicences = { showingNotices = true })
                    }
                }
            }
        }
    }

    /** The home screen's parts, in the order of the bar at the bottom. */
    private enum class Tab(val label: String, val icon: Int) {
        HOME("Home", R.drawable.ic_home),
        FILTERS("Filters", R.drawable.ic_filter),
        ACTIVITY("Activity", R.drawable.ic_chart),
        SECURITY("Security", R.drawable.ic_shield),
        ABOUT("About", R.drawable.ic_info),
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
                state == Core.State.NeedsBrowser -> Triple("Setup", MaterialTheme.colorScheme.surfaceContainerHigh, MaterialTheme.colorScheme.onSurface)
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
                    Core.State.NeedsBrowser -> BrowserSetupContent()
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
                        Text("Check or open a link", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
                        // Checking needs no network: it works before protection is on.
                        AddressField(state.generation, mayBrowse)
                        if (mayBrowse) {
                            Text(
                                "Check looks at the link on this device without opening it. Open safely loads it in a sealed browser " +
                                    "with no access to your files, accounts or network, wiped with the session.",
                                style = MaterialTheme.typography.bodySmall,
                            )
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

    /** First run, or after an update of Rift: install the sealed browser Rift carries (§8.10). */
    @Composable
    private fun BrowserSetupContent() {
        val setup by BrowserSetup.state.collectAsState()
        val update = (setup as? BrowserSetup.State.Needed)?.update == true
        Text(if (update) "Update the sealed browser" else "One step left", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
        Text(
            if (update) "Rift was updated, and its sealed browser needs the matching version. It comes inside Rift."
            else "Rift opens links in its own sealed browser: a separate app with its own Linux user, no permissions, " +
                "and no access to Rift or your files. It comes inside Rift; Android asks you to confirm the install.",
            style = MaterialTheme.typography.bodyMedium,
        )
        when (val current = setup) {
            BrowserSetup.State.Installing -> Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.testTag("browser-installing")) {
                CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(12.dp))
                Text("Installing…")
            }
            BrowserSetup.State.NeedsPermission -> {
                Text(
                    "Android needs your permission for Rift to install apps. Turn on \"Allow from this source\" for Rift, then come back.",
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.testTag("browser-permission"),
                )
                Button(
                    onClick = { startActivity(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:$packageName"))) },
                    modifier = Modifier.fillMaxWidth().height(52.dp).testTag("browser-settings"),
                ) { Text("Open settings") }
            }
            else -> {
                if (current is BrowserSetup.State.Failed) {
                    Text(current.reason, color = MaterialTheme.colorScheme.error, modifier = Modifier.testTag("browser-failure"))
                }
                Button(onClick = { BrowserSetup.install(this@MainActivity) }, modifier = Modifier.fillMaxWidth().height(52.dp).testTag("install-browser")) {
                    Icon(painterResource(R.drawable.ic_lock), contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(if (update) "Update sealed browser" else "Install sealed browser")
                }
            }
        }
        // Checking a link needs no browser.
        AddressField(0, mayBrowse = false)
    }

    @Composable
    private fun AddressField(generation: Long, mayBrowse: Boolean) {
        var typed by remember { mutableStateOf("") }
        var result by remember { mutableStateOf<LinkCheck?>(null) }
        var checking by remember { mutableStateOf(false) }
        val scope = rememberCoroutineScope()
        val open = { if (mayBrowse) browse(generation, typed.takeIf { it.isNotBlank() }) }
        val check = {
            val input = typed
            if (input.isNotBlank() && !checking) {
                checking = true
                scope.launch {
                    result = withContext(Dispatchers.Default) { Core.check(input) }
                    checking = false
                }
            }
        }
        OutlinedTextField(
            value = typed,
            onValueChange = {
                typed = it
                result = null
            },
            placeholder = { Text("Paste or type a link") },
            leadingIcon = { Icon(painterResource(R.drawable.ic_link), contentDescription = null) },
            singleLine = true,
            shape = RoundedCornerShape(16.dp),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, imeAction = ImeAction.Go, autoCorrectEnabled = false),
            keyboardActions = KeyboardActions(onGo = { if (mayBrowse) open() else check() }),
            modifier = Modifier.noAutofill().fillMaxWidth().testTag("home-address"),
        )
        // Below 360 dp the icons and the usual padding leave no room for the labels.
        val roomy = LocalConfiguration.current.screenWidthDp >= 360
        val padding = if (roomy) ButtonDefaults.ContentPadding else PaddingValues(horizontal = 10.dp)
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            FilledTonalButton(
                onClick = check,
                enabled = typed.isNotBlank() && !checking,
                contentPadding = padding,
                modifier = Modifier.weight(1f).height(52.dp).testTag("check"),
            ) {
                if (roomy) {
                    Icon(painterResource(R.drawable.ic_shield), contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                }
                Text(if (checking) "Checking…" else "Check", style = MaterialTheme.typography.titleSmall, maxLines = 1, softWrap = false)
            }
            Button(onClick = open, enabled = mayBrowse, contentPadding = padding, modifier = Modifier.weight(1.3f).height(52.dp).testTag("browse")) {
                Text("Open safely", style = MaterialTheme.typography.titleSmall, maxLines = 1, softWrap = false)
                if (roomy) {
                    Spacer(Modifier.width(8.dp))
                    Icon(painterResource(R.drawable.ic_arrow_forward), contentDescription = null, modifier = Modifier.size(18.dp))
                }
            }
        }
        result?.let { CheckResult(it, onOpen = open.takeIf { mayBrowse }, onClose = { result = null }) }
    }

    /** What a check found (LinkCheckViews), with Open safely where Rift would load it. */
    @Composable
    private fun CheckResult(check: LinkCheck, onOpen: (() -> Unit)?, onClose: () -> Unit) {
        val verdict = verdictOf(check)
        Surface(
            color = verdict.container,
            contentColor = verdict.content,
            shape = RoundedCornerShape(20.dp),
            modifier = Modifier.fillMaxWidth().animateContentSize().testTag("check-result"),
        ) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                CheckHeadline(verdict)
                CheckDetails(check, verdict)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (onOpen != null && verdict.openable) {
                        FilledTonalButton(onClick = onOpen, modifier = Modifier.testTag("check-open")) { Text("Open safely") }
                    }
                    TextButton(onClick = onClose, modifier = Modifier.testTag("check-close")) { Text("Clear") }
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
                    "${week.total(Tally.FILE_SCANNED).let { "${format(it)} ${if (it == 1) "file" else "files"}" }} scanned. Counts only, kept on this device for two weeks: " +
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
            // Below 360 dp the label needs the icon's room.
            if (LocalConfiguration.current.screenWidthDp >= 360) {
                Box(Modifier.size(36.dp).clip(CircleShape).background(accent.copy(alpha = 0.16f)), contentAlignment = Alignment.Center) {
                    Icon(painterResource(icon), contentDescription = null, tint = accent, modifier = Modifier.size(20.dp))
                }
                Spacer(Modifier.width(12.dp))
            }
            Column {
                Text(format(value), style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold, maxLines = 1)
                Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis)
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
                        "Files you download while browsing, or open or share with Rift from other apps, land here: " +
                            "encrypted, scanned, and viewable safely. They are deleted with the session.",
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
                        FilledTonalButton(onClick = { view(file.id) }, modifier = Modifier.testTag("preview-${file.id}")) {
                            Icon(painterResource(R.drawable.ic_eye), contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("View safely")
                        }
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

    private fun view(fileId: String) {
        if (Core.previews.value[fileId] == null) Core.preview(fileId)
        viewing = fileId
    }

    /**
     * One quarantined file, full screen: its verdict and what an isolated
     * worker drew of it (pinch to zoom, double-tap to fit), or its escaped
     * text. Back returns to the home screen.
     */
    @Composable
    private fun FileScreen(fileId: String) {
        BackHandler { viewing = null }
        val downloads by Core.downloads.collectAsState()
        val previews by Core.previews.collectAsState()
        val verdicts by Core.verdicts.collectAsState()
        val file = downloads.firstNotNullOfOrNull { d -> d.file?.takeIf { it.id == fileId } }
        // Gone with its session: back to the home screen.
        LaunchedEffect(file == null) { if (file == null) viewing = null }
        if (file == null) return
        LaunchedEffect(fileId) { if (Core.previews.value[fileId] == null) Core.preview(fileId) }
        val preview = previews[fileId]
        Column(
            Modifier.fillMaxSize().safeDrawingPadding().padding(horizontal = 16.dp, vertical = 8.dp).testTag("viewer"),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            TextButton(onClick = { viewing = null }, contentPadding = PaddingValues(0.dp), modifier = Modifier.testTag("viewer-close")) {
                Text("Back")
            }
            Text(file.displayName, style = MaterialTheme.typography.titleLarge, maxLines = 2, overflow = TextOverflow.Ellipsis)
            Text(
                "${Formatter.formatShortFileSize(LocalContext.current, file.size.toLong())} · from ${file.source}" +
                    (file.contentType?.let { " · labelled $it" } ?: "") + " · sha256 ${file.sha256.take(12)}…",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            VerdictArea(file.id, verdicts.containsKey(file.id), verdicts[file.id])
            Box(
                Modifier.weight(1f).fillMaxWidth().clip(RoundedCornerShape(20.dp)).background(MaterialTheme.colorScheme.surfaceContainerHighest),
                contentAlignment = Alignment.Center,
            ) {
                PreviewContent(fileId, file.displayName, preview)
            }
            Text(
                when {
                    preview?.bitmap != null -> "A picture drawn by an isolated worker: no scripts, links or network. " +
                        "${preview.bitmap.width}×${preview.bitmap.height}. Pinch to zoom."
                    preview?.text != null -> preview.note.orEmpty()
                    else -> "Opened in an isolated worker with no files and no network. Nothing in the file runs."
                },
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }

    @Composable
    private fun PreviewContent(fileId: String, name: String, preview: Core.Preview?) {
        val bitmap = preview?.bitmap
        when {
            preview == null || preview.running -> Text("Rendering in an isolated worker…", style = MaterialTheme.typography.bodyMedium)
            bitmap != null -> {
                val image = remember(bitmap) { bitmap.asImageBitmap() }
                var scale by remember(fileId) { mutableFloatStateOf(1f) }
                var offset by remember(fileId) { mutableStateOf(Offset.Zero) }
                val zoom = rememberTransformableState { change, pan, _ ->
                    scale = (scale * change).coerceIn(1f, MAX_ZOOM)
                    offset = if (scale == 1f) Offset.Zero else offset + pan
                }
                Image(
                    image,
                    contentDescription = "Preview of $name",
                    contentScale = ContentScale.Fit,
                    modifier = Modifier.fillMaxSize()
                        .pointerInput(fileId) {
                            detectTapGestures(onDoubleTap = {
                                scale = 1f
                                offset = Offset.Zero
                            })
                        }
                        .transformable(zoom)
                        .graphicsLayer {
                            scaleX = scale
                            scaleY = scale
                            translationX = offset.x
                            translationY = offset.y
                        }
                        .testTag("preview-image-$fileId"),
                )
            }
            preview.text != null -> Text(
                preview.text,
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.fillMaxSize().padding(12.dp).verticalScroll(rememberScrollState()).testTag("preview-text-$fileId"),
            )
            else -> Text(
                "Preview unavailable: ${preview.failure}",
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(24.dp).testTag("preview-failure-$fileId"),
            )
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
            NetworkLock.State.TurnedOff -> "Network lock off, as you chose: no VPN. Pages still reach websites only through " +
                "Rift's proxy, which checks every connection and refuses local and private addresses." to false
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
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Network lock", style = MaterialTheme.typography.bodyLarge)
                        Text(
                            "Shown by Android as a VPN. It routes nothing anywhere: it cuts the browser off from every network but Rift's proxy.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Switch(
                        checked = lock != NetworkLock.State.TurnedOff,
                        onCheckedChange = { on ->
                            NetworkLock.turn(this@MainActivity, on)
                            if (on) turnOnLock()
                        },
                        modifier = Modifier.testTag("lock-switch"),
                    )
                }
                Text(
                    summary,
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (problem) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.testTag("lock-state"),
                )
                if (isReduced) {
                    Text(
                        if (Hardening.status.collectAsState().value.network == Hardening.Measure.InEffect) {
                            "This session runs without the network lock. Extra isolation's firewall (root) still keeps the browser " +
                                "to Rift's proxy, WebRTC included."
                        } else {
                            "This session runs with reduced isolation: pages can reach your local network through WebRTC, " +
                                "and a compromised browser is not limited to Rift's proxy."
                        },
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
                    Text(
                        Core.aiStatus.collectAsState().value?.text ?: "Rift AI: loads with the first check.",
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.testTag("ai-status"),
                    )
                    listOf(
                        "Checked against the threat database and by Rift AI: links you check or open, every address a page " +
                            "moves to (redirects too), and every connection a page makes through Rift's proxy (plain HTTP by " +
                            "full address, HTTPS by host name only, because the rest is encrypted).",
                        "The database blocks what it lists. Rift AI only warns: it never blocks on its own, and a low score " +
                            "does not mean a link is safe. Pages hosted on large sites (a form on Google Docs, a file on " +
                            "Dropbox) look like that site's real pages, so the AI is not the check that catches those.",
                        "The proxy also refuses local and private addresses; connections around it are dropped by the network lock.",
                        "Everything is checked on this device. Safe Browsing is off, so no addresses or hashes are sent to Google.",
                        "No browser is immune to every attack: a flaw in the engine and in Android together could still escape. " +
                            "Rift limits what such an escape reaches, and wipes the session.",
                    ).forEach { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                }
            }
        }
    }

    /** Extra isolation (§8.9): off unless the user turns it on; each measure as read back by the helper. */
    @Composable
    private fun ExtraIsolationCard() {
        val status by Hardening.status.collectAsState()
        Card(
            Modifier.fillMaxWidth().animateContentSize().testTag("extra-isolation"),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
        ) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Extra isolation", style = MaterialTheme.typography.titleMedium)
                        Text("Optional · with Shizuku or root", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Switch(
                        checked = status.on,
                        onCheckedChange = { if (it) Hardening.enable() else Hardening.disable() },
                        modifier = Modifier.testTag("extra-switch"),
                    )
                }
                if (!status.on) {
                    Text(
                        if (status.undoPending) "Turned off while Shizuku was not running: copy and paste in Rift's browser stay blocked (and, with root, its firewall stays) until Shizuku runs again; Rift then undoes them."
                        else "Uses Shizuku (started with adb or root) or Sui to lock the browser further with Android's own tools: " +
                            "no clipboard, wipes done by Android itself, and with root a firewall that keeps the browser to Rift's proxy. " +
                            "Copy and paste in Rift's browser stop working while it is on.",
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.testTag("extra-about"),
                    )
                    return@Column
                }
                val (helperText, problem) = when (val h = status.helper) {
                    Hardening.Helper.Off, Hardening.Helper.Connecting -> "Starting Rift's helper…" to false
                    Hardening.Helper.NotRunning -> "Shizuku is not running. Install Shizuku (shizuku.rikka.app) or Sui, start it, and Rift connects." to true
                    Hardening.Helper.AskingPermission -> "Allow Rift in Shizuku's prompt." to false
                    Hardening.Helper.Denied -> "Shizuku has not allowed Rift. Allow it in the Shizuku app, then turn this off and on." to true
                    is Hardening.Helper.Failed -> h.reason to true
                    is Hardening.Helper.Connected -> (if (h.root) "Rift's helper runs as root." else "Rift's helper runs as shell (Shizuku started with adb).") to false
                }
                Text(
                    helperText,
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (problem) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.testTag("extra-helper"),
                )
                if (status.helper is Hardening.Helper.Connected) {
                    MeasureRow("Copy and paste blocked for the browser app", status.clipboard, "extra-clipboard")
                    MeasureRow("Each wipe done by Android at Rift's request, not the browser's", status.wipe, "extra-wipe")
                    MeasureRow("Firewall: the browser reaches only Rift's proxy, even on this phone", status.network, "extra-network")
                }
            }
        }
    }

    @Composable
    private fun MeasureRow(label: String, measure: Hardening.Measure, tag: String) {
        val status = LocalStatusColors.current
        val (icon, tint, detail) = when (measure) {
            Hardening.Measure.InEffect -> Triple(R.drawable.ic_check_circle, status.safe, "In effect, checked.")
            is Hardening.Measure.Pending -> Triple(R.drawable.ic_info, MaterialTheme.colorScheme.onSurfaceVariant, measure.text)
            is Hardening.Measure.Problem -> Triple(R.drawable.ic_warning, MaterialTheme.colorScheme.error, measure.text)
        }
        Row(verticalAlignment = Alignment.Top, modifier = Modifier.testTag(tag)) {
            Icon(painterResource(icon), contentDescription = null, tint = tint, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(10.dp))
            Column {
                Text(label, style = MaterialTheme.typography.bodyMedium)
                if (detail.isNotEmpty()) {
                    Text(detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.testTag("$tag-detail"))
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
        const val MAX_ZOOM = 6f
    }

    /**
     * The third-party notices (§25): this APK's Android libraries, the Rust
     * crates in its native libraries, the data Rift AI learned from (with
     * the model), and the Apache License, as build.sh and notices.gradle.kts
     * wrote them into the assets. One item per line, so
     * the long texts are laid out only as they scroll into view.
     */
    @Composable
    private fun NoticesScreen() {
        BackHandler { showingNotices = false }
        val lines by produceState<List<String>?>(null) {
            value = withContext(Dispatchers.IO) {
                NOTICE_FILES.flatMap { name ->
                    val text = runCatching { assets.open(name).bufferedReader().use { it.readLines() } }
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
                        "Rift is licensed under MIT OR Apache-2.0. It includes the third-party software below, " +
                            "under the licences shown, Google's Material icons, under the Apache License 2.0, " +
                            "and a model learned from the public data listed below.",
                    )
                }
            }
            items(lines ?: listOf("Loading…")) { line ->
                Text(line, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

internal fun format(n: Int): String = NumberFormat.getIntegerInstance().format(n)

/** The notice assets, in the order shown. */
private val NOTICE_FILES = listOf(
    "notices/android-libraries.txt", "notices/rust-crates.txt", "url-model-notice.txt", "notices/apache-2.0.txt",
)
