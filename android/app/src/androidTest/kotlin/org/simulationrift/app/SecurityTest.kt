package org.simulationrift.app

import android.app.ActivityManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.ResultReceiver
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import java.io.File
import java.net.HttpURLConnection
import java.net.NetworkInterface
import java.net.URL
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.MethodSorters
import org.json.JSONArray
import org.simulationrift.bridge.ISession
import org.simulationrift.bridge.NavigationDecision
import org.simulationrift.bridge.Rift
import org.simulationrift.core.DownloadInfo
import org.simulationrift.core.IntelStatus
import org.simulationrift.core.ScanStatus
import org.simulationrift.core.Verdict

/**
 * Security tests that run on the device (docs/architecture.md §23). They
 * run in the controller's main process, drive the browser app like a user
 * would, and read what test pages observed from the fixture server
 * (android/fixtures/server.py, reached through `adb reverse`). They need
 * the browser app and the outsider test app installed, and VPN consent
 * granted to the controller and the outsider (run-tests.sh does both).
 */
@RunWith(AndroidJUnit4::class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class SecurityTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context: Context = instrumentation.targetContext
    private val device: UiDevice = UiDevice.getInstance(instrumentation)

    @Before
    fun startCore() {
        Core.ensureStarted(context)
        awaitLock()
    }

    // ---- S1 / S2: what a page can reach ------------------------------------------

    @Test
    fun s01_pageFindsNoNativeBridge() {
        val results = visit("s1", "/s1.html")
        // The only global allowed is WebView's own window.android.webview
        // (Media Integrity API), and only while it refuses to answer.
        val globals = results.getString("bridge.globals")
        assertTrue(globals, globals == "none" || globals == "android")
        if (globals == "android") {
            assertEquals(
                "MediaIntegrityError|MediaIntegrityTokenProvider|getExperimentalMediaIntegrityTokenProvider",
                results.getString("android.webview.members"),
            )
            assertEquals("REJECTED OperationError: API disabled by application.", results.getString("media_integrity"))
        }
        assertEquals("undefined", results.getString("webkit.messageHandlers"))
        assertEquals("undefined", results.getString("chrome.webview"))
        assertEquals("none", results.getString("plain.objects.with.native.methods"))
    }

    @Test
    fun s02_pageIsDeniedDevicePermissions() {
        val results = visit("s2", "/s2.html")
        assertEquals("true", results.getString("secure_context")) // so the prompts are real
        for (key in listOf("camera", "microphone")) {
            assertTrue("$key: ${results.getString(key)}", results.getString(key).startsWith("DENIED"))
        }
        assertTrue(results.getString("geolocation"), results.getString("geolocation").startsWith("DENIED"))
        assertFalse(results.getString("clipboard_read").startsWith("ALLOWED"))
        assertTrue(results.getString("file_fetch").startsWith("DENIED"))
        assertTrue(results.getString("content_fetch").startsWith("DENIED"))
        assertEquals("BLOCKED", results.getString("window_open"))

        // The OS denies what the manifest never requests (B4).
        val requested = context.packageManager
            .getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS).requestedPermissions.orEmpty()
        val dangerous = requested.filter { name ->
            val info = context.packageManager.getPermissionInfo(name, 0)
            info.protection == PermissionInfo.PROTECTION_DANGEROUS
        }
        assertEquals(emptyList<String>(), dangerous)
        assertTrue("android.permission.INTERNET" in requested)

        // Nor does the browser app, the one pages run in. androidx.core adds a
        // signature permission of the app's own, for its unexported receivers.
        val browser = context.packageManager
            .getPackageInfo(Rift.BROWSER_PACKAGE, PackageManager.GET_PERMISSIONS).requestedPermissions.orEmpty()
            .filter { it != "${Rift.BROWSER_PACKAGE}.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION" }.sorted()
        assertEquals(listOf("android.permission.ACCESS_NETWORK_STATE", "android.permission.INTERNET", Rift.PERMISSION), browser)
    }

    // ---- Navigation policy in the trusted UI (INV-6, §10.2–§10.4) ---------------

    @Test
    fun n1_externalAppLinksAreBlocked() {
        val generation = activeGeneration()
        allowFixtureHost()
        openBrowser(generation, fixture("/links.html?go=" + java.net.URLEncoder.encode("intent://scan/#Intent;scheme=zxing;end", "UTF-8")))
        assertNotNull("block screen", device.wait(Until.findObject(By.text("Page blocked")), PAGE_TIMEOUT_MS))
        assertNotNull(device.findObject(By.textContains("\"intent:\" links are blocked")))
        for (url in listOf("javascript:alert(1)", "file:///data/data/${context.packageName}/files", "content://settings/system", "market://details?id=x")) {
            val decision = Core.decide(generation, url)
            assertTrue("$url: $decision", decision is NavigationDecision.Block)
        }
    }

    @Test
    fun n2_lookalikeAddressNeedsConfirmation() {
        val generation = activeGeneration()
        allowFixtureHost()
        openBrowser(generation, fixture("/links.html?go=" + java.net.URLEncoder.encode("https://paypa1.com/login", "UTF-8")))
        assertNotNull("interstitial", device.wait(Until.findObject(By.res("interstitial")), UI_TIMEOUT_MS))
        assertNotNull(device.findObject(By.textContains("looks like paypal.com")))
        device.findObject(By.res("go-back")).click()
        assertTrue(device.wait(Until.gone(By.res("interstitial")), UI_TIMEOUT_MS))
    }

    @Test
    fun n3_unencryptedPagesAreMarked() {
        visit("s1", "/s1.html")
        assertNotNull(device.wait(Until.findObject(By.textContains("not encrypted")), UI_TIMEOUT_MS))
        assertNotNull(device.findObject(By.textContains("no threat database")))
    }

    @Test
    fun n4_trustedBarClaimsNothingUnchecked() {
        // Before the core has decided on a page, the bar must not summarize
        // one; on an unsupported engine it must say browsing is refused.
        // A fresh session, so no earlier test's page is still on screen.
        val generation = resetAndAwait(activeGeneration())
        context.startActivity(
            Intent().setComponent(Rift.BROWSER_ACTIVITY)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                .putExtra(Rift.EXTRA_GENERATION, generation),
        )
        // The engine's verdict comes from the browser app; the controller
        // has no WebView to ask.
        val deadline = SystemClock.elapsedRealtime() + UI_TIMEOUT_MS
        while (Core.sandbox.value == null && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(50)
        val supported = Core.sandbox.value?.verified ?: throw AssertionError("no sandbox report from :browser")
        val expected = if (supported) "No page checked yet" else "Browsing refused on this device"
        assertNotNull(expected, device.wait(Until.findObject(By.res("protection").text(expected)), UI_TIMEOUT_MS))
        report("n4", "engine supported=$supported; bar: $expected")
    }

    // ---- S8 / S9 / S10: downloads go through the core (INV-13, §11.1) -----------

    @Test
    fun s08_oversizedDownloadStopsAtTheLimit() {
        allowFixtureHost()
        val d = download("/files/big")
        assertTrue("${d.failure}", d.failure?.contains("larger than the 104857600-byte limit") == true)
    }

    @Test
    fun s09_localDestinationsNeedAnExplicitPerHostAllowance() {
        // Not allowed yet in a fresh session: the proxy refuses the page and
        // the core refuses the transfer.
        val generation = resetAndAwait(activeGeneration())
        openBrowser(generation, fixture("/files/hello.txt"))
        awaitDenial("localhost:$FIXTURE_PORT")
        val refused = submit(generation, fixture("/files/hello.txt"))
        assertTrue("${refused.failure}", refused.failure?.contains("resolves to 127.0.0.1") == true)
        // Allowing "localhost" does not allow another name for the same machine.
        allowFixtureHost()
        val literal = submit(generation, fixture("/files/to-loopback"))
        assertTrue("${literal.failure}", literal.failure?.contains("127.0.0.1 resolves to 127.0.0.1") == true)
        val allowed = download("/files/hello.txt")
        assertEquals(1040uL, allowed.file?.size)
    }

    @Test
    fun s10_hostileFilenameIsDisplayOnly() {
        allowFixtureHost()
        val file = download("/files/hostile").file
        assertNotNull(file)
        assertEquals("evilgpj.pdf", file!!.displayName)
        assertTrue(file.id.matches(Regex("[0-9a-f]{32}")))
    }

    @Test
    fun s10b_cookieGatedDownloadIsRefetchedWithItsCookie() {
        allowFixtureHost()
        val file = download("/login?next=/files/private.bin", match = "/files/private.bin").file
        assertNotNull(file)
        assertEquals("private.bin", file!!.displayName)
        assertEquals(1050uL, file.size)
    }

    // ---- S3–S7, S19: the isolated preview worker (§8.6) -----------------------------

    @Test
    fun p1_imagesAndPdfsArePreviewedByAnIsolatedWorker() {
        allowFixtureHost()
        val picture = previewOf(download("/files/picture.png").file!!.id).bitmap
        assertNotNull(picture)
        assertEquals(300 to 200, picture!!.width to picture.height)
        // The fixture is a red-to-the-right, green-downward gradient.
        assertTrue(android.graphics.Color.red(picture.getPixel(290, 5)) > 230)
        assertTrue(android.graphics.Color.green(picture.getPixel(5, 195)) > 230)

        val page = previewOf(download("/files/document.pdf").file!!.id).bitmap
        assertNotNull(page)
        // US Letter fitted into the 2048 x 2048 box; the fixture's blue box spans 72..192 pt from the top.
        assertEquals(2048, page!!.height)
        assertTrue("${page.width}", page.width in 1580..1584)
        assertEquals(android.graphics.Color.BLUE, page.getPixel(page.width / 2, 132 * 2048 / 792))
        assertEquals(android.graphics.Color.WHITE, page.getPixel(10, 10))

        val broken = previewOf(download("/files/broken.png").file!!.id).failure
        assertTrue("$broken", broken?.startsWith("the file could not be previewed") == true)
        report("p1", "picture ${picture.width}x${picture.height}; page ${page.width}x${page.height}; broken: $broken")
    }

    @Test
    fun p2_textIsShownAsEscapedPlainText() {
        allowFixtureHost()
        val preview = previewOf(download("/files/notes.txt").file!!.id)
        assertEquals(null, preview.bitmap)
        assertEquals("line one\nline two \\u{1b}[31mred\\u{1b}[0m \\u{202e}esrever\nRIFT-PREVIEW-PLAINTEXT-MARKER", preview.text)
        assertTrue("${preview.note}", preview.note?.startsWith("Plain text, not interpreted.") == true)
        report("p2", "text ${preview.text?.length} chars; note: ${preview.note}")
    }

    @Test
    fun s03_workerCannotReachAppFiles() {
        val canary = File(context.filesDir, "canary.txt").apply { writeText("worker canary") }
        try {
            val probe = probeWorker(canary)
            assertEquals("true", probe["isolated"])
            assertTrue("${probe["seccomp"]}", probe["seccomp"] != null && probe["seccomp"] != "0")
            for (key in listOf("read_canary", "list_app_files", "write_app_files", "list_external_storage")) {
                assertTrue("$key: ${probe[key]}", probe[key]?.startsWith("DENIED") == true)
            }
            assertFalse(File(context.filesDir, "from-worker").exists())
            report("s03", probe.entries.joinToString(" | ") { "${it.key}=${it.value}" })
        } finally {
            canary.delete()
        }
    }

    @Test
    fun s04_workerCannotReachTheNetworkOrTheCore() {
        val probe = probeWorker(File(context.filesDir, "canary.txt"))
        for (key in listOf("tcp_connect", "udp_socket", "dns", "clipboard", "bind_core", "unix_socket_filtered_thread", "exec_mapping_filtered_thread")) {
            assertTrue("$key: ${probe[key]}", probe[key]?.startsWith("DENIED") == true)
        }
        // isolated_app alone does not deny AF_UNIX sockets or executable
        // mappings (§8.6, PoC A6); only the parser thread's filter does. Reported, not asserted.
        // The product worker's own render path runs under that filter:
        allowFixtureHost()
        val id = download("/files/picture.png").file!!.id
        assertNotNull(previewOf(id, FilterCheckingPreviewService::class.java).bitmap)
        report("s04", probe.entries.joinToString(" | ") { "${it.key}=${it.value}" })
    }

    @Test
    fun s05_malformedWorkerRepliesAreRejected() {
        allowFixtureHost()
        val id = download("/files/picture.png").file!!.id
        for (service in listOf(OversizedPreviewService::class.java, GarbagePreviewService::class.java, ReplayingPreviewService::class.java)) {
            val failure = previewOf(id, service).failure
            assertTrue("${service.simpleName}: $failure", failure?.contains("invalid reply") == true)
            report("s05", "${service.simpleName}: $failure")
        }
        assertNotNull("control", previewOf(id).bitmap)
    }

    @Test
    fun s06_crashingOrHangingWorkerFailsOnlyItsJob() {
        allowFixtureHost()
        val id = download("/files/picture.png").file!!.id
        val crashed = previewOf(id, CrashingPreviewService::class.java).failure
        assertTrue("$crashed", crashed?.contains("stopped unexpectedly") == true)

        val started = SystemClock.elapsedRealtime()
        Core.preview(id, HangingPreviewService::class.java)
        // While the worker hangs, the UI thread keeps answering.
        var slowestUiMs = 0L
        while (Core.previews.value[id]?.running == true) {
            val t = SystemClock.elapsedRealtime()
            instrumentation.runOnMainSync {}
            slowestUiMs = maxOf(slowestUiMs, SystemClock.elapsedRealtime() - t)
            SystemClock.sleep(200)
            if (SystemClock.elapsedRealtime() - started > PREVIEW_TIMEOUT_MS) throw AssertionError("hung preview never ended")
        }
        val hungMs = SystemClock.elapsedRealtime() - started
        val hung = Core.previews.value[id]?.failure
        assertTrue("$hung", hung?.contains("did not render in time") == true)
        assertTrue("$hungMs ms", hungMs in 11_000..20_000)
        assertTrue("UI blocked for $slowestUiMs ms", slowestUiMs < 500)
        assertNotNull("next preview", previewOf(id).bitmap)
        report("s06", "crash: $crashed; hang ended after $hungMs ms: $hung; slowest UI round trip $slowestUiMs ms")
    }

    @Test
    fun s07_unconfinedWorkerIsRefused() {
        allowFixtureHost()
        val marker = File(context.filesDir, UnconfinedPreviewService.MARKER).apply { delete() }
        val id = download("/files/picture.png").file!!.id
        val unconfined = previewOf(id, UnconfinedPreviewService::class.java).failure
        assertTrue("$unconfined", unconfined?.contains("not declared as an isolated process") == true)
        assertFalse("input reached the unconfined worker", marker.exists())
        val processes = context.getSystemService(ActivityManager::class.java).runningAppProcesses.orEmpty().map { it.processName }
        assertFalse("$processes", processes.any { it.endsWith(":unconfined") })

        val noSeccomp = previewOf(id, NoSeccompPreviewService::class.java).failure
        assertTrue("$noSeccomp", noSeccomp?.contains("is not confined") == true)
        report("s07", "non-isolated: $unconfined; no seccomp: $noSeccomp")
    }

    @Test
    fun s19_previewLeavesNoPlaintextOnDisk() {
        allowFixtureHost()
        for (path in listOf("/files/picture.png", "/files/document.pdf")) {
            assertNotNull(path, previewOf(download(path).file!!.id).bitmap)
        }
        assertNotNull(previewOf(download("/files/notes.txt").file!!.id).text)
        val marker = "RIFT-PREVIEW-PLAINTEXT-MARKER".toByteArray()
        val hits = context.dataDir.walkTopDown().filter { it.isFile && contains(it.readBytes(), marker) }
            .map { it.relativeTo(context.dataDir).path }.toList()
        // The engine runs in the browser app, so nothing in the controller may hold it.
        assertEquals(emptyList<String>(), hits)
        report("s19", "plaintext marker found in: ${hits.ifEmpty { listOf("none") }}")
    }

    // ---- S15: unsupported engine configuration (INV-7) --------------------------

    @Test
    fun s15_unverifiedSandboxRefusesBrowsing() {
        // The refusal paths of the check itself are unit tests in the browser
        // module (WebViewSandboxTest), which build.sh runs.
        // A generation whose browser never confirmed its sandbox: everything is blocked.
        val generation = resetAndAwait(activeGeneration())
        val decision = Core.decide(generation, "https://example.org/")
        assertEquals("sandbox-unavailable", (decision as NavigationDecision.Block).reason.code)
        assertFalse(decision.inspectAnyway)
    }

    // ---- S12: reset destroys session state (INV-8) -------------------------------

    @Test
    fun s12_resetDestroysEverySessionStore() {
        val generation = activeGeneration()
        assertEquals("cookie,server_cookie,localStorage,indexedDB,cacheStorage,serviceWorker,httpCache",
            visit("seed", "/seed.html", doneKey = "seeded").getString("seeded"))
        val before = visit("probe-before", "/probe.html?test=probe-before")
        for (key in STORES) assertEquals("control: $key", "PRESENT", before.getString(key))

        val started = SystemClock.elapsedRealtime()
        val next = resetAndAwait(generation)
        val resetMs = SystemClock.elapsedRealtime() - started
        assertTrue(next > generation)
        assertEquals(emptyList<String>(), browserState().second)
        assertEquals(emptyList<String>(), File(context.dataDir, "shared_prefs").list().orEmpty().toList())
        assertFalse(Core.decide(generation, fixture("/probe.html")) is NavigationDecision.Proceed)

        assertFalse(File(context.filesDir, "rift/sessions/$generation").exists())
        assertTrue(Core.downloads.value.isEmpty())

        val after = visit("probe-after", "/probe.html?test=probe-after")
        for (key in STORES) assertEquals(key, "absent", after.getString(key))
        report("s12", "reset_ms=$resetMs generation=$generation->$next")
    }

    // ---- Phase 3: scans and the signed threat database (§12, §13) -----------------

    @Test
    fun s16a_withoutADatabaseScansSayWhatIsMissing() {
        assertTrue("${Core.intel.value}", awaitIntel { it is IntelStatus.Missing } is IntelStatus.Missing)
        allowFixtureHost()
        val plain = verdictOf(download("/files/hello.txt").file!!.id)
        assertEquals(ScanStatus.NOT_FULLY_SCANNED, plain.status)
        assertEquals(2, plain.gaps.size)
        // The type check runs without a database: an executable named as a PDF.
        val mismatch = verdictOf(download("/files/invoice.pdf").file!!.id)
        assertEquals(ScanStatus.SUSPICIOUS, mismatch.status)
        assertEquals(listOf("type"), mismatch.findings.map { it.check })
        report("s16a", "plain: ${plain.label} ${plain.gaps}; invoice.pdf: ${mismatch.label} ${mismatch.findings.map { it.description }}")
    }

    @Test
    fun s16b_tamperedUpdateIsRefused() {
        val copy = File(context.cacheDir, "s16b").apply { deleteRecursively() }
        copyAsset("intel-demo/repo", File(copy, "repo"))
        val rules = File(copy, "repo/targets").listFiles().orEmpty().single { it.name.endsWith("rules.yar") }
        val bytes = rules.readBytes()
        val at = String(bytes, Charsets.US_ASCII).indexOf("MARKER")
        bytes[at] = 'N'.code.toByte() // same length: tough's hash check must catch it
        rules.writeBytes(bytes)
        val root = context.assets.open("intel-demo/root.json").use { it.readBytes() }
        Core.installIntel(root, File(copy, "repo"))
        val message = awaitIntelMessage()
        copy.deleteRecursively()
        assertEquals("the update was refused: a file in it does not match its signature", message)
        assertTrue("${Core.intel.value}", Core.intel.value is IntelStatus.Missing)
        report("s16b", message)
    }

    @Test
    fun s21a_signedDemoDatabaseFindsTheDemoFile() {
        Core.installDemoIntel()
        val installed = awaitIntel { it is IntelStatus.Installed } as? IntelStatus.Installed
        assertNotNull("${Core.intel.value} ${Core.intelMessage.value}", installed)
        assertTrue(installed!!.demo)
        allowFixtureHost()
        // Scans here run in the worker that checks the parser-thread filter
        // is in force on the scan path; if it were not, the rules would not report.
        Core.scanWorker = FilterCheckingPreviewService::class.java
        try {
            val demo = verdictOf(download("/files/demo-file.txt").file!!.id)
            assertEquals(ScanStatus.KNOWN_MALICIOUS, demo.status)
            assertEquals(listOf("file hash", "rules"), demo.findings.map { it.check })
            assertTrue(demo.demo)
            assertEquals(installed.snapshot, demo.snapshot)
            val plain = verdictOf(download("/files/notes.txt").file!!.id)
            assertEquals(ScanStatus.NOT_FLAGGED, plain.status)
            assertEquals(emptyList<String>(), plain.gaps)
            report("s21a", "database ${installed.snapshot}; demo-file.txt: ${demo.label} ${demo.findings.map { "${it.check}:${it.id}" }} ${demo.engine}; notes.txt: ${plain.label}")
        } finally {
            Core.scanWorker = PreviewService::class.java
        }
    }

    @Test
    fun s21b_hungScanWorkerCostsOnlyRuleCoverage() {
        resetAndAwait(activeGeneration()) // a new session: no cached verdicts
        allowFixtureHost()
        Core.scanWorker = HangingScanService::class.java
        try {
            val started = SystemClock.elapsedRealtime()
            val verdict = verdictOf(download("/files/demo-file.txt").file!!.id)
            val elapsed = SystemClock.elapsedRealtime() - started
            // The core's hash check still finds it; the missing rule scan is named.
            assertEquals(ScanStatus.KNOWN_MALICIOUS, verdict.status)
            assertEquals(listOf("file hash"), verdict.findings.map { it.check })
            assertTrue("${verdict.gaps}", verdict.gaps.single().contains("did not scan in time"))
            report("s21b", "hung scan ended after $elapsed ms: ${verdict.label}; ${verdict.gaps}")
        } finally {
            Core.scanWorker = PreviewService::class.java
        }
    }

    // ---- Helpers -------------------------------------------------------------------

    // ---- S23–S28: the browser app and the network lock (§8.3, §8.8, INV-14) -------

    @Test
    fun s23_browserProcessReachesNothingOfRift() {
        val generation = activeGeneration()
        val probe = escapeProbe(stale = generation - 1)
        report("s23", probe.keySet().sorted().joinToString(" | ") { "$it=${probe.getString(it)}" })
        assertEquals(Rift.WEB_PROCESS, probe.text("process"))
        assertTrue("same UID as the controller", probe.text("uid") != android.os.Process.myUid().toString())
        for (key in listOf("file.rift", "file.marker", "file.device", "file.prefs", "bind.worker")) {
            assertTrue("$key: ${probe.text(key)}", probe.text(key).startsWith("DENIED"))
        }
        assertEquals("ALLOWED register=Refused decide=stale-session", probe.text("core.stale"))
    }

    @Test
    fun s24_otherAppsAreRefused() {
        visit("s1", "/s1.html") // the session's proxy is running from here on
        val port = Core.egressPort() ?: throw AssertionError("the proxy is not running")
        val before = Core.egressStats()!!.unauthenticated
        val result = outsider("proxyPort" to port)
        report("s24", result.keySet().sorted().joinToString(" | ") { "$it=${result.getString(it)}" })
        assertEquals("DENIED", result.text("permission"))
        for (key in listOf("bind.session", "bind.core", "start.browser")) {
            assertTrue("$key: ${result.text(key)}", result.text(key).startsWith("DENIED SecurityException"))
        }
        for (key in listOf("proxy.none", "proxy.wrong")) {
            assertEquals(key, "ALLOWED HTTP/1.1 407 Proxy Authentication Required", result.text(key))
        }
        assertTrue(Core.egressStats()!!.unauthenticated >= before + 2u)
    }

    @Test
    fun s25_pagesCannotReachLocalOrPrivateAddresses() {
        http("/arrivals/clear")
        val page = visit("s25", "/reach.html?test=s25")
        val arrived = arrivals()
        val refused = Core.egressStats()?.recent.orEmpty().map { it.destination }
        report("s25", "page: $page; arrived: $arrived; refused by the proxy: $refused")
        // The control arrives, so the page ran and the log works; nothing else does.
        assertEquals(listOf("tcp control"), arrived.filter { it.startsWith("tcp") }.map { it.substringBefore(" host=") })
        for (destination in listOf("127.0.0.1:$FIXTURE_PORT", "10.0.2.2:$FIXTURE_PORT")) {
            assertTrue("$destination not in $refused", destination in refused)
        }
    }

    @Test
    fun s26_webrtcAndDirectSocketsHaveNoRoute() {
        http("/arrivals/clear")
        val page = visit("s26", "/reach.html?test=s26")
        val probe = escapeProbe(stale = 0)
        SystemClock.sleep(1_000) // time for a datagram that got through to arrive
        val arrived = arrivals()
        val candidates = page.getString("webrtc").lines().mapNotNull { it.split(' ').getOrNull(4) }
        val device = NetworkInterface.getNetworkInterfaces().toList()
            .filter { !it.isLoopback && !it.name.startsWith("tun") }
            .flatMap { it.inetAddresses.toList() }
            .map { it.hostAddress.orEmpty().substringBefore('%') }
        val dropped = NetworkLock.dropped.value
        report("s26", "candidates: $candidates; device addresses: $device; arrived: $arrived; dropped: $dropped; " +
            listOf("tcp.host", "tcp.public", "tcp.loopback", "udp.host", "dns").joinToString(" | ") { "$it=${probe.getString(it)}" })
        assertEquals(emptyList<String>(), arrived.filter { it.startsWith("udp") })
        assertEquals(listOf("tcp control"), arrived.filter { it.startsWith("tcp") }.map { it.substringBefore(" host=") })
        for (address in device) assertFalse("WebRTC exposed $address: $candidates", address in candidates)
        for (key in listOf("tcp.host", "tcp.public", "dns")) {
            assertTrue("$key: ${probe.text(key)}", probe.text(key).startsWith("DENIED"))
        }
        assertTrue("$dropped", dropped.destinations.any { it == "UDP 10.0.2.2:3478" })
        // Loopback is not routed through any VPN (§8.3): reported above, not asserted.
    }

    @Test
    fun s27_resetWipesTheBrowserApp() {
        val generation = activeGeneration()
        visit("seed", "/seed.html", doneKey = "seeded")
        val (pidBefore, filesBefore) = browserState()
        // Control: the inventory does see the engine's state.
        assertTrue("$filesBefore", filesBefore.any { "_s$generation" in it })
        val started = SystemClock.elapsedRealtime()
        val next = resetAndAwait(generation)
        val resetMs = SystemClock.elapsedRealtime() - started
        val (pidAfter, filesAfter) = browserState()
        assertTrue("pid $pidAfter", pidAfter != pidBefore)
        assertEquals(emptyList<String>(), filesAfter)
        report("s27", "generation $generation->$next in $resetMs ms; browser pid $pidBefore->$pidAfter; files ${filesBefore.size}->${filesAfter.size}")
    }

    @Test
    fun s28_losingTheLockEndsTheSessionAndWipesTheBrowser() {
        val generation = activeGeneration()
        visit("s1", "/s1.html")
        try {
            outsider("vpn" to "take")
            val deadline = SystemClock.elapsedRealtime() + CORE_TIMEOUT_MS
            while (NetworkLock.state.value !is NetworkLock.State.Lost) {
                if (SystemClock.elapsedRealtime() > deadline) throw AssertionError("lock not lost: ${NetworkLock.state.value}")
                SystemClock.sleep(50)
            }
            val next = activeGenerationAfter(generation)
            assertTrue("${Core.notice.value}", Core.notice.value?.contains("network lock stopped") == true)
            assertEquals(emptyList<String>(), browserState().second)
            assertFalse(Core.decide(generation, fixture("/s1.html")) is NavigationDecision.Proceed)
            // Rift does not take the VPN back from the other app on its own.
            NetworkLock.start(context, userAction = false)
            SystemClock.sleep(500)
            assertTrue("${NetworkLock.state.value}", NetworkLock.state.value is NetworkLock.State.Lost)
            // Without the lock the browser refuses to load anything.
            openBrowser(next, fixture("/s1.html"))
            assertNotNull("refusal", device.wait(Until.findObject(By.textContains("network lock is off")), UI_TIMEOUT_MS))
            report("s28", "lock lost: ${NetworkLock.state.value}; session $generation -> $next; browser wiped")
        } finally {
            outsider("vpn" to "release")
            Core.dismissNotice()
            awaitLock()
        }
    }

    @Test
    fun s28b_reducedIsolationIsChosenAndLabelled() {
        val generation = resetAndAwait(activeGeneration())
        Core.useReducedIsolation(generation)
        openBrowser(generation, null)
        assertNotNull("label", device.wait(Until.findObject(By.res("reduced")), UI_TIMEOUT_MS))
        // Only for that session.
        val next = resetAndAwait(generation)
        assertTrue(Core.reduced.value != next)
        report("s28b", "generation $generation ran with reduced isolation, labelled; $next did not")
    }

    private fun escapeProbe(stale: Long): Bundle = ask(
        Intent().setComponent(ComponentName(Rift.BROWSER_PACKAGE, "${Rift.BROWSER_PACKAGE}.EscapeProbeActivity"))
            .putExtra("fixturePort", FIXTURE_PORT)
            .putExtra("staleGeneration", stale),
        ESCAPE_TIMEOUT_MS,
    )

    private fun activeGenerationAfter(generation: Long): Long {
        val deadline = SystemClock.elapsedRealtime() + CORE_TIMEOUT_MS
        while (SystemClock.elapsedRealtime() < deadline) {
            val state = Core.state.value
            if (state is Core.State.Active && state.generation != generation) return state.generation
            if (state is Core.State.Failed) throw AssertionError("session failed: ${state.message}")
            SystemClock.sleep(20)
        }
        throw AssertionError("no new session after $generation: ${Core.state.value}")
    }

    private fun awaitIntel(done: (IntelStatus?) -> Boolean): IntelStatus? {
        val deadline = SystemClock.elapsedRealtime() + SCAN_TIMEOUT_MS
        while (!done(Core.intel.value) && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(50)
        return Core.intel.value
    }

    private fun awaitIntelMessage(): String {
        val deadline = SystemClock.elapsedRealtime() + SCAN_TIMEOUT_MS
        while (SystemClock.elapsedRealtime() < deadline) {
            Core.intelMessage.value?.takeIf { it != "Checking the update…" }?.let { return it }
            SystemClock.sleep(50)
        }
        throw AssertionError("no install outcome: ${Core.intelMessage.value}")
    }

    /** Waits for the scan that follows each download. */
    private fun verdictOf(id: String): Verdict {
        val deadline = SystemClock.elapsedRealtime() + SCAN_TIMEOUT_MS
        while (SystemClock.elapsedRealtime() < deadline) {
            Core.verdicts.value[id]?.let { return it }
            SystemClock.sleep(50)
        }
        throw AssertionError("no verdict for $id: ${Core.verdicts.value}")
    }

    private fun copyAsset(path: String, target: File) {
        val children = context.assets.list(path).orEmpty()
        if (children.isEmpty()) {
            target.parentFile?.mkdirs()
            context.assets.open(path).use { input -> target.outputStream().use { input.copyTo(it) } }
        } else {
            for (child in children) copyAsset("$path/$child", File(target, child))
        }
    }

    private fun activeGeneration(): Long {
        val deadline = SystemClock.elapsedRealtime() + CORE_TIMEOUT_MS
        while (SystemClock.elapsedRealtime() < deadline) {
            when (val state = Core.state.value) {
                is Core.State.Active -> return state.generation
                is Core.State.Failed -> throw AssertionError("session failed: ${state.message}")
                else -> SystemClock.sleep(50)
            }
        }
        throw AssertionError("no active session: ${Core.state.value}")
    }

    private fun resetAndAwait(generation: Long): Long {
        Core.reset(generation)
        val deadline = SystemClock.elapsedRealtime() + CORE_TIMEOUT_MS
        while (SystemClock.elapsedRealtime() < deadline) {
            val state = Core.state.value
            if (state is Core.State.Active && state.generation != generation) return state.generation
            if (state is Core.State.Failed) throw AssertionError("reset failed: ${state.message}")
            SystemClock.sleep(20)
        }
        throw AssertionError("reset did not finish: ${Core.state.value}")
    }

    private fun openBrowser(generation: Long, url: String?) {
        context.startActivity(
            Intent().setComponent(Rift.BROWSER_ACTIVITY)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                .putExtra(Rift.EXTRA_GENERATION, generation)
                .apply { url?.let { putExtra(Rift.EXTRA_URL, it) } },
        )
        // The first start of the engine on a freshly booted emulator can take
        // most of the UI timeout by itself (n1 on API 33 in CI).
        val deadline = SystemClock.elapsedRealtime() + ENGINE_START_TIMEOUT_MS
        while (Core.sandbox.value == null && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(50)
    }

    /** Opens a fixture page in the current session and waits for its report. */
    private fun visit(test: String, path: String, doneKey: String = "done"): JSONObject {
        // The proxy refuses local names unless the session allows them (INV-13).
        allowFixtureHost()
        http("/clear?test=$test")
        openBrowser(activeGeneration(), fixture(path))
        val deadline = SystemClock.elapsedRealtime() + PAGE_TIMEOUT_MS
        while (SystemClock.elapsedRealtime() < deadline) {
            val results = JSONObject(http("/results?test=$test"))
            if (results.has(doneKey)) return results
            if (results.has("probe_error") || results.has("seed_error")) throw AssertionError("page error: $results")
            SystemClock.sleep(100)
        }
        throw AssertionError("page $path did not report $doneKey")
    }

    private fun allowFixtureHost() {
        Core.allowLocalHost("localhost")
        val deadline = SystemClock.elapsedRealtime() + CORE_TIMEOUT_MS
        while ("localhost" !in Core.localHosts.value) {
            if (SystemClock.elapsedRealtime() > deadline) throw AssertionError("allowance not applied")
            SystemClock.sleep(20)
        }
    }

    /** Navigates to a download URL and waits for the core's outcome for it. */
    private fun download(path: String, match: String = path): Core.Download {
        val before = Core.downloads.value.map { it.key }.toSet()
        openBrowser(activeGeneration(), fixture(path))
        return awaitDownload(before, path, match)
    }

    /** Hands `url` to the core as the engine would, without the browser. */
    private fun submit(generation: Long, url: String, match: String = url): Core.Download {
        val before = Core.downloads.value.map { it.key }.toSet()
        Core.submitDownload(generation, DownloadInfo(url, null, "rift-test", null, null))
        return awaitDownload(before, url, match)
    }

    private fun awaitDownload(before: Set<Long>, path: String, match: String): Core.Download {
        val deadline = SystemClock.elapsedRealtime() + DOWNLOAD_TIMEOUT_MS
        while (SystemClock.elapsedRealtime() < deadline) {
            Core.downloads.value.firstOrNull { it.key !in before && match in it.url && !it.running }?.let {
                report("download", "$path -> ${it.file ?: it.failure}")
                return it
            }
            SystemClock.sleep(100)
        }
        throw AssertionError("no finished download for $path: ${Core.downloads.value}")
    }

    /** Starts a preview and waits for its outcome. */
    private fun previewOf(id: String, service: Class<out android.app.Service> = PreviewService::class.java): Core.Preview {
        Core.preview(id, service)
        val deadline = SystemClock.elapsedRealtime() + PREVIEW_TIMEOUT_MS
        while (SystemClock.elapsedRealtime() < deadline) {
            Core.previews.value[id]?.takeIf { !it.running }?.let { return it }
            SystemClock.sleep(50)
        }
        throw AssertionError("preview of $id did not finish")
    }

    /** Asks a fresh worker-identical isolated process what it can reach. */
    private fun probeWorker(canary: File): Map<String, String> {
        val connected = CompletableFuture<IWorkerProbe>()
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                connected.complete(IWorkerProbe.Stub.asInterface(service))
            }

            override fun onServiceDisconnected(name: ComponentName) = Unit
        }
        val intent = Intent(context, ProbeWorkerService::class.java)
        assertTrue(context.bindIsolatedService(intent, Context.BIND_AUTO_CREATE, "probe_${SystemClock.elapsedRealtimeNanos()}", context.mainExecutor, connection))
        try {
            val text = connected.get(10, TimeUnit.SECONDS).probe(canary.path, FIXTURE_PORT)
            return text.lines().filter { '=' in it }.associate { it.substringBefore('=') to it.substringAfter('=') }
        } finally {
            context.unbindService(connection)
        }
    }

    private fun contains(haystack: ByteArray, needle: ByteArray): Boolean =
        (0..haystack.size - needle.size).any { i -> needle.indices.all { haystack[i + it] == needle[it] } }

    /** The browser app's session service: its process id and every file the app holds. */
    private fun browserState(): Pair<Int, List<String>> {
        val connected = CompletableFuture<ISession>()
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                connected.complete(ISession.Stub.asInterface(service))
            }

            override fun onServiceDisconnected(name: ComponentName) = Unit
        }
        assertTrue(context.bindService(Intent().setComponent(Rift.SESSION_SERVICE), connection, Context.BIND_AUTO_CREATE))
        try {
            val session = connected.get(10, TimeUnit.SECONDS)
            return session.pid() to session.inventory()
        } finally {
            context.unbindService(connection)
        }
    }

    /** Starts `intent` (an activity of another app) and waits for the Bundle it sends back. */
    private fun ask(intent: Intent, timeoutMs: Long = PAGE_TIMEOUT_MS): Bundle {
        val answer = CompletableFuture<Bundle>()
        val receiver = object : ResultReceiver(Handler(Looper.getMainLooper())) {
            override fun onReceiveResult(resultCode: Int, resultData: Bundle?) {
                answer.complete(resultData ?: Bundle())
            }
        }
        // Re-parcelled as a plain ResultReceiver: the other app cannot load this subclass.
        val parcel = android.os.Parcel.obtain()
        val plain = try {
            receiver.writeToParcel(parcel, 0)
            parcel.setDataPosition(0)
            ResultReceiver.CREATOR.createFromParcel(parcel)
        } finally {
            parcel.recycle()
        }
        context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK).putExtra("receiver", plain))
        return answer.get(timeoutMs, TimeUnit.MILLISECONDS)
    }

    private fun Bundle.text(key: String): String = getString(key) ?: throw AssertionError("no $key in $this")

    private fun awaitLock() {
        NetworkLock.start(context, userAction = true)
        val deadline = SystemClock.elapsedRealtime() + CORE_TIMEOUT_MS
        while (NetworkLock.state.value != NetworkLock.State.Active) {
            if (SystemClock.elapsedRealtime() > deadline) {
                throw AssertionError("network lock not active: ${NetworkLock.state.value} (run-tests.sh grants VPN consent)")
            }
            SystemClock.sleep(50)
        }
    }

    /** Waits until the proxy has refused `destination` in this session. */
    private fun awaitDenial(destination: String) {
        val deadline = SystemClock.elapsedRealtime() + PAGE_TIMEOUT_MS
        while (Core.egressStats()?.recent?.none { it.destination == destination } != false) {
            if (SystemClock.elapsedRealtime() > deadline) throw AssertionError("no refusal of $destination: ${Core.egressStats()}")
            SystemClock.sleep(100)
        }
    }

    private fun arrivals(): List<String> {
        val list = JSONArray(http("/arrivals"))
        return (0 until list.length()).map { list.getString(it) }
    }

    private fun outsider(vararg extras: Pair<String, Any>): Bundle {
        val intent = Intent().setComponent(ComponentName(OUTSIDER, "$OUTSIDER.OutsiderActivity"))
        for ((key, value) in extras) {
            when (value) {
                is Int -> intent.putExtra(key, value)
                is String -> intent.putExtra(key, value)
                else -> throw IllegalArgumentException("$key")
            }
        }
        return ask(intent)
    }

    private fun report(test: String, line: String) = android.util.Log.i(TAG, "result $test: $line")

    private fun fixture(path: String) = "http://localhost:$FIXTURE_PORT$path"

    private fun http(path: String): String {
        val connection = URL(fixture(path)).openConnection() as HttpURLConnection
        return try {
            connection.inputStream.bufferedReader().readText()
        } finally {
            connection.disconnect()
        }
    }

    private companion object {
        const val OUTSIDER = "org.simulationrift.outsider"
        const val FIXTURE_PORT = 8766
        const val UI_TIMEOUT_MS = 10_000L
        const val PAGE_TIMEOUT_MS = 20_000L
        const val CORE_TIMEOUT_MS = 15_000L
        const val ENGINE_START_TIMEOUT_MS = 30_000L
        const val DOWNLOAD_TIMEOUT_MS = 120_000L
        const val PREVIEW_TIMEOUT_MS = 30_000L
        const val SCAN_TIMEOUT_MS = 40_000L
        // DNS through the lock fails only after the resolver's own timeouts.
        const val ESCAPE_TIMEOUT_MS = 90_000L
        val STORES = listOf("cookie", "server_cookie", "localStorage", "indexedDB", "cacheStorage", "serviceWorker")
    }
}
