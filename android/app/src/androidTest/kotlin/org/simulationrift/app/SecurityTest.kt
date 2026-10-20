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
import android.view.inputmethod.EditorInfo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.UiObject2
import androidx.test.uiautomator.Until
import java.io.File
import java.net.HttpURLConnection
import java.net.NetworkInterface
import java.net.URL
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.MethodSorters
import org.json.JSONArray
import org.simulationrift.bridge.ISession
import org.simulationrift.bridge.NavigationDecision
import org.simulationrift.bridge.PageWatch
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
        // A system "isn't responding" dialog would cover the windows under
        // test; run-tests.sh records every ANR in anr.txt.
        device.executeShellCommand("am broadcast -a android.intent.action.CLOSE_SYSTEM_DIALOGS")
        Core.ensureStarted(context)
        awaitLock()
        recoverFromEarlierFailure()
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
        assertTrue("android.permission.USE_BIOMETRIC" in requested) // the vault prompt (§8.7)

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
        val earlier = Core.sandbox.value
        // Right after a wipe the window can be removed before it attaches
        // (finding 47); Core.openWindow then opens it again.
        Core.openWindow(context, generation, null)
        // The engine's verdict comes from the browser app (the controller has
        // no WebView to ask), as a new report for this window.
        val deadline = SystemClock.elapsedRealtime() + ENGINE_START_TIMEOUT_MS
        while (Core.sandbox.value === earlier && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(50)
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
    fun s16c_importedFolderIsCopiedVerifiedAndRemoved() {
        // A folder as a user might choose it: the repository plus things that are not part of it.
        val chosen = File(context.cacheDir, "s16c").apply { deleteRecursively() }
        copyAsset("intel-demo/repo", chosen)
        File(chosen, "notes.txt").writeText("not part of the repository")
        File(chosen, "targets/.DS_Store").writeText("x")
        File(chosen, "targets/nested").mkdirs()
        val staging = File(context.filesDir, "rift/import")
        try {
            // Without targets/, nothing is installed and the user is told why.
            File(chosen, "targets").renameTo(File(context.cacheDir, "s16c-targets"))
            Core.importIntel(IntelImport.FileTree(chosen))
            val missing = awaitIntelMessage()
            assertEquals("the update was not read: the folder has no targets directory; choose the repository folder itself", missing)
            File(context.cacheDir, "s16c-targets").renameTo(File(chosen, "targets"))

            Core.importIntel(IntelImport.FileTree(chosen))
            val message = awaitIntelMessage()
            assertTrue(message, message.startsWith("Installed demo-"))
            val installed = Core.intel.value as? IntelStatus.Installed
            assertNotNull("${Core.intel.value}", installed)
            // The copy is removed after the attempt, on the same executor.
            val deadline = SystemClock.elapsedRealtime() + UI_TIMEOUT_MS
            while (staging.exists() && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(50)
            assertFalse("staging copy left behind", staging.exists())
            report("s16c", "without targets: $missing; then: $message")
        } finally {
            chosen.deleteRecursively()
            File(context.cacheDir, "s16c-targets").deleteRecursively()
        }
    }

    @Test
    fun s16e_onlineUpdateUsesTheCoresCheckedFetcher() {
        // A fresh session first (its reset refuses unexpected files, such as
        // the copy below): localhost is a loopback name, refused without the
        // user's allowance (INV-13).
        resetAndAwait(activeGeneration())
        // The signed demo repository, served on loopback inside this process.
        val served = File(context.cacheDir, "s16e").apply { deleteRecursively() }
        copyAsset("intel-demo/repo", served)
        val server = java.net.ServerSocket(0, 8, java.net.InetAddress.getByName("127.0.0.1"))
        val requests = java.util.concurrent.atomic.AtomicInteger()
        thread(name = "s16e-server", isDaemon = true) { serveFiles(server, served, requests) }
        try {
            val base = "http://localhost:${server.localPort}"
            Core.updateIntelOnline(base)
            val refused = awaitIntelMessage()
            assertEquals("the update was refused: the update server could not be reached, or is not an allowed destination", refused)
            assertEquals("no request reached the server", 0, requests.get())

            allowFixtureHost()
            Core.updateIntelOnline(base)
            val message = awaitIntelMessage()
            assertTrue(message, message.startsWith("Installed demo-"))
            assertTrue("${Core.intel.value}", Core.intel.value is IntelStatus.Installed)
            report("s16e", "without the allowance: $refused; with it: $message after ${requests.get()} requests")
        } finally {
            server.close()
            served.deleteRecursively()
        }
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
            val hung = download("/files/demo-file.txt").file!!.id
            // Queued for the hanging worker; files after it get a working one.
            val queued = SystemClock.elapsedRealtime() + UI_TIMEOUT_MS
            while (!Core.verdicts.value.containsKey(hung)) {
                if (SystemClock.elapsedRealtime() > queued) throw AssertionError("no scan queued for $hung")
                SystemClock.sleep(10)
            }
            Core.scanWorker = PreviewService::class.java
            // A second scan finishes while the first worker still hangs (bounded pool).
            val plain = verdictOf(download("/files/notes.txt").file!!.id)
            val plainAt = SystemClock.elapsedRealtime() - started
            assertEquals(ScanStatus.NOT_FLAGGED, plain.status)
            assertNull("the hung scan finished first", Core.verdicts.value[hung])
            val verdict = verdictOf(hung)
            val elapsed = SystemClock.elapsedRealtime() - started
            // The core's hash check still finds it; the missing rule scan is named.
            assertEquals(ScanStatus.KNOWN_MALICIOUS, verdict.status)
            assertEquals(listOf("file hash"), verdict.findings.map { it.check })
            assertTrue("${verdict.gaps}", verdict.gaps.single().contains("did not scan in time"))
            report("s21b", "hung scan ended after $elapsed ms: ${verdict.label}; ${verdict.gaps}; a scan queued after it finished at $plainAt ms: ${plain.label}")
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
            // On CI (API 34) the new window's task was once removed by Android
            // 50 ms after it started, right after the wipe; the window is
            // opened again (bounded) and each attempt is reported.
            var attempts = 0
            var refusal: UiObject2? = null
            while (refusal == null && attempts < WINDOW_ATTEMPTS) {
                attempts++
                openBrowser(next, fixture("/s1.html"))
                refusal = device.wait(Until.findObject(By.textContains("network lock is off")), UI_TIMEOUT_MS)
            }
            assertNotNull("refusal after $attempts windows", refusal)
            report("s28", "lock lost: ${NetworkLock.state.value}; session $generation -> $next; browser wiped; windows opened: $attempts")
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
        val deadline = SystemClock.elapsedRealtime() + SESSION_TIMEOUT_MS
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
            Core.intelMessage.value?.takeIf { it !in PROGRESS }?.let { return it }
            SystemClock.sleep(50)
        }
        throw AssertionError("no install outcome: ${Core.intelMessage.value}")
    }

    // ---- Phase 4: the Rift Vault (§14, S18 on the device) ---------------------------

    @Test
    fun v1_keptFileOutlivesTheSessionAndNoPlaintextIsOnDisk() {
        destroyVault()
        Locker.createWithPassphrase(PASSPHRASE.toByteArray())
        awaitVault<Locker.State.Unlocked>()
        allowFixtureHost()
        val file = submit(activeGeneration(), fixture("/files/notes.txt")).file!!
        Core.keep(file.id)
        awaitCondition("kept") { file.id in Locker.kept.value }
        val entry = (Locker.state.value as Locker.State.Unlocked).entries.single()
        assertEquals(file.sha256, entry.sha256)
        assertEquals("notes.txt", entry.displayName)

        // On disk: the scrypt-wrapped identity, the index (and the one before,
        // for crash recovery) and one sealed object, nothing readable.
        val vault = File(context.filesDir, "rift/vault")
        val stored = vault.walkTopDown().filter { it.isFile }.map { it.relativeTo(vault).path }.sorted().toList()
        assertEquals(listOf("identity.pass", "index.age", "index.age.prev", "objects/${entry.id}.age"), stored)
        assertEquals(emptyList<String>(), filesContaining(MARKER) + filesContaining("AGE-SECRET-KEY-".toByteArray()))

        // The session ends; the kept copy does not, and the reset's leftover check accepts it.
        val next = resetAndAwait(activeGeneration())
        assertTrue(Locker.kept.value.isEmpty())
        Locker.lock()
        awaitVault<Locker.State.Locked>()
        val wrong = vaultMessageOf { Locker.unlockWithPassphrase("not the passphrase".toByteArray()) }
        assertEquals("The vault was not unlocked: the passphrase or key does not open this vault", wrong)
        assertTrue(Locker.state.value is Locker.State.Locked)
        Locker.unlockWithPassphrase(PASSPHRASE.toByteArray())
        val reopened = awaitVault<Locker.State.Unlocked>()
        assertEquals(listOf(entry), reopened.entries)

        // Export writes the original bytes where the user chose; then the file is removed.
        val exported = File(context.cacheDir, "v1-export").apply { delete() }
        assertEquals(
            "Exported. The copy is outside Rift's protection now, and was not made safe.",
            vaultMessageOf { Locker.export(entry.id, android.net.Uri.fromFile(exported)) },
        )
        assertTrue(contains(exported.readBytes(), MARKER))
        exported.delete()
        assertEquals("Removed from the vault.", vaultMessageOf { Locker.remove(entry.id) })
        assertTrue((Locker.state.value as Locker.State.Unlocked).entries.isEmpty())
        assertFalse(File(vault, "objects/${entry.id}.age").exists())
        report("v1", "stored=$stored; after reset to $next: wrong passphrase -> \"$wrong\"; reopened ${reopened.entries.size} entry")
        destroyVault()
    }

    @Test
    fun v2_vaultLocksInTheBackgroundAndWhenIdle() {
        destroyVault()
        Locker.createWithPassphrase(PASSPHRASE.toByteArray())
        awaitVault<Locker.State.Unlocked>()
        val home = openHome()
        assertTrue(Locker.state.value is Locker.State.Unlocked)
        device.pressHome()
        awaitVault<Locker.State.Locked>()
        home.finish()

        val idle = Locker.inactivityMs
        try {
            Locker.inactivityMs = 1_500
            Locker.unlockWithPassphrase(PASSPHRASE.toByteArray())
            awaitVault<Locker.State.Unlocked>()
            val started = SystemClock.elapsedRealtime()
            awaitVault<Locker.State.Locked>()
            report("v2", "locked on Home; idle lock after ${SystemClock.elapsedRealtime() - started} ms (limit 1500)")
        } finally {
            Locker.inactivityMs = idle
        }
        destroyVault()
    }

    /**
     * The Keystore key (§8.7) through the real BiometricPrompt: a PIN set by
     * the shell, typed into the system's credential screen. Removing the PIN
     * deletes the key, and the vault says so instead of opening; the recovery
     * passphrase opens it, and a new PIN's key protects it again.
     */
    @Test
    fun v3_keystoreVaultNeedsTheScreenLockAndRecoversWithItsPassphrase() {
        destroyVault()
        device.executeShellCommand("locksettings set-pin $PIN")
        try {
            awaitCondition("secure lock screen") { VaultKeystore.deviceSecure(context) }
            Locker.open(context) // refreshes the state, which now offers the keystore
            awaitCondition("keystore offered") { (Locker.state.value as? Locker.State.Absent)?.deviceSecure == true }
            val home = openHome()
            Locker.createWithDeviceLock(home)
            enterPin()
            val created = awaitVault<Locker.State.Unlocked>()
            assertNotNull(created.keyLevel)
            assertFalse(created.recovery)
            val wrapped = File(context.filesDir, "rift/vault/identity.platform").readBytes()
            assertFalse(contains(wrapped, "AGE-SECRET-KEY-".toByteArray()))
            Locker.setRecoveryPassphrase(RECOVERY.toByteArray())
            awaitCondition("recovery set") { (Locker.state.value as? Locker.State.Unlocked)?.recovery == true }

            Locker.lock()
            awaitVault<Locker.State.Locked>()
            Locker.unlockWithDeviceLock(home)
            enterPin()
            awaitVault<Locker.State.Unlocked>()
            Locker.lock()
            awaitVault<Locker.State.Locked>()
            home.finish()

            device.executeShellCommand("locksettings clear --old $PIN")
            awaitCondition("lock screen removed") { !VaultKeystore.deviceSecure(context) }
            val again = openHome()
            val invalidated = vaultMessageOf { Locker.unlockWithDeviceLock(again) }
            assertEquals(VaultKeystore.INVALIDATED_RECOVERABLE, invalidated)
            val wrong = vaultMessageOf { Locker.unlockWithRecovery("not the recovery passphrase".toByteArray()) }
            assertEquals("The vault was not unlocked: the passphrase or key does not open this vault", wrong)
            Locker.unlockWithRecovery(RECOVERY.toByteArray())
            val recovered = awaitVault<Locker.State.Unlocked>()
            assertNull("the old key is gone", recovered.keyLevel)

            // A new screen lock, a new key: the same vault opens through the prompt again.
            device.executeShellCommand("locksettings set-pin $PIN")
            awaitCondition("secure lock screen again") { VaultKeystore.deviceSecure(context) }
            Locker.protectAgain(again)
            enterPin()
            awaitCondition("protected again") { (Locker.state.value as? Locker.State.Unlocked)?.keyLevel != null }
            Locker.lock()
            awaitVault<Locker.State.Locked>()
            Locker.unlockWithDeviceLock(again)
            enterPin()
            awaitVault<Locker.State.Unlocked>()
            again.finish()
            report(
                "v3",
                "key in ${created.keyLevel}; ${wrapped.size}-byte wrapped identity; after the PIN was removed: $invalidated; " +
                    "recovered with the recovery passphrase, protected by a new key and unlocked through the prompt again",
            )
        } finally {
            device.executeShellCommand("locksettings clear --old $PIN")
            destroyVault()
        }
    }

    @Test
    fun v4_keptFilesPreviewInAnIsolatedWorkerUntilLocked() {
        destroyVault()
        Locker.createWithPassphrase(PASSPHRASE.toByteArray())
        awaitVault<Locker.State.Unlocked>()
        allowFixtureHost()
        val file = submit(activeGeneration(), fixture("/files/picture.png")).file!!
        Core.keep(file.id)
        awaitCondition("kept") { file.id in Locker.kept.value }
        val entry = (Locker.state.value as Locker.State.Unlocked).entries.single()
        resetAndAwait(activeGeneration())

        // After the session: rendered from the vault's copy, by a fresh worker.
        Locker.preview(entry.id)
        val deadline = SystemClock.elapsedRealtime() + PREVIEW_TIMEOUT_MS
        var preview = Locker.previews.value[entry.id]
        while ((preview == null || preview.running) && SystemClock.elapsedRealtime() < deadline) {
            SystemClock.sleep(50)
            preview = Locker.previews.value[entry.id]
        }
        val bitmap = preview?.bitmap
        assertNotNull("${preview?.failure}", bitmap)
        assertEquals(emptyList<String>(), filesContaining(MARKER))

        // Locking clears what is shown.
        Locker.lock()
        awaitVault<Locker.State.Locked>()
        assertTrue(Locker.previews.value.isEmpty())
        report("v4", "vault preview ${bitmap!!.width}x${bitmap.height} after the session ended; cleared on lock")
        destroyVault()
    }

    @Test
    fun v5_keptFilesKeepTheVerdictTheyHadAsHistory() {
        destroyVault()
        Core.installDemoIntel()
        assertTrue("${Core.intelMessage.value}", awaitIntel { it is IntelStatus.Installed } is IntelStatus.Installed)
        Locker.createWithPassphrase(PASSPHRASE.toByteArray())
        awaitVault<Locker.State.Unlocked>()
        allowFixtureHost()
        val file = submit(activeGeneration(), fixture("/files/demo-file.txt")).file!!
        val verdict = verdictOf(file.id)
        assertEquals(ScanStatus.KNOWN_MALICIOUS, verdict.status)
        Core.keep(file.id)
        awaitCondition("kept") { file.id in Locker.kept.value }
        resetAndAwait(activeGeneration())

        val scan = (Locker.state.value as Locker.State.Unlocked).entries.single().scan
        assertNotNull("no verdict kept", scan)
        assertEquals("Known malicious", scan!!.label)
        assertEquals(verdict.snapshot, scan.snapshot)
        assertTrue(scan.demo)
        assertEquals(verdict.findings.map { "${it.check}:${it.id}" }, scan.findings)
        report("v5", "kept with: ${scan.label} ${scan.findings} database ${scan.snapshot}")
        destroyVault()
    }

    @Test
    fun v6_keptFilesAreScannedAgainWithTheCurrentDatabase() {
        destroyVault()
        Core.installDemoIntel()
        assertTrue("${Core.intelMessage.value}", awaitIntel { it is IntelStatus.Installed } is IntelStatus.Installed)
        Locker.createWithPassphrase(PASSPHRASE.toByteArray())
        awaitVault<Locker.State.Unlocked>()
        allowFixtureHost()
        val file = submit(activeGeneration(), fixture("/files/demo-file.txt")).file!!
        Core.keep(file.id)
        awaitCondition("kept") { file.id in Locker.kept.value }
        // The session and its quarantined copy end; the vault's copy is scanned.
        resetAndAwait(activeGeneration())
        val id = (Locker.state.value as Locker.State.Unlocked).entries.single().id
        val started = System.currentTimeMillis() / 1000

        val message = vaultMessageOf { Locker.rescan(id) }
        assertTrue(message, message.startsWith("Scanned again: Known malicious"))
        val scan = (Locker.state.value as Locker.State.Unlocked).entries.single().scan
        assertNotNull("no scan recorded", scan)
        assertEquals(ScanStatus.KNOWN_MALICIOUS, scan!!.status)
        assertTrue("scanned at ${scan.scannedUnix}, rescan started at $started", scan.scannedUnix.toLong() >= started)
        assertTrue(scan.demo)
        assertTrue("${scan.findings}", scan.findings.any { it.startsWith("file hash:") })
        // Recorded in the vault: it is still there after a lock and unlock.
        Locker.lock()
        awaitVault<Locker.State.Locked>()
        Locker.unlockWithPassphrase(PASSPHRASE.toByteArray())
        assertEquals(scan, awaitVault<Locker.State.Unlocked>().entries.single().scan)
        report("v6", "scanned again: ${scan.label} ${scan.findings} database ${scan.snapshot} at ${scan.scannedUnix}")
        destroyVault()
    }

    @Test
    fun v7_theLockPolicyIsTheUsersAndStaysBounded() {
        destroyVault()
        Locker.createWithPassphrase(PASSPHRASE.toByteArray())
        awaitVault<Locker.State.Unlocked>()
        val stored = File(context.filesDir, "rift/vault-lock")
        try {
            val message = vaultMessageOf { Locker.setPolicy(Locker.LockPolicy(onBackground = false, idleMinutes = 1)) }
            assertTrue(message, message.contains("stays unlocked when Rift goes to the background"))
            assertEquals(Locker.LockPolicy(onBackground = false, idleMinutes = 1), Locker.policy.value)
            assertEquals(60_000L, Locker.inactivityMs)
            assertEquals("background=false\nidle-minutes=1\n", stored.readText())
            // Home no longer locks it; the inactivity limit still applies.
            val home = openHome()
            device.pressHome()
            SystemClock.sleep(2_000)
            assertTrue("${Locker.state.value}", Locker.state.value is Locker.State.Unlocked)
            home.finish()
            // Only the offered limits exist: there is no "never".
            assertThrows(IllegalArgumentException::class.java) { Locker.LockPolicy(idleMinutes = 0) }
            assertThrows(IllegalArgumentException::class.java) { Locker.LockPolicy(idleMinutes = 24 * 60) }
            // Changing it needs the vault unlocked.
            Locker.lock()
            awaitVault<Locker.State.Locked>()
            Locker.setPolicy(Locker.LockPolicy())
            SystemClock.sleep(500)
            assertEquals(Locker.LockPolicy(onBackground = false, idleMinutes = 1), Locker.policy.value)
            report("v7", "background lock off: still unlocked after Home; idle 1 min; stored ${stored.readText().replace("\n", " ")}")
        } finally {
            if (Locker.state.value !is Locker.State.Unlocked) {
                Locker.unlockWithPassphrase(PASSPHRASE.toByteArray())
                awaitVault<Locker.State.Unlocked>()
            }
            vaultMessageOf { Locker.setPolicy(Locker.LockPolicy()) }
            assertEquals(Locker.LockPolicy(), Locker.policy.value)
            destroyVault()
        }
    }

    // ---- Fault injection (Phase 7) ----------------------------------------------------
    // run-tests.sh runs these one at a time with `-e fault <step>` and kills
    // the controller (this process) at a random moment while f1 or f3 runs.
    // In the normal suite they are skipped.

    /** Skips the test unless the host asked for fault-injection step `step`. */
    private fun faultStep(step: String) = org.junit.Assume.assumeTrue(
        "a fault-injection step, run by run-tests.sh",
        InstrumentationRegistry.getArguments().getString("fault") == step,
    )

    private fun keptEntries() = (Locker.state.value as Locker.State.Unlocked).entries

    /** f0: a new, unlocked vault for the keep rounds. */
    @Test
    fun f0_prepareTheVault() {
        faultStep("prepare")
        destroyVault()
        Locker.createWithPassphrase(PASSPHRASE.toByteArray())
        awaitVault<Locker.State.Unlocked>()
        report("f0", "vault created")
    }

    /** f1: keeps one downloaded file again and again until the host kills this process. */
    @Test
    fun f1_keepUntilKilled() {
        faultStep("keep")
        if (Locker.state.value !is Locker.State.Unlocked) {
            Locker.unlockWithPassphrase(PASSPHRASE.toByteArray())
            awaitVault<Locker.State.Unlocked>()
        }
        // After a kill, the restarted core recovers before a session is active.
        val generation = activeGeneration()
        allowFixtureHost()
        val file = submit(generation, fixture("/files/notes.txt")).file!!
        var kept = keptEntries().size
        // The host starts its timer at this line.
        report("f1", "keeping from $kept")
        val deadline = SystemClock.elapsedRealtime() + FAULT_WINDOW_MS
        while (SystemClock.elapsedRealtime() < deadline) {
            Core.keep(file.id)
            awaitCondition("kept") { keptEntries().size > kept }
            kept = keptEntries().size
            report("f1", "kept $kept")
        }
        throw AssertionError("not killed within ${FAULT_WINDOW_MS} ms")
    }

    /**
     * f2, after a kill during f1: the vault opens, holds every keep that
     * completed (`-e kept N`, from f1's log) and at most the one in flight,
     * stores nothing but its own files, and every entry decrypts to the
     * bytes its index recorded; no plaintext is on disk.
     */
    @Test
    fun f2_theVaultIsWholeAfterTheKill() {
        faultStep("check-vault")
        val completed = InstrumentationRegistry.getArguments().getString("kept")!!.toInt()
        Locker.unlockWithPassphrase(PASSPHRASE.toByteArray())
        val entries = awaitVault<Locker.State.Unlocked>().entries
        assertTrue("${entries.size} entries after $completed completed keeps", entries.size in completed..completed + 1)
        val vault = File(context.filesDir, "rift/vault")
        val stored = vault.walkTopDown().filter { it.isFile }.map { it.relativeTo(vault).path }.toSet()
        assertEquals(setOf("identity.pass", "index.age") + entries.map { "objects/${it.id}.age" }, stored - "index.age.prev")
        val exported = File(context.cacheDir, "f2-export")
        for (entry in entries) {
            exported.delete()
            // Each export shows the same message, so its file is what is awaited.
            Locker.export(entry.id, android.net.Uri.fromFile(exported))
            awaitCondition("exported ${entry.id}") { exported.length() == entry.size.toLong() }
            val digest = java.security.MessageDigest.getInstance("SHA-256").digest(exported.readBytes())
            assertEquals(entry.sha256, digest.joinToString("") { "%02x".format(it) })
        }
        exported.delete()
        assertEquals(emptyList<String>(), filesContaining(MARKER))
        Locker.lock()
        awaitVault<Locker.State.Locked>()
        report("f2", "${entries.size} entries after $completed completed keeps; stored ${stored.size} files; every entry decrypted to its recorded hash")
    }

    /** f3: installs the demo database, then waits for the host to kill this process. */
    @Test
    fun f3_installUntilKilled() {
        faultStep("install")
        // After a kill, the restarted core opens the database before anything can be installed.
        assertNotNull(awaitIntel { it != null })
        // The host starts its timer at this line.
        report("f3", "installing")
        val started = SystemClock.elapsedRealtime()
        Core.installDemoIntel()
        val outcome = awaitIntelMessage()
        report("f3", "outcome after ${SystemClock.elapsedRealtime() - started} ms: $outcome")
        SystemClock.sleep(FAULT_WINDOW_MS)
        throw AssertionError("not killed within ${FAULT_WINDOW_MS} ms")
    }

    /**
     * f4, after a kill during f3: the threat database is the old one or the
     * new one, never damaged, and still finds the demo file; the install's
     * working copy is gone.
     */
    @Test
    fun f4_theDatabaseIsWholeAfterTheKill() {
        faultStep("check-intel")
        val status = awaitIntel { it != null }
        assertTrue("$status", status is IntelStatus.Installed || status is IntelStatus.Missing)
        if (status is IntelStatus.Installed) {
            activeGeneration()
            allowFixtureHost()
            assertEquals(ScanStatus.KNOWN_MALICIOUS, verdictOf(download("/files/demo-file.txt").file!!.id).status)
        }
        val leftovers = File(context.filesDir, "rift/import").walkTopDown().filter { it.isFile }.map { it.path }.toList()
        assertEquals(emptyList<String>(), leftovers)
        report("f4", "database after the kill: $status")
    }

    /**
     * r1: pages lay out at the window's height. A WebView left at
     * WRAP_CONTENT lays pages out at zero height, so every viewport unit
     * (100vh) was 0 px and pages sized by them collapsed (found by H1).
     */
    @Test
    fun r1_pagesLayOutAtTheWindowsHeight() {
        val (body, window) = visit("r1", "/recents.html?test=r1").getString("viewport").split(" ").map { it.toDouble() }
        assertTrue("window $window px", window > 0)
        assertEquals("100vh against the window's height", window, body, 1.0)
    }

    // ---- Host-captured checks (Phase 7) ----------------------------------------------
    // run-tests.sh runs these with `-e host <step>`, captures what only root
    // can read while they wait, and copies it into this app's files. Skipped
    // otherwise.

    /**
     * h1: the recents snapshot Android stores for the browser's task shows no
     * page. This opens recents.html (black and white stripes over the whole
     * page) and waits; the host takes a screenshot while the page is shown
     * (the control: the page was on screen, and this measure sees it),
     * presses Home, copies the snapshot Android then stored for the browser's
     * task, and writes `h1/ready`.
     */
    @Test
    fun h1_theRecentsSnapshotShowsNoPage() {
        org.junit.Assume.assumeTrue("a host-captured check, run by run-tests.sh", InstrumentationRegistry.getArguments().getString("host") == "h1")
        val dir = File(context.filesDir, "h1")
        try {
            visit("h1", "/recents.html")
            // The host starts at this line.
            report("h1", "page shown")
            awaitCondition("the host's capture", HOST_CAPTURE_MS) { File(dir, "ready").exists() }
            val page = oneShadeRows(File(dir, "page.png"))
            val snapshot = oneShadeRows(File(dir, "snapshot.jpg"))
            report("h1", "rows of one shade: ${percent(page)} of the screenshot with the page shown, ${percent(snapshot)} of the stored snapshot")
            assertTrue("${percent(page)} of the screenshot's rows are one shade, so the page was not on screen", page < 0.5)
            assertTrue("only ${percent(snapshot)} of the stored snapshot's rows are one shade, so it may show the page", snapshot > 0.98)
        } finally {
            dir.deleteRecursively()
        }
    }

    /**
     * The share of an image's rows that are one shade: all but 2% of their
     * pixels within a few grey levels of the row's commonest. The page's
     * vertical stripes make every row they cross mixed.
     */
    private fun oneShadeRows(file: File): Double {
        val bitmap = android.graphics.BitmapFactory.decodeFile(file.path) ?: throw AssertionError("cannot decode $file")
        val row = IntArray(bitmap.width)
        var uniform = 0
        for (y in 0 until bitmap.height) {
            bitmap.getPixels(row, 0, bitmap.width, 0, y, bitmap.width, 1)
            val histogram = IntArray(256)
            for (p in row) {
                histogram[(android.graphics.Color.red(p) * 299 + android.graphics.Color.green(p) * 587 + android.graphics.Color.blue(p) * 114) / 1000]++
            }
            val mode = histogram.indices.maxBy { histogram[it] }
            if ((maxOf(0, mode - 8)..minOf(255, mode + 8)).sumOf { histogram[it] } >= row.size * 0.98) uniform++
        }
        return uniform.toDouble() / bitmap.height
    }

    private fun percent(share: Double) = "%.1f%%".format(share * 100)

    // ---- Licences (§25) ---------------------------------------------------------------

    /**
     * Both APKs carry their third-party notices (written by notices.py and
     * notices.gradle.kts at build time), and the home screen shows them.
     */
    @Test
    fun l1_thirdPartyNoticesShipAndAreShown() {
        val own = listOf("android-libraries.txt", "rust-crates.txt", "apache-2.0.txt")
            .associateWith { context.assets.open("notices/$it").bufferedReader().use { r -> r.readText() } }
        val android = own.getValue("android-libraries.txt")
        assertTrue("JNA listed", android.contains("net.java.dev.jna:jna:"))
        assertTrue("libffi's notice, which JNA's native code needs", android.contains("libffi - Copyright"))
        val rust = own.getValue("rust-crates.txt")
        for (crate in listOf("yara-x ", "age ", "aws-lc-rs ", "uniffi ", "wasmtime ")) {
            assertTrue("$crate listed", rust.contains("\n$crate"))
        }
        assertTrue("YARA-X's copyright, from its repository", rust.contains("The YARA-X Authors"))
        assertTrue("MPL-2.0 text for uniffi", rust.contains("Mozilla Public License Version 2.0"))
        assertTrue(own.getValue("apache-2.0.txt").contains("TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION"))
        val browser = context.createPackageContext(Rift.BROWSER_PACKAGE, 0).assets
        // The browser app's own list: its web engine library, and no JNA (it loads no Rust).
        val browserLibraries = browser.open("notices/android-libraries.txt").bufferedReader().use { it.readText() }
        assertTrue(Regex(""":webkit:\d""").containsMatchIn(browserLibraries))
        assertFalse(browserLibraries.contains("net.java.dev.jna"))
        browser.open("notices/apache-2.0.txt").close()

        val home = openHome()
        try {
            // Once on API 33 in CI the home screen had no scrollable view after
            // 10 s (cause unknown); the message now says what was in front.
            assertNotNull("home screen shown; in front: ${device.currentPackageName}", device.wait(Until.findObject(By.res("session")), UI_TIMEOUT_MS))
            // The button is at the end of the home screen. Swiped in bounded steps
            // along the right-hand margin, which scrolls the column but holds no
            // text field to focus (a focused field's keyboard covers the screen).
            assertNotNull("scrollable; in front: ${device.currentPackageName}", device.wait(Until.findObject(By.scrollable(true)), UI_TIMEOUT_MS))
            val x = device.displayWidth - 12
            var open = device.findObject(By.res("notices-open"))
            repeat(20) {
                if (open == null) {
                    device.swipe(x, device.displayHeight * 3 / 4, x, device.displayHeight / 4, 30)
                    open = device.wait(Until.findObject(By.res("notices-open")), 500)
                }
            }
            assertNotNull("the licences button", open)
            open!!.click()
            assertNotNull(device.wait(Until.findObject(By.res("notices")), UI_TIMEOUT_MS))
            assertNotNull(device.wait(Until.findObject(By.textStartsWith("Android libraries in this app")), UI_TIMEOUT_MS))
            device.pressBack()
            assertTrue("Back returns to the home screen", device.wait(Until.gone(By.res("notices")), UI_TIMEOUT_MS))
            assertNotNull(device.wait(Until.findObject(By.res("session")), UI_TIMEOUT_MS))
        } finally {
            home.finish()
        }
        report("l1", "notices: Android ${android.lines().size} lines, Rust ${rust.lines().size} lines; screen opened and closed")
    }

    // ---- Live page watch (§10.5) ------------------------------------------------------

    /**
     * A page that asks for the location, camera and microphone, loads from a
     * listed address, probes the LAN, uses WebRTC and opens a file chooser;
     * then a listed address and a listed download. The session's live watch,
     * fed only by Rift's enforcement points, must show each, the browser's
     * bar must say "Danger", and the page must have got nothing.
     */
    @Test
    fun w1_liveWatchShowsWhatThePageTried() {
        Core.installDemoIntel()
        assertTrue("${Core.intelMessage.value}", awaitIntel { it is IntelStatus.Installed } is IntelStatus.Installed)
        val generation = resetAndAwait(activeGeneration())
        val page = visit("w1", "/watch.html")
        for (key in listOf("geolocation", "camera", "microphone")) {
            assertTrue("$key: ${page.optString(key)}", page.optString(key).startsWith("DENIED"))
        }
        // "lan" settles either way (an opaque no-cors response is the proxy's
        // 403 too); the proxy's own record of the refusal is checked below.
        // The file chooser needs a tap on the page (a user gesture).
        val upload = device.wait(Until.findObject(By.text("Upload a file")), UI_TIMEOUT_MS)
        assertNotNull("the page's upload button", upload)
        upload!!.click()
        val expected = setOf("location", "camera", "microphone", "known-malicious-request", "local-network", "direct-connection", "files")
        val seen = awaitWatch(generation) { codes -> codes.containsAll(expected) }
        assertTrue("seen: $seen; page: ${http("/results?test=w1")}; proxy refused: ${Core.egressStats()?.recent}", seen.containsAll(expected))
        assertEquals(PageWatch.Level.DANGER, Core.pageWatch(generation)?.level)
        assertNotNull(device.wait(Until.findObject(By.res("watch-status").textStartsWith("Danger:")), UI_TIMEOUT_MS))
        screenshot("w1-bar")
        assertNotEquals("LOADED", http("/results?test=w1").let { JSONObject(it).optString("known_bad") })

        // A listed address is blocked before it loads; a listed download is found in quarantine.
        openBrowser(generation, "http://rift-demo.invalid/known-bad")
        assertNotNull(device.wait(Until.findObject(By.text("Page blocked")), UI_TIMEOUT_MS))
        val demo = verdictOf(download("/files/demo-file.txt").file!!.id)
        assertEquals(ScanStatus.KNOWN_MALICIOUS, demo.status)
        val after = awaitWatch(generation) { it.containsAll(setOf("known-malicious-address", "file-known-malicious")) }
        assertTrue("seen: $after", after.containsAll(setOf("known-malicious-address", "file-known-malicious")))

        // The list opens from the bar, in the browser's own trusted UI.
        device.findObject(By.res("watch-status"))?.click()
        assertNotNull(device.wait(Until.findObject(By.res("watch-list")), UI_TIMEOUT_MS))
        screenshot("w1-list")
        // And on Rift's home screen.
        val home = openHome()
        try {
            assertNotNull(device.wait(Until.findObject(By.res("watch-level").text("Danger in this session")), UI_TIMEOUT_MS))
            screenshot("w1-home")
        } finally {
            home.finish()
        }
        val watch = Core.pageWatch(generation)!!
        report("w1", "page: $page; watch: " + watch.events.joinToString(" | ") { "${it.level} ${it.code} x${it.count}" })

        // A new session starts with an empty watch.
        val next = resetAndAwait(generation)
        assertEquals(emptyList<PageWatch.Event>(), Core.pageWatch(next)?.events)
        assertNull("the old session's watch is gone", Core.pageWatch(generation))
    }

    /**
     * Text fields ask the keyboard not to learn (§10.6): Rift's own address
     * fields in both apps and a page's field. Read from the system's record
     * of input starts, which is what the keyboard was given.
     */
    @Test
    fun h2_keyboardsAreAskedNotToLearn() {
        val home = openHome()
        try {
            val since = lastInputStart()
            (device.wait(Until.findObject(By.res("home-address")), UI_TIMEOUT_MS) ?: throw AssertionError("home address field")).click()
            assertLearningOff(context.packageName, since, "the home screen's address field")
        } finally {
            home.finish()
        }
        allowFixtureHost()
        openBrowser(activeGeneration(), fixture("/type.html"))
        val fields = { device.wait(Until.findObjects(By.pkg(Rift.BROWSER_PACKAGE).clazz("android.widget.EditText")), UI_TIMEOUT_MS).orEmpty() }
        var since = lastInputStart()
        (device.wait(Until.findObject(By.res("address")), UI_TIMEOUT_MS) ?: throw AssertionError("address bar")).click()
        assertLearningOff(Rift.BROWSER_PACKAGE, since, "the browser's address bar")
        device.pressBack() // the keyboard
        since = lastInputStart()
        // The page's field appears once the keyboard has gone and the page is laid out again.
        val deadline = SystemClock.elapsedRealtime() + UI_TIMEOUT_MS
        var page = fields().firstOrNull { it.resourceName != "address" }
        while (page == null && SystemClock.elapsedRealtime() < deadline) {
            SystemClock.sleep(200)
            page = fields().firstOrNull { it.resourceName != "address" }
        }
        (page ?: throw AssertionError("the page's text field: ${fields().map { it.resourceName }}")).click()
        assertLearningOff(Rift.BROWSER_PACKAGE, since, "the page's text field")
        report("h2", "learning off in the home screen's address field, the browser's address bar and a page's field")
    }

    /** The number of the system's most recent input start (dumpsys input_method). */
    private fun lastInputStart(): Int = inputStarts().maxOfOrNull { it.number } ?: 0

    private data class InputStart(val number: Int, val pkg: String, val inputType: Int, val imeOptions: Int)

    /** The input starts the system remembers, with the window's package and what the field asked for. */
    private fun inputStarts(): List<InputStart> {
        val dump = device.executeShellCommand("dumpsys input_method")
        return Regex("""StartInput #(\d+):(.*?)(?=StartInput #|\z)""", RegexOption.DOT_MATCHES_ALL).findAll(dump).mapNotNull { m ->
            val body = m.groupValues[2]
            val pkg = Regex("""targetWin=\S+ \[([^\]]+)]""").find(body)?.groupValues?.get(1) ?: return@mapNotNull null
            val type = Regex("""inputType=0x([0-9a-f]+)""").find(body)?.groupValues?.get(1)?.toLong(16)?.toInt() ?: return@mapNotNull null
            val options = Regex("""imeOptions=0x([0-9a-f]+)""").find(body)?.groupValues?.get(1)?.toLong(16)?.toInt() ?: return@mapNotNull null
            InputStart(m.groupValues[1].toInt(), pkg, type, options)
        }.toList()
    }

    /** A text field in `pkg` started input after input start `since`, with IME_FLAG_NO_PERSONALIZED_LEARNING. */
    private fun assertLearningOff(pkg: String, since: Int, what: String) {
        val deadline = SystemClock.elapsedRealtime() + UI_TIMEOUT_MS
        var seen: List<InputStart> = emptyList()
        while (SystemClock.elapsedRealtime() < deadline) {
            // inputType 0 is a window gaining focus, not a text field.
            seen = inputStarts().filter { it.number > since && it.pkg == pkg && it.inputType != 0 }
            if (seen.isNotEmpty()) break
            SystemClock.sleep(200)
        }
        val latest = seen.maxByOrNull { it.number } ?: throw AssertionError("$what: no input start recorded for $pkg")
        assertTrue(
            "$what: imeOptions=0x${Integer.toHexString(latest.imeOptions)}",
            latest.imeOptions and EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING != 0,
        )
    }

    /** Saves the screen as evidence; run-tests.sh collects these into screens/. */
    private fun screenshot(name: String) {
        val dir = context.getExternalFilesDir("evidence") ?: return
        device.waitForIdle()
        assertTrue("screenshot $name", device.takeScreenshot(java.io.File(dir, "$name.png")))
    }

    /** The codes in `generation`'s watch, once `done` holds for them or the page timeout passes. */
    private fun awaitWatch(generation: Long, done: (Set<String>) -> Boolean): Set<String> {
        val deadline = SystemClock.elapsedRealtime() + PAGE_TIMEOUT_MS
        var codes = emptySet<String>()
        while (SystemClock.elapsedRealtime() < deadline) {
            codes = Core.pageWatch(generation)?.events?.map { it.code }?.toSet().orEmpty()
            if (done(codes)) return codes
            SystemClock.sleep(200)
        }
        return codes
    }

    // ---- Privacy (§17, §18): what Rift sends by itself ------------------------------

    /**
     * Local work and a manual update from the configured host move no byte
     * on any real network for either of Rift's UIDs, and Rift schedules no
     * alarm or job. The fixture and the update server are on loopback, which
     * netstats does not count; traffic in the lock's tunnel (the browser's
     * dropped packets) is excluded, as it leaves no device.
     */
    @Test
    fun x1_localWorkAndUpdatesSendNothingElsewhere() {
        val uids = mapOf(
            "controller" to android.os.Process.myUid(),
            "browser" to context.packageManager.getPackageUid(Rift.BROWSER_PACKAGE, 0),
        )
        destroyVault()
        resetAndAwait(activeGeneration())
        allowFixtureHost()
        val served = File(context.cacheDir, "x1").apply { deleteRecursively() }
        copyAsset("intel-demo/repo", served)
        val server = java.net.ServerSocket(0, 8, java.net.InetAddress.getByName("127.0.0.1"))
        val requests = java.util.concurrent.atomic.AtomicInteger()
        thread(name = "x1-server", isDaemon = true) { serveFiles(server, served, requests) }
        val before = uids.mapValues { networkBytes(it.value) }
        try {
            // (b) A manual update from the configured host.
            Core.updateIntelOnline("http://localhost:${server.localPort}")
            val installed = awaitIntelMessage()
            assertTrue(installed, installed.startsWith("Installed demo-"))
            // (a) Local work: a download from the fixture, its scan and preview,
            // keeping it, scanning the vault's copy, locking and unlocking.
            val file = download("/files/picture.png").file!!
            verdictOf(file.id)
            assertNotNull(previewOf(file.id).bitmap)
            Locker.createWithPassphrase(PASSPHRASE.toByteArray())
            awaitVault<Locker.State.Unlocked>()
            Core.keep(file.id)
            awaitCondition("kept") { file.id in Locker.kept.value }
            val id = (Locker.state.value as Locker.State.Unlocked).entries.single().id
            val rescanned = vaultMessageOf { Locker.rescan(id) }
            assertTrue(rescanned, rescanned.startsWith("Scanned again"))
            Locker.lock()
            awaitVault<Locker.State.Locked>()
            // Idle with a session open (§18: no polling).
            SystemClock.sleep(IDLE_MS)
        } finally {
            server.close()
            served.deleteRecursively()
        }
        val after = uids.mapValues { networkBytes(it.value) }
        // Any mention among alarms; among jobs, registered jobs ("JOB #…"), since
        // the job dump also names every package in its quota and timer state.
        val mentions = { line: String -> "org.simulationrift" in line && "org.simulationrift.app.test" !in line }
        val scheduled = mapOf(
            "alarm" to device.executeShellCommand("dumpsys alarm").lines().filter(mentions),
            "jobscheduler" to device.executeShellCommand("dumpsys jobscheduler").lines().filter { "JOB #" in it && mentions(it) },
        )
        // Control: the measurement sees this UID's traffic. One TCP handshake
        // from the controller's UID (this process) to a public address,
        // without DNS (the local emulator's resolver once answered nothing).
        val control = try {
            java.net.Socket().use { it.connect(java.net.InetSocketAddress("1.1.1.1", 443), 10_000) }
            val seen = networkBytes(uids.getValue("controller")) - after.getValue("controller")
            assertTrue("the control request was not counted", seen > 0)
            "control request counted ($seen bytes)"
        } catch (e: java.io.IOException) {
            "control not run (no network: $e), so the measurement's sensitivity is unverified here"
        }
        report("x1", "bytes on real networks before $before, after $after; update requests ${requests.get()}; " +
            "alarm and job lines ${scheduled.mapValues { it.value.size }}; $control")
        assertEquals("bytes on real networks", before, after)
        assertEquals(emptyMap<String, List<String>>(), scheduled.filterValues { it.isNotEmpty() })
        destroyVault()
    }

    /**
     * Ordinary browsing (§17 c): the page's traffic leaves through the
     * controller's proxy, and the browser's UID moves nothing on any real
     * network itself. Needs the internet; without it the test is skipped
     * and says so.
     */
    @Test
    fun x2_browsingLeavesOnlyThroughTheProxy() {
        val online = try {
            java.net.Socket().use { it.connect(java.net.InetSocketAddress("1.1.1.1", 443), 10_000) }
            true
        } catch (e: java.io.IOException) {
            report("x2", "skipped: no internet ($e)")
            false
        }
        org.junit.Assume.assumeTrue("needs the internet", online)
        val generation = resetAndAwait(activeGeneration())
        val controller = android.os.Process.myUid()
        val browser = context.packageManager.getPackageUid(Rift.BROWSER_PACKAGE, 0)
        val before = networkBytes(controller) to networkBytes(browser)
        val allowedBefore = Core.egressStats()?.allowed ?: 0u
        openBrowser(generation, "https://example.org/")
        assertNotNull("page", device.wait(Until.findObject(By.textContains("Example Domain")), PAGE_TIMEOUT_MS))
        val after = networkBytes(controller) to networkBytes(browser)
        val allowed = (Core.egressStats()?.allowed ?: 0u) - allowedBefore
        report("x2", "controller +${after.first - before.first} bytes, browser +${after.second - before.second} bytes " +
            "on real networks; proxy requests allowed +$allowed")
        assertTrue("the page did not go through the proxy", allowed > 0u && after.first > before.first)
        assertEquals("browser bytes on real networks", before.second, after.second)

        // The core's own TLS (downloads and updates): verified against the
        // bundled roots on this device, and refused for another host's certificate.
        val page = submit(generation, "https://example.org/")
        assertNotNull("${page.failure}", page.file)
        val wrong = submit(generation, "https://wrong.host.badssl.com/")
        assertNull("a certificate for another name was accepted", wrong.file)
        report("x2", "core HTTPS: example.org stored ${page.file!!.size} bytes; wrong host: ${wrong.failure}")
    }

    /**
     * Bytes `uid` moved on real networks, from netstats after a forced poll:
     * every network but VPNs (type 17). Loopback belongs to no network, so it
     * is not counted.
     */
    private fun networkBytes(uid: Int): Long {
        device.executeShellCommand("dumpsys netstats --poll")
        val section = device.executeShellCommand("dumpsys netstats detail").substringAfter("\nUID stats:").substringBefore("\nUID tag stats:")
        var counting = false
        var total = 0L
        for (line in section.lines().map { it.trim() }) {
            when {
                line.startsWith("ident=") ->
                    counting = Regex("""\buid=(\d+)""").find(line.substringAfterLast(']'))?.groupValues?.get(1)?.toInt() == uid &&
                        !Regex("""\btype=17\b""").containsMatchIn(line)
                counting && line.startsWith("st=") ->
                    total += Regex("""\b[rt]b=(\d+)""").findAll(line).sumOf { it.groupValues[1].toLong() }
            }
        }
        return total
    }

    private fun destroyVault() {
        Locker.destroy()
        awaitVault<Locker.State.Absent>()
        Locker.holding = false
    }

    private inline fun <reified T : Locker.State> awaitVault(): T {
        val deadline = SystemClock.elapsedRealtime() + VAULT_TIMEOUT_MS
        while (SystemClock.elapsedRealtime() < deadline) {
            (Locker.state.value as? T)?.let { return it }
            SystemClock.sleep(50)
        }
        throw AssertionError("vault not ${T::class.simpleName}: ${Locker.state.value}; ${Locker.message.value}")
    }

    /** The message of vault action `start` (each test's consecutive messages differ). */
    private fun vaultMessageOf(start: () -> Unit): String {
        val before = Locker.message.value
        start()
        val deadline = SystemClock.elapsedRealtime() + VAULT_TIMEOUT_MS
        while (SystemClock.elapsedRealtime() < deadline) {
            Locker.message.value?.takeIf { it != before }?.let { return it }
            SystemClock.sleep(50)
        }
        throw AssertionError("no vault message after: $before")
    }

    private fun awaitCondition(what: String, timeoutMs: Long = VAULT_TIMEOUT_MS, condition: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + timeoutMs
        while (!condition()) {
            if (SystemClock.elapsedRealtime() > deadline) throw AssertionError("timed out waiting for: $what")
            SystemClock.sleep(50)
        }
    }

    /** Opens the home screen in front, as the user would see it. */
    private fun openHome(): android.app.Activity {
        val monitor = instrumentation.addMonitor(MainActivity::class.java.name, null, false)
        try {
            context.startActivity(Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            return monitor.waitForActivityWithTimeout(UI_TIMEOUT_MS) ?: throw AssertionError("home screen did not open")
        } finally {
            instrumentation.removeMonitor(monitor)
        }
    }

    /** Types the PIN into the system's credential screen once BiometricPrompt shows it. */
    private fun enterPin() {
        assertTrue("no credential screen", device.wait(Until.hasObject(By.pkg("com.android.systemui").clazz("android.widget.EditText")), UI_TIMEOUT_MS))
        SystemClock.sleep(500)
        device.executeShellCommand("input text $PIN")
        device.executeShellCommand("input keyevent 66")
    }

    private fun filesContaining(needle: ByteArray): List<String> =
        context.dataDir.walkTopDown().filter { it.isFile && contains(it.readBytes(), needle) }
            .map { it.relativeTo(context.dataDir).path }.toList()

    /** Waits for the scan that follows each download. */
    private fun verdictOf(id: String): Verdict {
        val deadline = SystemClock.elapsedRealtime() + SCAN_TIMEOUT_MS
        while (SystemClock.elapsedRealtime() < deadline) {
            Core.verdicts.value[id]?.let { return it }
            SystemClock.sleep(50)
        }
        throw AssertionError("no verdict for $id: ${Core.verdicts.value}")
    }

    /** A minimal static file server for s16e: GET only, names inside `root` only. */
    private fun serveFiles(server: java.net.ServerSocket, root: File, requests: java.util.concurrent.atomic.AtomicInteger) {
        while (!server.isClosed) {
            val socket = try {
                server.accept()
            } catch (e: java.io.IOException) {
                return // closed by the test
            }
            socket.use {
                requests.incrementAndGet()
                val reader = it.getInputStream().bufferedReader()
                val path = reader.readLine().orEmpty().split(' ').getOrNull(1).orEmpty().trimStart('/')
                while (reader.readLine().orEmpty().isNotEmpty()) Unit
                val file = File(root, path).takeIf { f -> path.split('/').none { c -> c == ".." || c.isEmpty() } && f.isFile }
                val body = file?.readBytes() ?: ByteArray(0)
                val status = if (file != null) "200 OK" else "404 Not Found"
                it.getOutputStream().apply {
                    write("HTTP/1.1 $status\r\nContent-Length: ${body.size}\r\nConnection: close\r\n\r\n".toByteArray())
                    write(body)
                    flush()
                }
            }
        }
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
        val deadline = SystemClock.elapsedRealtime() + SESSION_TIMEOUT_MS
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
        val deadline = SystemClock.elapsedRealtime() + SESSION_TIMEOUT_MS
        while (SystemClock.elapsedRealtime() < deadline) {
            val state = Core.state.value
            if (state is Core.State.Active && state.generation != generation) return state.generation
            if (state is Core.State.Failed) throw AssertionError("reset failed: ${state.message}")
            SystemClock.sleep(20)
        }
        throw AssertionError("reset did not finish: ${Core.state.value}")
    }

    private fun openBrowser(generation: Long, url: String?) {
        Core.openWindow(context, generation, url)
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

    /**
     * A failed reset leaves the core Failed until the user retries (INV-8).
     * The test that caused it has already failed; this retries as the user
     * would, so the next test starts from a session and reports on its own.
     */
    private fun recoverFromEarlierFailure() {
        val failed = Core.state.value as? Core.State.Failed ?: return
        report("recovery", "retrying after: ${failed.message}")
        Core.retry()
        val deadline = SystemClock.elapsedRealtime() + RECOVERY_TIMEOUT_MS
        while (Core.state.value !is Core.State.Active) {
            if (SystemClock.elapsedRealtime() > deadline) throw AssertionError("retry did not recover: ${Core.state.value}")
            SystemClock.sleep(50)
        }
    }

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

        /** A session start or reset includes the browser wipe, whose clear may take up to 30 s (AndroidBrowserDisposal). */
        const val SESSION_TIMEOUT_MS = 60_000L
        const val WINDOW_ATTEMPTS = 3
        const val IDLE_MS = 15_000L

        /** Intel messages that mean "still working". */
        val PROGRESS = setOf("Checking the update…", "Reading the update…", "Downloading the update…")

        /** A retried cleanup: the system wipe, with its bounded bind retries. */
        const val RECOVERY_TIMEOUT_MS = 60_000L
        const val ENGINE_START_TIMEOUT_MS = 30_000L
        const val DOWNLOAD_TIMEOUT_MS = 120_000L
        const val PREVIEW_TIMEOUT_MS = 30_000L
        const val SCAN_TIMEOUT_MS = 40_000L
        // DNS through the lock fails only after the resolver's own timeouts.
        const val ESCAPE_TIMEOUT_MS = 90_000L
        const val VAULT_TIMEOUT_MS = 20_000L
        /** How long f1 and f3 wait to be killed before they fail. */
        const val FAULT_WINDOW_MS = 60_000L
        const val HOST_CAPTURE_MS = 60_000L
        const val PASSPHRASE = "correct horse battery"
        const val PIN = "1111"
        const val RECOVERY = "recovery passphrase of the test"
        val MARKER = "RIFT-PREVIEW-PLAINTEXT-MARKER".toByteArray()
        val STORES = listOf("cookie", "server_cookie", "localStorage", "indexedDB", "cacheStorage", "serviceWorker")
    }
}
