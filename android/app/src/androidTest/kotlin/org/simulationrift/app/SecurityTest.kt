package org.simulationrift.app

import android.app.ActivityManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.os.IBinder
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import java.io.File
import java.net.HttpURLConnection
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

/**
 * Phase 2 security tests that run on the device (docs/architecture.md §23).
 * They run in the app's main process, drive `:browser` like a user would,
 * and read what test pages observed from the fixture server
 * (android/fixtures/server.py, reached through `adb reverse`).
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
    }

    // ---- Navigation policy in the trusted UI (INV-6, §10.2–§10.4) ---------------

    @Test
    fun n1_externalAppLinksAreBlocked() {
        val generation = activeGeneration()
        openBrowser(generation, fixture("/links.html?go=" + java.net.URLEncoder.encode("intent://scan/#Intent;scheme=zxing;end", "UTF-8")))
        assertNotNull("block screen", device.wait(Until.findObject(By.text("Page blocked")), UI_TIMEOUT_MS))
        assertNotNull(device.findObject(By.textContains("\"intent:\" links are blocked")))
        for (url in listOf("javascript:alert(1)", "file:///data/data/${context.packageName}/files", "content://settings/system", "market://details?id=x")) {
            val decision = Core.decide(generation, url)
            assertTrue("$url: $decision", decision is NavigationDecision.Block)
        }
    }

    @Test
    fun n2_lookalikeAddressNeedsConfirmation() {
        val generation = activeGeneration()
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

    // ---- S8 / S9 / S10: downloads go through the core (INV-13, §11.1) -----------

    @Test
    fun s08_oversizedDownloadStopsAtTheLimit() {
        allowFixtureHost()
        val d = download("/files/big")
        assertTrue("${d.failure}", d.failure?.contains("larger than the 104857600-byte limit") == true)
    }

    @Test
    fun s09_localDestinationsNeedAnExplicitPerHostAllowance() {
        // Not allowed yet in a fresh session: localhost is refused.
        resetAndAwait(activeGeneration())
        val refused = download("/files/hello.txt")
        assertTrue("${refused.failure}", refused.failure?.contains("resolves to 127.0.0.1") == true)
        // Allowing "localhost" does not allow another name for the same machine.
        allowFixtureHost()
        val literal = download("/files/to-loopback", match = "127.0.0.1")
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
        for (key in listOf("tcp_connect", "udp_socket", "dns", "clipboard", "bind_core")) {
            assertTrue("$key: ${probe[key]}", probe[key]?.startsWith("DENIED") == true)
        }
        // isolated_app does not deny AF_UNIX sockets (§8.6, PoC A6); reported, not asserted.
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
        val marker = "RIFT-PREVIEW-PLAINTEXT-MARKER".toByteArray()
        val hits = context.dataDir.walkTopDown().filter { it.isFile && contains(it.readBytes(), marker) }
            .map { it.relativeTo(context.dataDir).path }.toList()
        // The session's engine directories are deleted at reset (S12); anything else is a leak.
        val engine = Regex("(^|.*/)[^/]+_s[0-9]+/.*")
        assertEquals(emptyList<String>(), hits.filterNot { engine.matches(it) })
        report("s19", "plaintext marker found in: ${hits.ifEmpty { listOf("none") }}")
    }

    // ---- S15: unsupported engine configuration (INV-7) --------------------------

    @Test
    fun s15_unverifiedSandboxRefusesBrowsing() {
        val good = WebViewSandbox.Facts("com.google.android.webview", "133.0.6943.137", true, true)
        assertTrue(WebViewSandbox.evaluate(good).verified)
        for (bad in listOf(
            good.copy(multiProcessEnabled = false),
            good.copy(multiProcessSupported = false, multiProcessEnabled = false),
            good.copy(versionName = "91.0.4472.114"),
            good.copy(versionName = "garbage"),
            good.copy(packageName = null, versionName = null),
        )) {
            assertFalse("$bad", WebViewSandbox.evaluate(bad).verified)
        }
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
        assertTrue(dataDirectories().any { it.endsWith("_s$generation") })

        val started = SystemClock.elapsedRealtime()
        val next = resetAndAwait(generation)
        val resetMs = SystemClock.elapsedRealtime() - started
        assertTrue(next > generation)
        assertEquals(emptyList<Int>(), browserPids())
        assertEquals(emptyList<String>(), dataDirectories().filter { it.endsWith("_s$generation") })
        assertEquals(emptyList<String>(), File(context.dataDir, "shared_prefs").list().orEmpty().toList())
        assertFalse(Core.decide(generation, fixture("/probe.html")) is NavigationDecision.Proceed)

        assertFalse(File(context.filesDir, "rift/sessions/$generation").exists())
        assertTrue(Core.downloads.value.isEmpty())

        val after = visit("probe-after", "/probe.html?test=probe-after")
        for (key in STORES) assertEquals(key, "absent", after.getString(key))
        report("s12", "reset_ms=$resetMs generation=$generation->$next")
    }

    // ---- Helpers -------------------------------------------------------------------

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

    private fun openBrowser(generation: Long, url: String) {
        context.startActivity(
            Intent(context, BrowserActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                .putExtra(BrowserActivity.EXTRA_GENERATION, generation)
                .putExtra(BrowserActivity.EXTRA_URL, url),
        )
    }

    /** Opens a fixture page in the current session and waits for its report. */
    private fun visit(test: String, path: String, doneKey: String = "done"): JSONObject {
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

    private fun browserPids(): List<Int> =
        context.getSystemService(ActivityManager::class.java).runningAppProcesses.orEmpty()
            .filter { it.processName == context.packageName + AndroidBrowserDisposal.BROWSER_PROCESS_SUFFIX }
            .map { it.pid }

    private fun dataDirectories(): List<String> =
        listOf(context.dataDir, context.cacheDir).flatMap { it.list().orEmpty().toList() }

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
        const val FIXTURE_PORT = 8766
        const val UI_TIMEOUT_MS = 10_000L
        const val PAGE_TIMEOUT_MS = 20_000L
        const val CORE_TIMEOUT_MS = 15_000L
        const val DOWNLOAD_TIMEOUT_MS = 120_000L
        const val PREVIEW_TIMEOUT_MS = 30_000L
        val STORES = listOf("cookie", "server_cookie", "localStorage", "indexedDB", "cacheStorage", "serviceWorker")
    }
}
