package org.simulationrift.app

import android.app.ActivityManager
import android.content.ComponentName
import android.view.KeyEvent
import android.content.ClipboardManager
import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.content.ServiceConnection
import android.content.ContentValues
import android.graphics.Bitmap
import android.graphics.Color
import android.provider.MediaStore
import android.content.pm.ApplicationInfo
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
import androidx.test.uiautomator.StaleObjectException
import androidx.test.uiautomator.Direction
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
import org.junit.Assume.assumeTrue
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
import org.simulationrift.core.TraceOutcome
import org.simulationrift.core.Verdict
import rikka.shizuku.Shizuku

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
        // The page went around the decoys (D1), and the watch says so.
        val past = awaitWatch(activeGeneration()) { it.containsAll(setOf("camera", "location")) }
        assertTrue("seen: $past", past.containsAll(setOf("camera", "location")))
        assertTrue(
            "${Core.pageWatch(activeGeneration())?.events}",
            Core.pageWatch(activeGeneration())!!.events.filter { it.code in setOf("camera", "location") }.all { "past Rift's decoys" in it.text },
        )
        assertFalse(results.getString("clipboard_read").startsWith("ALLOWED"))
        assertTrue(results.getString("file_fetch").startsWith("DENIED"))
        assertTrue(results.getString("content_fetch").startsWith("DENIED"))
        assertEquals("BLOCKED", results.getString("window_open"))

        // The OS denies what the manifest never requests (B4).
        val requested = context.packageManager
            .getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS).requestedPermissions.orEmpty()
        // Shizuku's own permission (extra isolation, §8.9) is the one exception:
        // Shizuku defines it when installed, grants it from its own prompt, and
        // it gives no access to the device. Undefined permissions grant nothing.
        val dangerous = requested.filter { name ->
            val info = try {
                context.packageManager.getPermissionInfo(name, 0)
            } catch (e: PackageManager.NameNotFoundException) {
                null
            }
            info?.protection == PermissionInfo.PROTECTION_DANGEROUS
        }
        assertEquals(emptyList<String>(), dangerous - SHIZUKU_PERMISSION)
        assertTrue(requested.none { it.startsWith("moe.shizuku.") && it != SHIZUKU_PERMISSION })
        assertTrue("android.permission.INTERNET" in requested)
        assertFalse("android.permission.USE_BIOMETRIC" in requested) // nothing to unlock
        // Both apps hide other apps' overlays over their windows (§10.7): a normal permission.
        assertTrue("android.permission.HIDE_OVERLAY_WINDOWS" in requested)
        if (android.os.Build.VERSION.SDK_INT >= 31) { // the permission is new in API 31
            assertEquals(PermissionInfo.PROTECTION_NORMAL, context.packageManager.getPermissionInfo("android.permission.HIDE_OVERLAY_WINDOWS", 0).protection)
        }

        // Nor does the browser app, the one pages run in. androidx.core adds a
        // signature permission of the app's own, for its unexported receivers.
        val browser = context.packageManager
            .getPackageInfo(Rift.BROWSER_PACKAGE, PackageManager.GET_PERMISSIONS).requestedPermissions.orEmpty()
            .filter { it != "${Rift.BROWSER_PACKAGE}.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION" }.sorted()
        assertEquals(listOf("android.permission.ACCESS_NETWORK_STATE", "android.permission.HIDE_OVERLAY_WINDOWS", "android.permission.INTERNET", Rift.PERMISSION), browser)
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

    @Test
    fun n5_linksFromOtherAppsAreCheckedAsTheEngineReadsThem() {
        // No threat database here (s16a and s16b, which run later, need none):
        // the lookalike check shows which host each link was judged by.
        // A session that has shown a page.
        visit("s1", "/s1.html")
        val first = activeGeneration()
        assertTrue(Core.hasBrowsed(first))

        // A message shared from another app, with a defanged lookalike link:
        // its link is found, opened in a new session and stopped for a warning.
        fromAnotherApp(Intent(Intent.ACTION_SEND).setType("text/plain")
            .putExtra(Intent.EXTRA_TEXT, "Have a look: hxxps://paypa1[.]com/login (urgent)"))
        val second = activeGenerationAfter(first)
        assertNotNull("the shared link's warning", device.wait(Until.findObject(By.res("interstitial")), PAGE_TIMEOUT_MS))
        assertNotNull(device.findObject(By.textContains("looks like paypal.com")))
        assertNotNull(device.findObject(By.textContains("paypa1.com/login")))
        // The trusted bar is drawn, not covered by the engine (INV-6): a
        // WebView that had shown no page covered it in black (found here).
        val bar = device.findObject(By.res("trusted-bar"))?.visibleBounds ?: throw AssertionError("no trusted bar")
        val covered = shareOf("n5-shared", bar) { r, g, b -> r < 12 && g < 12 && b < 12 }
        assertTrue("trusted bar ${"%.1f".format(covered * 100)}% black", covered < 0.2)

        // A link that hides the lookalike host behind a backslash is judged as
        // the engine reads it (the host before the backslash), not as
        // example.org. The warning could have led to a page, so the session
        // counts as used and the link gets another new one.
        fromAnotherApp(Intent(Intent.ACTION_VIEW, Uri.parse("https://paypa1.com\\@example.org/")))
        val third = activeGenerationAfter(second)
        assertNotNull("the backslash link's warning", device.wait(Until.findObject(By.textContains("paypa1.com/@example.org")), PAGE_TIMEOUT_MS))
        assertNotNull(device.findObject(By.textContains("looks like paypal.com")))

        // Text without a link is refused with a reason, not dropped (in yet
        // another session: the last one also showed a warning).
        fromAnotherApp(Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, "no link in here"))
        val fourth = activeGenerationAfter(third)
        assertNotNull("text without a link", device.wait(Until.findObject(By.text("This is not a valid web address.")), PAGE_TIMEOUT_MS))
        // A refused address loads nothing, so the session stays unused.
        assertFalse(Core.hasBrowsed(fourth))
        report("n5", "sessions $first -> $second -> $third -> $fourth; bar ${"%.1f".format(covered * 100)}% black; shared, backslash and linkless text handled")
    }

    @Test
    fun n6_filesFromOtherAppsAreQuarantinedAndViewedSafely() {
        val generation = activeGeneration()
        // A picture in the shared media store, shared to Rift as a gallery
        // would: a content URI with a read grant.
        val picture = context.contentResolver.insert(
            MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
            ContentValues().apply {
                put(MediaStore.Images.Media.DISPLAY_NAME, "rift-n6.png")
                put(MediaStore.Images.Media.MIME_TYPE, "image/png")
            },
        ) ?: throw AssertionError("no media store item")
        try {
            val image = Bitmap.createBitmap(300, 200, Bitmap.Config.ARGB_8888).apply { eraseColor(Color.rgb(200, 30, 160)) }
            context.contentResolver.openOutputStream(picture)!!.use { image.compress(Bitmap.CompressFormat.PNG, 100, it) }
            fromAnotherApp(Intent(Intent.ACTION_SEND).setType("image/png").putExtra(Intent.EXTRA_STREAM, picture)
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION))
            // Straight to the viewer, drawn by an isolated worker.
            assertNotNull("the viewer", device.wait(Until.findObject(By.res("viewer")), UI_TIMEOUT_MS))
            awaitCondition("the shared picture quarantined") { Core.downloads.value.any { it.file?.displayName == "rift-n6.png" } }
            val file = Core.downloads.value.firstNotNullOf { it.file?.takeIf { f -> f.displayName == "rift-n6.png" } }
            assertEquals("another app", file.source)
            assertEquals(generation, activeGeneration())
            val drawn = device.wait(Until.findObject(By.res("preview-image-${file.id}")), PAGE_TIMEOUT_MS)
                ?: throw AssertionError("no preview: ${Core.previews.value[file.id]}")
            val bitmap = Core.previews.value[file.id]?.bitmap ?: throw AssertionError("no bitmap")
            assertEquals(300, bitmap.width)
            val pink = shareOf("n6-viewer", drawn.visibleBounds) { r, g, b -> r > 180 && g < 60 && b > 140 }
            assertTrue("the drawn picture ${"%.1f".format(pink * 100)}% its colour", pink > 0.3)
            awaitCondition("a verdict for the shared picture") { Core.verdicts.value[file.id] != null }
            // Back to the home screen, where the file is listed with the session's.
            device.findObject(By.res("viewer-close")).click()
            assertNotNull("the home screen", device.wait(Until.findObject(By.res("session")), UI_TIMEOUT_MS))
            // Slow swipes, finding the button again after each: the home screen
            // is redrawn as the scan finishes, which made a held scroll view stale,
            // and on small screens a fast swipe flung past the file.
            val view = swipeUntil(By.res("preview-${file.id}"))
                ?: run {
                    screenshot("n6-home")
                    // What the accessibility tree held at each position, from the top
                    // (CI's API 34 emulator never showed the button; the others do).
                    val dir = context.getExternalFilesDir("evidence")
                    val (w, h) = device.displayWidth to device.displayHeight
                    var listed = false
                    repeat(12) { i ->
                        dir?.let { java.io.File(it, "n6-tree-$i.xml").outputStream().use { out -> device.dumpWindowHierarchy(out) } }
                        listed = listed || device.hasObject(By.textContains("rift-n6.png"))
                        inputSwipe(w / 2, h * 3 / 4, w / 2, h / 2)
                        device.waitForIdle()
                    }
                    throw AssertionError("the file's View in Rift button is not on the home screen (its name is shown: $listed; trees in n6-tree-*.xml)")
                }
            // And "View in Rift" opens it again. Brought to mid-screen first (a
            // button at the edge can be under the gesture bar), found afresh
            // for each tap, and tapped twice at most.
            val h = device.displayHeight
            if (view.visibleBounds.bottom > h * 4 / 5) inputSwipe(device.displayWidth / 2, h * 3 / 4, device.displayWidth / 2, h / 2)
            device.waitForIdle()
            val opened = (1..2).any {
                device.findObject(By.res("preview-${file.id}"))?.click()
                device.wait(Until.hasObject(By.res("preview-image-${file.id}")), UI_TIMEOUT_MS) == true
            }
            assertTrue("View in Rift opened the viewer", opened)
            device.pressBack()
            assertNotNull(device.wait(Until.findObject(By.res("session")), UI_TIMEOUT_MS))

            // Rift's own providers are not a source (a confused deputy could
            // otherwise read Rift's state), and a bare path is not a file to take.
            val before = Core.downloads.value.size
            fromAnotherApp(Intent(Intent.ACTION_VIEW, Uri.parse("content://${context.packageName}.androidx-startup/rift/stats")))
            awaitCondition("Rift's own provider refused") {
                Core.downloads.value.drop(before).any { it.failure == "Rift does not take files from itself" }
            }
            fromAnotherApp(Intent(Intent.ACTION_VIEW, Uri.fromFile(File(context.filesDir, "rift/stats"))))
            assertNotNull("a file path", device.wait(Until.findObject(By.textContains("\"file:\" links are blocked")), PAGE_TIMEOUT_MS))
            assertTrue(Core.downloads.value.drop(before).all { it.file == null })
            report("n6", "shared picture ${file.size} bytes quarantined from ${file.source}, drawn ${bitmap.width}x${bitmap.height} " +
                "(${"%.1f".format(pink * 100)}% its colour); own provider and file path refused")
        } finally {
            context.contentResolver.delete(picture, null, null)
        }
    }

    // v1 and v2 (Check, Rift AI) are named to run after s16a-s16b and n3,
    // which need no threat database installed: v1 installs the demo one.
    @Test
    fun v1_checkLooksAtALinkWithoutOpeningIt() {
        Core.installDemoIntel()
        assertTrue("${Core.intelMessage.value}", awaitIntel { it is IntelStatus.Installed } is IntelStatus.Installed)
        val generation = activeGeneration()
        val browsedBefore = Core.hasBrowsed(generation)
        val home = openHome()
        val rows = mutableListOf<String>()
        try {
            for ((url, expected) in listOf(
                // Not in any feed the model learned from: made up for this test.
                "http://secure-paypal-login.verify-account.xyz/signin/update.php?id=1" to "Looks dangerous",
                "https://www.wikipedia.org/" to "No known threats found",
                "https://shop.local-hardware.de/kontakt" to "No known threats found",
                "http://rift-demo.invalid/known-bad" to "Known malicious",
                "javascript:alert(1)" to "Rift won't open this",
            )) {
                val field = device.wait(Until.findObject(By.res("home-address")), UI_TIMEOUT_MS) ?: throw AssertionError("home address field")
                field.text = url
                (awaitFresh { device.findObject(By.res("check").enabled(true)) } ?: throw AssertionError("check button")).click()
                // The previous result is replaced as the text changes: wait for this one's.
                // Found, not read: the card is redrawn as the result arrives.
                val title = expected.takeIf { awaitFresh { device.findObject(By.res("check-title").text(expected)) } != null }
                    ?: throw AssertionError("$url: expected \"$expected\", shown: ${runCatching { device.findObject(By.res("check-title"))?.text }.getOrNull()}")
                device.waitForIdle()
                freshTree()
                val score = runCatching { device.findObject(By.res("check-ai-score"))?.text }.getOrNull()
                val abstained = device.findObject(By.res("check-ai-abstained")) != null
                rows += "$url: $title, AI ${score ?: if (abstained) "not scored (most visited site)" else "none"}"
                screenshot("v1-${rows.size}")
            }
            // Checking opened nothing: the same session, no page loaded, no browser window.
            assertEquals(generation, activeGeneration())
            assertEquals(browsedBefore, Core.hasBrowsed(generation))
            assertNull(device.findObject(By.pkg(Rift.BROWSER_PACKAGE)))
        } finally {
            home.finish()
        }
        // The AI's verdicts through the core's API, and how long a whole check takes.
        val high = Core.check("http://secure-paypal-login.verify-account.xyz/signin/update.php?id=1")
        assertEquals(org.simulationrift.core.AiLevel.HIGH, high.ai?.level)
        assertTrue("${high.ai}", high.ai!!.score.toInt() >= 90 && high.ai!!.signals.isNotEmpty())
        // One of the most visited sites: the model does not score it.
        val popular = Core.check("https://www.wikipedia.org/")
        assertTrue("${popular.ai}", popular.ai!!.abstained && popular.ai!!.level == org.simulationrift.core.AiLevel.LOW)
        val low = Core.check("https://shop.local-hardware.de/kontakt")
        assertTrue("${low.ai}", !low.ai!!.abstained && low.ai!!.level == org.simulationrift.core.AiLevel.LOW)
        val micros = (1..300).map { Core.check("https://example-$it.org/docs/page-$it?ref=$it").micros.toLong() }.sorted()
        val p50 = micros[150]
        val p95 = micros[284]
        assertTrue("p95 $p95 us", p95 < 15_000)
        report("v1", "${rows.joinToString("; ")}; nothing opened; a whole check p50 $p50 us, p95 $p95 us on this device")
    }

    @Test
    fun v2_riftAiWarnsBeforeAPageLoads() {
        val generation = resetAndAwait(activeGeneration())
        val url = "http://secure-paypal-login.verify-account.xyz/signin/update.php?id=1"
        openBrowser(generation, url)
        assertNotNull("the warning", device.wait(Until.findObject(By.res("interstitial")), PAGE_TIMEOUT_MS))
        assertNotNull(device.wait(Until.findObject(By.textContains("Rift AI")), UI_TIMEOUT_MS))
        screenshot("v2-interstitial")
        // The live watch has it as a warning.
        val seen = awaitWatch(generation) { "ai-suspicious" in it }
        assertTrue("seen: $seen", "ai-suspicious" in seen)
        val event = Core.pageWatch(generation)!!.events.first { it.code == "ai-suspicious" }
        assertEquals(PageWatch.Level.WARNING, event.level)
        report("v2", "warned before loading: ${event.text.take(160)}")
    }

    /**
     * Check's link tools (§10.10): a redirect link is unwrapped and its
     * trackers named by ClearURLs-format rules, the clean link is checked in
     * its place and Undo goes back, the same in the share sheet; and a trace
     * contacts neither an address the threat database lists nor the phone's
     * own network. Rules are installed from text, as a download would be,
     * so the test needs no network.
     */
    @Test
    fun v3_linkToolsCleanUnwrapAndRefuseWhatTheyShould() {
        if (Core.intel.value !is IntelStatus.Installed) {
            Core.installDemoIntel()
            assertTrue("${Core.intelMessage.value}", awaitIntel { it is IntelStatus.Installed } is IntelStatus.Installed)
        }
        LinkCleaning.install(
            """{"providers":{
                "globalRules":{"urlPattern":".*","rules":["(?:%3F)?utm(?:_[a-z_]*)?","(?:%3F)?fbclid"]},
                "google":{"urlPattern":"^https?:\\/\\/(?:[a-z0-9-]+\\.)*?google(?:\\.[a-z]{2,}){1,}",
                    "redirections":["^https?:\\/\\/(?:[a-z0-9-]+\\.)*?google(?:\\.[a-z]{2,}){1,}\\/url\\?.*?(?:url|q)=(https?[^&]+)"]}
            }}""",
        )
        assertEquals("Rules updated.", LinkCleaning.state.value.message)
        val wrapped = "https://www.google.com/url?q=https%3A%2F%2Fnews.example%2Fstory%3Futm_source%3Dx%26id%3D4&usg=AOv"
        val clean = "https://news.example/story?id=4"
        val generation = activeGeneration()
        val browsedBefore = Core.hasBrowsed(generation)
        val home = openHome()
        try {
            // The tools are below the verdict: on a small screen, below the fold.
            scrollHomeTo(By.res("home-address"), "address field").text = wrapped
            scrollHomeTo(By.res("check").enabled(true), "check button").click()
            assertNotNull(awaitFresh { device.findObject(By.res("check-title")) })
            val unwrapped = scrollHomeTo(By.res("tools-clean-unwrapped"), "unwrapped address")
            assertEquals("https://news.example/story?utm_source=x&id=4", unwrapped.text)
            screenshot("v3-wrapped")
            scrollHomeTo(By.res("tools-clean-use"), "use the clean link").click()
            scrollHomeTo(By.res("check-address").text(clean), "the clean link checked")
            scrollHomeTo(By.res("tools-clean-none"), "no trackers left")
            screenshot("v3-clean")
            scrollHomeTo(By.res("tools-undo"), "undo").click()
            scrollHomeTo(By.res("tools-clean-unwrapped"), "back to the wrapped link")

            // Quick fixes: plain HTTP and a query.
            scrollHomeTo(By.res("home-address"), "address field").text = "http://example.org/a?x=1"
            scrollHomeTo(By.res("check").enabled(true), "check button").click()
            assertNotNull(awaitFresh { device.findObject(By.res("check-title")) })
            scrollHomeTo(By.res("tools-https"), "use https")
            scrollHomeTo(By.res("tools-no-query"), "remove the query").click()
            scrollHomeTo(By.res("check-address").text("http://example.org/a"), "the link without its query")
            // Leaving Rift is a second, warned tap.
            scrollHomeTo(By.res("tools-elsewhere"), "open elsewhere").click()
            scrollHomeTo(By.res("tools-leave-warning"), "the warning before leaving")
            screenshot("v3-elsewhere")
        } finally {
            home.finish()
        }
        // Nothing was opened by any of it.
        assertEquals(generation, activeGeneration())
        assertEquals(browsedBefore, Core.hasBrowsed(generation))

        // The share sheet has the same tools.
        share("Look: $wrapped")
        assertNotNull("the sheet's verdict", device.wait(Until.findObject(By.res("check-title")), PAGE_TIMEOUT_MS))
        (swipeUntil(By.res("tools-clean-use")) ?: run { screenshot("v3-share"); throw AssertionError("the share sheet's clean link") }).click()
        assertNotNull("the sheet checks the clean link", swipeUntil(By.text(clean)))
        screenshot("v3-share-clean")
        (swipeUntil(By.res("share-close")) ?: throw AssertionError("close")).click()
        assertTrue(device.wait(Until.gone(By.res("share-sheet")), UI_TIMEOUT_MS))

        // A trace: a listed address is not contacted; nor is the phone's own network.
        val listed = Core.trace("http://rift-demo.invalid/known-bad")
        assertTrue("${listed.outcome}", listed.outcome is TraceOutcome.Stopped)
        assertEquals(1, listed.hops.size)
        assertNull(listed.hops[0].status)
        assertEquals(5, severity(listed.hops[0].check))
        val local = Core.trace(fixture("/s1.html"))
        val failed = local.outcome as? TraceOutcome.Failed ?: throw AssertionError("${local.outcome}")
        assertNull(local.hops.single().status)
        assertTrue(failed.reason, failed.reason.contains("loopback") || failed.reason.contains("local"))
        report("v3", "unwrapped and cleaned to $clean, undo, https and query fixes, share sheet; listed hop not contacted; local trace refused: ${failed.reason}")
    }

    /** Hands `intent` to Rift's home screen as another app's link or share would. */
    /**
     * Sharing to Rift (§10.1): a shared link is checked at once and the
     * verdict shown in a sheet over the sharing app, with what was found on
     * request, and opened only by Open in Rift, which goes through the
     * core's checks again. Text without a link gets no Open. A picture that
     * another app shares, readable only through its grant, still reaches
     * the viewer through the sheet's activity.
     */
    @Test
    fun n7_sharedLinksGetAVerdictBeforeOpening() {
        share("Have a look: hxxps://paypa1[.]com/login (urgent)")
        // A cold start of the controller can come first.
        val title = device.wait(Until.findObject(By.res("check-title")), PAGE_TIMEOUT_MS)
            ?: run { screenshot("n7-no-verdict"); throw AssertionError("no verdict") }
        val verdict = title.text
        assertTrue(verdict, verdict in setOf("Warning signs", "Looks dangerous"))
        assertNotNull(device.findObject(By.res("share-summary")))
        assertNull("details are folded", device.findObject(By.res("share-details")))
        assertNull("nothing is opened yet", device.findObject(By.res("trusted-bar")))
        screenshot("n7-sheet")
        device.findObject(By.res("share-why")).click()
        assertNotNull(device.wait(Until.findObject(By.res("share-details")), UI_TIMEOUT_MS))
        assertNotNull(device.findObject(By.textContains("looks like paypal.com")))
        screenshot("n7-details")
        device.findObject(By.res("share-why")).click()
        assertTrue(device.wait(Until.gone(By.res("share-details")), UI_TIMEOUT_MS))
        device.findObject(By.res("share-open")).click()
        // The core asks again before loading, in the sealed browser.
        assertNotNull("the warning before loading", device.wait(Until.findObject(By.res("interstitial")), PAGE_TIMEOUT_MS))
        assertNotNull(device.findObject(By.textContains("paypa1.com/login")))

        // Text without a link: a reason, and nothing to open.
        share("no link in here")
        device.wait(Until.findObject(By.res("check-title").text("Rift won't open this")), PAGE_TIMEOUT_MS)
            ?: run { screenshot("n7-no-refusal"); throw AssertionError("text without a link") }
        assertNull(device.findObject(By.res("share-open")))
        device.findObject(By.res("share-close")).click()
        assertTrue(device.wait(Until.gone(By.res("share-sheet")), UI_TIMEOUT_MS))

        // A picture from another app, through its grant.
        val generation = activeGeneration()
        assertEquals("sent", outsider("share" to "picture").text("share"))
        awaitCondition("the shared picture quarantined") { Core.downloads.value.any { it.file?.displayName == "rift-n7.png" } }
        val file = Core.downloads.value.firstNotNullOf { it.file?.takeIf { f -> f.displayName == "rift-n7.png" } }
        assertEquals("another app", file.source)
        assertNotNull("the viewer", device.wait(Until.findObject(By.res("viewer")), UI_TIMEOUT_MS))
        awaitCondition("a preview of the shared picture") { Core.previews.value[file.id]?.bitmap != null }
        assertEquals(300, Core.previews.value[file.id]!!.bitmap!!.width)
        report("n7", "verdict $verdict; refused text; picture ${file.size} bytes from ${file.source} in session $generation")
    }

    private fun share(text: String) {
        context.startActivity(
            Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, text)
                .setPackage(context.packageName).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        )
    }

    private fun fromAnotherApp(intent: Intent) {
        context.startActivity(intent.setClassName(context.packageName, MainActivity::class.java.name).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }

    // ---- S8 / S9 / S10: downloads go through the core (INV-13, §11.1) -----------

    /**
     * n9: Test-open runs a link out of sight in a new session for 10 s, then
     * shows the core's report before the page (§10.11). The fixture page is
     * reached by a redirect, calls itself PayPal, asks for a password and a
     * card over plain HTTP, asks for the location and starts a download by
     * itself: the report lists the hops, the look-alike check's warning,
     * the site reached, and the download, which is not fetched.
     */
    /**
     * n10: Rift AI's page model (§16.1) reads a page shaped like a phishing
     * kit (a password form posting to another site's PHP script, links that
     * go nowhere, a brand that is not the site, urgent text) and warns about
     * it in the watch and in the test-open report. The counts come from the
     * browser's script, so this tests that script, the bridge and the model.
     */
    @Test
    fun n10_riftAiReadsAPhishingKitPage() {
        visit("s1", "/s1.html")
        val first = activeGeneration()
        Core.testOpen(fixture("/kit.html"))
        allowFixtureHost()
        val second = activeGenerationAfter(first)
        assertNotNull("the report", awaitFresh(PAGE_TIMEOUT_MS) { device.findObject(By.res("test-report-summary")) })
        screenshot("n10-report")
        val ai = Core.pageWatch(second)?.events?.firstOrNull { it.code == "page-ai" } ?: throw AssertionError("no page-ai event: ${Core.pageWatch(second)?.events?.map { it.code }}")
        assertEquals(PageWatch.Level.WARNING, ai.level)
        assertTrue(ai.text, "resembling phishing" in ai.text && !ai.text.contains("safe", ignoreCase = true))
        val reading = Core.testOpenReport(second)?.sections?.first { it.title == "Rift AI's reading of the page" }?.items.orEmpty()
        assertTrue("reading: $reading", reading.any { "resembling phishing" in it })
        (swipeUntil(By.res("test-show")) ?: throw AssertionError("show the page")).let { settled(By.res("test-show"))?.click() ?: it.click() }
        assertNotNull("the page is shown", awaitFresh { Unit.takeIf { device.findObject(By.res("test-open")) == null } })
        report("n10", ai.text)
    }

    @Test
    fun n9_testOpenReportsWhatALinkDidBeforeItIsShown() {
        // A session a page has used: the test-open must start a new one.
        visit("s1", "/s1.html")
        val first = activeGeneration()
        Core.testOpen(fixture("/login?next=/fake-login.html"))
        // Queued on the core's worker right behind the reset, so the new
        // session allows the fixture host before its window can ask.
        allowFixtureHost()
        val second = activeGenerationAfter(first)
        assertNotNull("the cover", device.wait(Until.findObject(By.res("test-open-running")), PAGE_TIMEOUT_MS))
        screenshot("n9-running")
        // The cover is replaced in the same Compose window, which API 34's cache keeps stale (freshTree).
        assertNotNull("the report", awaitFresh(PAGE_TIMEOUT_MS) { device.findObject(By.res("test-report-summary")) })
        screenshot("n9-report")

        val codes = Core.pageWatch(second)?.events?.map { it.code }.orEmpty()
        for (code in listOf("page-claims-brand", "page-password-no-tls", "page-asks-card", PageWatch.Attempt.DOWNLOAD)) {
            assertTrue("$code in $codes", code in codes)
        }
        val report = Core.testOpenReport(second) ?: throw AssertionError("no report")
        val hops = report.sections.first { it.title == "Where it went" }.items
        assertTrue("hops: $hops", hops.any { "/login" in it } && hops.any { "/fake-login.html" in it } && hops.any { "/files/invoice.pdf" in it })
        val sites = report.sections.first { it.title.startsWith("Sites it reached") }.items
        assertTrue("sites: $sites", "localhost:$FIXTURE_PORT" in sites)
        assertEquals(PageWatch.Level.WARNING, report.level)
        assertTrue("nothing fetched: ${Core.downloads.value}", Core.downloads.value.isEmpty())
        assertNull("not a test-open", Core.testOpenReport(first))

        (swipeUntil(By.res("test-show")) ?: throw AssertionError("show the page")).let { settled(By.res("test-show"))?.click() ?: it.click() }
        assertNotNull("the page is shown", awaitFresh { Unit.takeIf { device.findObject(By.res("test-open")) == null } })
        report("n9", "hops ${hops.size}, sites $sites, watch $codes")
    }

    /**
     * v4 (after s16, as it installs the demo database): a link the threat database lists can still be opened, after the
     * warning, and only in a new session (§10.4): the core decides it again
     * (a block the browser asks to lift for any other reason is refused),
     * resets, and in the new session lets that host, and no other listed
     * one, through the proxy. The bar says what the page is. The demo host
     * never resolves, so the proxy's next check refuses it, which shows the
     * database's refusal was lifted for that host only.
     */
    /**
     * Check's threat lists (§10.12) and history (§10.13): a host on a danger
     * list is called dangerous and on a warning list a warning sign, with the
     * list named; a most visited site is never flagged by a list; the history
     * is off until switched on, then keeps each check, encrypted, checks a
     * link again on a tap, and turning it off deletes it. Lists are installed
     * from text, as a download would be, so the test needs no network.
     */
    @Test
    fun v5_threatListsAndHistory() {
        // Run on its own (run-tests.sh's retry), the home screen may still be starting.
        activeGeneration()
        ThreatLists.install("hagezi-tif", "listed-dangerous.example\ndocs.google.com\n")
        ThreatLists.install("stevenblack", "0.0.0.0 ads.listed.example\n")
        awaitCondition("the lists are loaded", UI_TIMEOUT_MS) {
            ThreatLists.state.value.lists["hagezi-tif"]?.hosts == 2L && ThreatLists.state.value.lists["stevenblack"]?.hosts == 1L
        }
        assertEquals(listOf("hagezi-tif"), Core.check("https://login.listed-dangerous.example/verify").listed)
        assertEquals(listOf("stevenblack"), Core.check("https://ads.listed.example/x").listed)
        assertTrue("a most visited site", Core.check("https://docs.google.com/forms/d/x").listed.isEmpty())
        assertTrue("an unlisted site", Core.check("https://news.example/").listed.isEmpty())
        assertFalse("off by default", CheckHistory.state.value.on)
        val home = openHome()
        try {
            scrollHomeTo(By.res("home-address"), "address field").text = "https://login.listed-dangerous.example/verify"
            (awaitFresh { device.findObject(By.res("check").enabled(true)) } ?: throw AssertionError("check button")).click()
            assertEquals("Listed as dangerous", awaitFresh { device.findObject(By.res("check-title")) }?.text)
            // The summary at the top of the verdict names the list: no scrolling (on CI's API 33 the
            // column sometimes did not move, and the lists line below stayed off screen).
            val named = awaitFresh { device.findObject(By.res("check-summary")) } ?: throw AssertionError("the verdict's summary")
            assertTrue(named.text, named.text.contains("HaGeZi Threat Intelligence Feeds"))
            screenshot("v5-listed")
            assertTrue("nothing kept while off", CheckHistory.state.value.entries.isEmpty())

            CheckHistory.setOn(true)
            awaitCondition("history on") { CheckHistory.state.value.on }
            Core.check("https://ads.listed.example/x")
            awaitCondition("the check is kept") { CheckHistory.state.value.entries.firstOrNull()?.verdict == "Warning signs" }
            val saved = File(context.filesDir, "rift/history/history.bin")
            awaitCondition("the history is saved") { saved.isFile }
            assertFalse("the file is encrypted", saved.readBytes().toString(Charsets.ISO_8859_1).contains("listed.example"))
            requireNotNull(device.wait(Until.findObject(By.res("tab-activity")), UI_TIMEOUT_MS)) { "Activity tab" }.click()
            scrollHomeTo(By.res("history-0"), "the history's first link").click()
            assertEquals("Warning signs", awaitFresh { device.findObject(By.res("check-title")) }?.text)
            scrollHomeTo(By.res("check-address").text("https://ads.listed.example/x"), "the link checked again")
            screenshot("v5-again")

            CheckHistory.setOn(false)
            awaitCondition("history off") { !CheckHistory.state.value.on }
            assertFalse("the file is deleted", File(context.filesDir, "rift/history/history.bin").exists())
            requireNotNull(device.wait(Until.findObject(By.res("tab-home")), UI_TIMEOUT_MS)) { "tabs" }.click()
            report("v5", "danger list named, warning list named, popular site not flagged, history kept encrypted, checked again, deleted")
        } finally {
            CheckHistory.setOn(false)
            ThreatLists.remove()
            home.finish()
        }
    }

    /**
     * The real threat lists (§10.12), by hand only: downloaded from their
     * projects through the core's fetcher, loaded, and timed, with the
     * controller's memory before and after. Needs the network.
     */
    @Test
    fun v6_realThreatListsLoad() {
        assumeTrue("by hand: -e lists real", InstrumentationRegistry.getArguments().getString("lists") == "real")
        val before = Runtime.getRuntime().let { it.totalMemory() - it.freeMemory() } + android.os.Debug.getNativeHeapAllocatedSize()
        val started = SystemClock.elapsedRealtime()
        ThreatLists.download()
        awaitCondition("the lists downloaded", 300_000) {
            ThreatLists.state.value.let { !it.busy && it.message != null && it.downloaded }
        }
        val took = SystemClock.elapsedRealtime() - started
        System.gc()
        val after = Runtime.getRuntime().let { it.totalMemory() - it.freeMemory() } + android.os.Debug.getNativeHeapAllocatedSize()
        val lists = ThreatLists.state.value.lists
        val times = (1..1000).map { i ->
            val t = System.nanoTime()
            Core.check("https://host$i.example/path")
            System.nanoTime() - t
        }.sorted()
        report("v6", "${ThreatLists.state.value.message} in $took ms; " +
            lists.entries.joinToString { "${it.key} ${it.value.hosts} hosts${it.value.error?.let { e -> " ($e)" } ?: ""}" } +
            "; memory ${(after - before) / 1_048_576} MB more; check p50 ${times[500] / 1000} us, p95 ${times[950] / 1000} us")
        assertTrue(lists.values.all { it.error == null && it.hosts > 0 })
    }

    @Test
    fun v4_aListedLinkOpensOnlyInANewSessionAfterTheWarning() {
        Core.installDemoIntel()
        assertTrue("${Core.intelMessage.value}", awaitIntel { it is IntelStatus.Installed } is IntelStatus.Installed)
        val first = resetAndAwait(activeGeneration())
        val listed = "http://rift-demo.invalid/known-bad"

        // Asking to open a link that is not listed changes nothing.
        Core.inspectAnyway(first, "javascript:alert(1)")
        Core.inspectAnyway(first, "http://rift-demo.invalid/fine")
        SystemClock.sleep(1_000)
        assertEquals(Core.State.Active(first, null), Core.state.value)

        openBrowser(first, listed)
        assertNotNull(device.wait(Until.findObject(By.text("Page blocked")), PAGE_TIMEOUT_MS))
        screenshot("v4-warning")
        assertNotNull("what opening it means", swipeUntil(By.textContains("This lowers the risk; it does not remove it")))
        swipeUntil(By.res("inspect-anyway"))
        // Once the column stops: a tap while it still flings only stops it.
        (settled(By.res("inspect-anyway")) ?: throw AssertionError("the open-anyway button")).click()
        val second = activeGenerationAfter(first)
        assertNotNull("the bar's banner", device.wait(Until.findObject(By.res("opened-listed")), PAGE_TIMEOUT_MS))
        assertNotNull(device.wait(Until.findObject(By.res("protection").text("Known malicious · opened on purpose")), UI_TIMEOUT_MS))
        screenshot("v4-opened")

        val decision = Core.decide(second, listed)
        assertTrue("$decision", decision is NavigationDecision.Proceed && decision.notes.any { it.code == NavigationDecision.OPENED_LISTED })
        assertTrue("another listed host", Core.decide(second, "http://cdn.rift-demo.invalid/known-bad") is NavigationDecision.Block)
        val seen = awaitWatch(second) { "opened-known-malicious" in it }
        assertTrue("seen: $seen", "opened-known-malicious" in seen)
        assertEquals(PageWatch.Level.DANGER, Core.pageWatch(second)?.level)
        // The emulator's resolver takes 30 s to give up on a name.
        val deadline = SystemClock.elapsedRealtime() + 90_000L
        while (Core.egressStats()?.recent.isNullOrEmpty() && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(200)
        val refused = Core.egressStats()?.recent.orEmpty().filter { it.destination.startsWith("rift-demo.invalid") }
        assertTrue("refusals: $refused; stats: ${Core.egressStats()}; watch: ${Core.pageWatch(second)?.events}", refused.isNotEmpty() && refused.all { it.code == "does-not-resolve" })

        // The allowance ends with the session.
        val third = resetAndAwait(second)
        assertTrue(Core.decide(third, listed) is NavigationDecision.Block)
        report("v4", "listed link opened in session $second only, after the warning; proxy refusals there: ${refused.map { it.code }}")
    }

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

    @Test
    fun s15b_aWebViewMissingExploitedFixesRefusesBrowsing() {
        // Without the debug allowance, as in a release build: on this
        // emulator's WebView (older than every fix in KnownExploited) the
        // browser must refuse and say why.
        Core.allowOutdatedWebView = false
        try {
            val generation = resetAndAwait(activeGeneration())
            val earlier = Core.sandbox.value
            Core.openWindow(context, generation, null)
            val deadline = SystemClock.elapsedRealtime() + ENGINE_START_TIMEOUT_MS
            while (Core.sandbox.value === earlier && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(50)
            val sandbox = Core.sandbox.value ?: throw AssertionError("no sandbox report from :browser")
            assumeTrue("this WebView has every listed fix: ${sandbox.detail}", sandbox.detail.contains("exploited in the wild"))
            assertFalse(sandbox.detail, sandbox.verified)
            assertNotNull(device.wait(Until.findObject(By.res("protection").text("Browsing refused on this device")), UI_TIMEOUT_MS))
            assertNotNull(device.findObject(By.textContains("exploited in the wild")))
            val decision = Core.decide(generation, "https://example.org/")
            assertEquals("sandbox-unavailable", (decision as NavigationDecision.Block).reason.code)
            report("s15b", sandbox.detail)
        } finally {
            Core.allowOutdatedWebView = true
            resetAndAwait(activeGeneration())
        }
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

    /**
     * The network lock's switch (§8.8): off is kept across launches, ends the
     * session, and every session after it runs reduced (labelled) with pages
     * still going through the proxy; on starts the lock again and sessions
     * are locked once more.
     */
    @Test
    fun s28c_theLockCanBeTurnedOffAndOn() {
        awaitLock()
        val locked = activeGeneration()
        try {
            instrumentation.runOnMainSync { NetworkLock.turn(context, false) }
            val off = activeGenerationAfter(locked)
            assertEquals(NetworkLock.State.TurnedOff, NetworkLock.state.value)
            assertEquals("a session after the lock is off runs reduced", off, Core.reduced.value)
            assertTrue("the choice is kept", File(context.filesDir, "rift/network-lock-off").exists())
            // A later start (a new launch) keeps it off.
            NetworkLock.start(context, userAction = false)
            assertEquals(NetworkLock.State.TurnedOff, NetworkLock.state.value)
            val page = visit("s2", "/s2.html")
            assertNotNull("a page loads through the proxy: $page", page)
            assertNotNull("label", device.wait(Until.findObject(By.res("reduced")), UI_TIMEOUT_MS))
            screenshot("s28c-off")
            instrumentation.runOnMainSync { NetworkLock.turn(context, true) }
            awaitLock()
            val on = activeGenerationAfter(off)
            assertNotEquals(on, Core.reduced.value)
            assertFalse(File(context.filesDir, "rift/network-lock-off").exists())
            report("s28c", "lock off: session $off reduced and labelled, a page loaded through the proxy; lock on: session $on locked")
        } finally {
            if (NetworkLock.state.value == NetworkLock.State.TurnedOff) instrumentation.runOnMainSync { NetworkLock.turn(context, true) }
            awaitLock()
        }
    }

    /**
     * Content filters (§10.9), with the user's own rules (no list is
     * downloaded in a test): a script is blocked, an element is hidden by
     * a site rule and a sign-in pop-up by a generic one, the article stays;
     * with filtering off the same page shows everything.
     */
    @Test
    fun f1_filtersBlockAdsAndHideElements() {
        try {
            ContentFilter.setEnabled(true)
            ContentFilter.setCustom("! test rules\n/ads/banner.js\nlocalhost##.ad-banner\n###sign-in-popup\n")
            awaitCondition("the rules are loaded", SESSION_TIMEOUT_MS) { ContentFilter.state.value.ready && ContentFilter.active() }
            val blockedBefore = ContentFilter.state.value.blocked
            val on = visit("f1", "/filters.html")
            assertEquals("the ad script", "BLOCKED", on.getString("ad_script"))
            assertEquals("the ad element", "HIDDEN", on.getString("banner"))
            assertEquals("the sign-in pop-up", "HIDDEN", on.getString("popup"))
            assertEquals("the article", "SHOWN", on.getString("content"))
            assertNotNull("the bar counts what was blocked", device.wait(Until.findObject(By.res("filter-count").textContains("blocked")), UI_TIMEOUT_MS))
            screenshot("f1-on")
            ContentFilter.countNow()
            assertTrue("the controller counted it", ContentFilter.state.value.blocked > blockedBefore)

            ContentFilter.setEnabled(false)
            awaitCondition("filtering is off", SESSION_TIMEOUT_MS) { !ContentFilter.state.value.ready }
            val off = visit("f1", "/filters.html")
            assertEquals("LOADED", off.getString("ad_script"))
            assertEquals("SHOWN", off.getString("banner"))
            assertEquals("SHOWN", off.getString("popup"))
            report("f1", "filters on: script blocked, element and pop-up hidden, article shown; off: everything shown")
        } finally {
            ContentFilter.setCustom("")
            ContentFilter.setEnabled(true)
        }
    }

    /**
     * "Skip sign-ins and pop-ups" (§10.9): a social site's sign-in wall comes
     * down by the lists' own kinds of rules (here the user's, so the test
     * needs no download): scrolling unlocked by `:style()`, the sign-up box
     * removed even when it comes late, the post's blur class and `inert`
     * stripped, a nag found by its text hidden with its section; and the
     * page's dialog boxes are dismissed unseen. A list's script rule never
     * runs.
     */
    @Test
    fun f7_signInWallsAndDialogsAreSkipped() {
        try {
            ContentFilter.setEnabled(true)
            ContentFilter.setAutoUpdate(false)
            ContentFilter.setCustom(
                "! test rules\nlocalhost##body:style(overflow: auto !important)\nlocalhost##.signup-wall:remove()\n" +
                    "localhost##.feed:remove-class(blurred)\nlocalhost##main:remove-attr(inert)\nlocalhost##main:style(filter: none !important)\n" +
                    "localhost##p:has-text(Sign up to continue):upward(section)\nlocalhost##+js(set, answers, 1)\n||tracker.example^\n",
            )
            ContentFilter.setSkipWalls(true)
            awaitCondition("the rules are loaded", SESSION_TIMEOUT_MS) {
                ContentFilter.state.value.let { it.ready && it.busy == null } && ContentFilter.active()
            }
            val on = visit("f7", "/walls.html")
            assertEquals("scrolling", "auto", on.getString("scroll"))
            assertEquals("the sign-up boxes", "REMOVED", on.getString("wall"))
            assertEquals("the post's blur class", "CLEAR", on.getString("blurred"))
            assertEquals("the post's inert", "USABLE", on.getString("inert"))
            assertEquals("the post's blur", "none", on.getString("filter"))
            assertEquals("the nag found by its text", "HIDDEN", on.getString("nag"))
            assertEquals("the dialogs were dismissed: no, nothing", "[false,null]", on.getString("dialogs"))
            awaitCondition("the watch says a dialog was dismissed", UI_TIMEOUT_MS) {
                Core.pageWatch(activeGeneration())?.events?.any { it.code == PageWatch.Attempt.DIALOG } == true
            }
            screenshot("f7-on")
            // Check names a server the lists block whole as a tracker's.
            assertTrue("a listed tracker server", ContentFilter.listsAddress("https://tracker.example/p?id=1"))
            assertFalse("an unlisted server", ContentFilter.listsAddress("https://news.example/story"))

            ContentFilter.setSkipWalls(false)
            ContentFilter.setCustom("! test rules\nlocalhost##.unrelated\n")
            awaitCondition("the rules are loaded again", SESSION_TIMEOUT_MS) {
                ContentFilter.state.value.let { it.ready && it.busy == null } && !ContentFilter.quietDialogs()
            }
            val off = visit("f7", "/walls.html?dialogs=0")
            assertEquals("hidden", off.getString("scroll"))
            assertEquals("SHOWN", off.getString("wall"))
            assertEquals("BLURRED", off.getString("blurred"))
            assertFalse("dialogs are shown again", ContentFilter.quietDialogs())
            report("f7", "skip on: scrolling unlocked, sign-up boxes removed (one added late), blur and inert stripped, text nag hidden, dialogs dismissed; off: the wall stays")
        } finally {
            ContentFilter.setCustom("")
            ContentFilter.setSkipWalls(true)
            ContentFilter.setAutoUpdate(true)
        }
    }

    /**
     * What a page can learn about the device (§10.5): its model, its GPU, its
     * disk, its network, its time zone and what the browser sends with every
     * request. Everything the page finds is made up and the same on every phone.
     */
    @Test
    fun i1_aPageLearnsNothingAboutTheDevice() {
        val page = visit("i1", "/identity.html")
        val ua = JSONObject("{\"v\":${page.getString("userAgent")}}").getString("v")
        assertTrue("the user agent names no build: $ua", !ua.contains("Build/") && !ua.contains("; wv)") && ua.contains("Android 10; K)"))
        assertFalse("the user agent names the model: $ua", android.os.Build.MODEL.isNotEmpty() && ua.contains(android.os.Build.MODEL))
        assertEquals("\"Linux armv8l\"", page.getString("platform"))
        assertEquals("8", page.getString("hardwareConcurrency"))
        assertEquals("4", page.getString("deviceMemory"))
        assertFalse("the network's real type: ${page.getString("connection")}", page.getString("connection").contains("\"type\""))
        assertEquals("\"UTC\"", page.getString("timezone"))
        assertEquals("0", page.getString("offset"))
        assertEquals("[\"2026-10-22T10:00:00.000Z\",22,\"Thu Jan 01 1970 00:00:00 GMT+0000 (Coordinated Universal Time)\"]", page.getString("dates"))
        assertEquals("[2147483648,0]", page.getString("storage"))
        val gl = page.getString("webgl")
        assertTrue("the GPU's name: $gl", gl.contains("SwiftShader") && !Regex("Adreno|Mali|Apple|Emulator|Translator|PowerVR", RegexOption.IGNORE_CASE).containsMatchIn(gl))
        assertEquals("\"none\"", page.getString("gpu"))
        assertEquals("[2172649472,10000000]", page.getString("perfMemory"))
        val headers = JSONObject(page.getString("headers"))
        // WebView adds the app's package name in X-Requested-With. Its control for that (an empty
        // allow list) did not stop it on WebView 124, so this is recorded, not asserted: it names
        // Rift's browser app, not the device.
        val headerNote = if (headers.has("x-requested-with")) "; X-Requested-With still names the browser app (WebView ${Regex("Chrome/(\\d+)").find(ua)?.groupValues?.get(1)})" else "; no X-Requested-With"
        assertFalse("a client hint names the WebView: $headers", headers.optString("sec-ch-ua").contains("WebView"))
        assertFalse("a client hint naming the device: $headers", headers.keys().asSequence().any { it.startsWith("sec-ch-ua-model") || it == "sec-ch-ua-platform-version" })
        assertTrue("the user agent header is the generic one", headers.getString("user-agent").contains("Android 10; K)"))
        val hardware = page.getString("hardwareApis")
        for (api in listOf("bluetooth", "usb", "serial", "hid", "nfc", "xr")) assertFalse("$api exists: $hardware", hardware.contains("\"$api\""))
        report("i1", "user agent ${ua.take(80)}; zone UTC; GPU, disk, memory, cores and network made up$headerNote; no hardware APIs")
    }

    /**
     * The filters' answer to one request, as the browser's call reaches it (§10.9): the
     * engine's own work is microseconds, so what is measured here is the bridge to it. The
     * lists are the user's own rules plus a few hundred generated ones, so the engine has
     * real work to do and the test needs no download.
     */
    @Test
    fun f2_aFilterCheckIsFast() {
        try {
            val rules = (0..500).joinToString("\n") { "||ads$it.example^\n/banner$it/*\n##.ad-$it" } + "\n"
            ContentFilter.setEnabled(true)
            ContentFilter.setCustom(rules)
            awaitCondition("the rules are loaded", SESSION_TIMEOUT_MS) {
                // Ready alone may still describe the rules before these (a retry run on its own blocked 2 of 100).
                ContentFilter.state.value.ready && ContentFilter.active() &&
                    ContentFilter.blocks("https://ads0.example/x.js", "https://news.example/", "script") &&
                    ContentFilter.blocks("https://ads99.example/x.js", "https://news.example/", "script")
            }
            val urls = (0 until 400).map { "https://cdn$it.example.com/a/b/c$it.js?x=$it" } + (0 until 100).map { "https://ads$it.example/x.js" }
            for (url in urls) ContentFilter.blocks(url, "https://news.example/", "script")
            // The quickest of five rounds, for both: a pause of the emulator (CI's API 33 once
            // paused a single round to 1.6 ms a check) says nothing about the check.
            var blocked = 0
            val each = (1..5).minOf {
                val started = SystemClock.elapsedRealtimeNanos()
                blocked = 0
                for (url in urls) if (ContentFilter.blocks(url, "https://news.example/", "script")) blocked++
                (SystemClock.elapsedRealtimeNanos() - started) / urls.size / 1000
            }
            // An empty call through the same bridge, for scale.
            val empty = (1..5).minOf {
                val started = SystemClock.elapsedRealtimeNanos()
                repeat(urls.size) { ContentFilter.active() }
                (SystemClock.elapsedRealtimeNanos() - started) / urls.size / 1000
            }
            assertEquals("the generated ad hosts are blocked", 100, blocked)
            // Android runs every debuggable app with CheckJNI, which makes each crossing of the JNA
            // bridge cost hundreds of µs on an emulator. A check crosses about five times (the call
            // and one buffer per string), so there it may cost at most eight empty calls, or less
            // than a release build's limit (an empty call can be so quick that eight are less).
            val debuggable = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
            if (debuggable) {
                assertTrue("a check took $each us on average, an empty call $empty us", each < 1000 || each <= 8 * maxOf(empty, 1))
            } else {
                assertTrue("a check took $each us on average", each < 1000)
            }
            report("f2", "a check through the bridge: $each us on average, the quickest of 5 rounds of ${urls.size} calls; an empty call $empty us (debuggable: $debuggable)")
        } finally {
            ContentFilter.setCustom("")
            ContentFilter.setEnabled(true)
        }
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

    /** The outcome of the install `start` begins: a new message, or the same text after a progress message. */
    private fun intelMessageOf(start: () -> Unit): String {
        val before = Core.intelMessage.value
        var progressed = false
        start()
        val deadline = SystemClock.elapsedRealtime() + SCAN_TIMEOUT_MS
        while (SystemClock.elapsedRealtime() < deadline) {
            val message = Core.intelMessage.value
            if (message in PROGRESS) progressed = true
            else if (message != null && (progressed || message != before)) return message
            SystemClock.sleep(20)
        }
        throw AssertionError("no install outcome: ${Core.intelMessage.value}")
    }

    // ---- Fault injection (Phase 7) ----------------------------------------------------
    // run-tests.sh runs these one at a time with `-e fault <step>` and kills
    // the controller (this process) at a random moment while f3 runs.
    // In the normal suite they are skipped.

    /** Skips the test unless the host asked for fault-injection step `step`. */
    private fun faultStep(step: String) = org.junit.Assume.assumeTrue(
        "a fault-injection step, run by run-tests.sh",
        InstrumentationRegistry.getArguments().getString("fault") == step,
    )

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
     * working copy is gone. With `-e expect installed` (the kill came after
     * the install reported success) it must be the new one.
     */
    @Test
    fun f4_theDatabaseIsWholeAfterTheKill() {
        faultStep("check-intel")
        val status = awaitIntel { it != null }
        assertTrue("$status", status is IntelStatus.Installed || status is IntelStatus.Missing)
        if (InstrumentationRegistry.getArguments().getString("expect") == "installed") {
            assertTrue("an install reported done is gone: $status", status is IntelStatus.Installed)
        }
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
     * f5: what Rift does when the disk fills. Prepares the demo database
     * and a quarantined download, then waits while the host fills /data up
     * to what apps may use. A database install and a download must then
     * each fail with a message, and a
     * reset must end in a new session or a stated failure, not hang. Once
     * the host frees the space, "Retry cleanup" starts a session in the same
     * process; f6 then checks what is left after a restart.
     */
    @Test
    fun f5_aFullDiskFailsCleanly() {
        faultStep("full")
        val installed = intelMessageOf { Core.installDemoIntel() }
        assertTrue(installed, installed.startsWith("Installed"))
        val generation = activeGeneration()
        allowFixtureHost()
        val file = submit(generation, fixture("/files/picture.png")).file!!
        assertTrue("${file.size} bytes, which would fit", file.size.toLong() > FULL_BYTES)
        // The host starts filling at this line.
        report("f5", "ready")
        awaitCondition("the host's fill", HOST_CAPTURE_MS) { context.filesDir.usableSpace < FULL_BYTES }
        report("f5", "full: ${context.filesDir.usableSpace} bytes usable")

        val install = intelMessageOf { Core.installDemoIntel() }
        report("f5", "install: $install; database ${Core.intel.value}")
        val download = submit(generation, fixture("/files/picture.png"))
        report("f5", "download: ${download.file ?: download.failure}")
        Core.reset(generation)
        val deadline = SystemClock.elapsedRealtime() + SESSION_TIMEOUT_MS
        while (SystemClock.elapsedRealtime() < deadline) {
            val state = Core.state.value
            if (state is Core.State.Failed || (state is Core.State.Active && state.generation != generation)) break
            SystemClock.sleep(20)
        }
        val reset = Core.state.value
        report("f5", "reset: $reset")

        // The user frees space and taps "Retry cleanup", without restarting Rift.
        // The host frees it at this line.
        report("f5", "free the space")
        awaitCondition("the host's cleanup", HOST_CAPTURE_MS) { context.filesDir.usableSpace > FULL_BYTES * 16 }
        if (reset is Core.State.Failed) {
            Core.retry()
            // The retry runs on the core's worker; until then the old failure stands.
            awaitCondition("the retry to start") { Core.state.value !== reset }
        }
        val retried = activeGenerationAfter(generation)
        report("f5", "after freeing the space: session $retried")

        // Said as it is: the copy failed, not that the build has no database.
        assertTrue(install, install.startsWith("the demo database could not be copied"))
        assertTrue("database ${Core.intel.value}", Core.intel.value is IntelStatus.Installed)
        assertNull("stored on a full disk", download.file)
        assertNotNull(download.failure)
        assertTrue("the reset neither finished nor failed: $reset", reset is Core.State.Failed || (reset is Core.State.Active && reset.generation != generation))
    }

    /**
     * f6, after f5 with the space freed: a session starts, the database
     * installed before the disk filled is still there and finds the demo
     * file, the failed install left no copy, and downloads are stored
     * again.
     */
    @Test
    fun f6_wholeAfterTheFullDisk() {
        faultStep("check-full")
        val generation = activeGeneration()
        val leftovers = File(context.filesDir, "rift/import").walkTopDown().filter { it.isFile }.map { it.path }.toList()
        assertEquals(emptyList<String>(), leftovers)
        val status = awaitIntel { it != null }
        assertTrue("$status", status is IntelStatus.Installed)
        allowFixtureHost()
        assertEquals(ScanStatus.KNOWN_MALICIOUS, verdictOf(submit(generation, fixture("/files/demo-file.txt")).file!!.id).status)
        val file = submit(generation, fixture("/files/picture.png")).file
        assertNotNull("a download after the space was freed", file)
        report("f6", "session $generation; database $status; downloads stored again")
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
        // Rift AI's data: the Public Suffix List's MPL-2.0 notice, Phishing.Database's MIT one.
        val model = context.assets.open("url-model-notice.txt").bufferedReader().use { it.readText() }
        assertTrue(model.contains("Mozilla Public License") && model.contains("Copyright (c) 2018-2025 Mitchell Krog"))
        val page = context.assets.open("page-model-notice.txt").bufferedReader().use { it.readText() }
        assertTrue(page.contains("CC BY 4.0") && page.contains("doi:10.17632/n96ncsr5g4.1"))
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
            // The button is on the About tab.
            requireNotNull(device.wait(Until.findObject(By.res("tab-about")), UI_TIMEOUT_MS)) { "About tab" }.click()
            assertNotNull(device.wait(Until.findObject(By.res("about-authors").text("Ali Alakber and Teeba Nazar")), UI_TIMEOUT_MS))
            scrollHomeTo(By.res("notices-open"), "the licences button").click()
            assertNotNull(device.wait(Until.findObject(By.res("notices")), UI_TIMEOUT_MS))
            assertNotNull(device.wait(Until.findObject(By.textStartsWith("Android libraries in this app")), UI_TIMEOUT_MS))
            device.pressBack()
            assertTrue("Back returns to the tabs", device.wait(Until.gone(By.res("notices")), UI_TIMEOUT_MS))
            requireNotNull(device.wait(Until.findObject(By.res("tab-home")), UI_TIMEOUT_MS)) { "tabs" }.click()
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
     * then a listed address and a listed download. The session's live watch
     * must show each, the browser's bar must say "Danger", and the page must
     * have got only decoys (D1).
     */
    @Test
    fun w1_liveWatchShowsWhatThePageTried() {
        Core.installDemoIntel()
        assertTrue("${Core.intelMessage.value}", awaitIntel { it is IntelStatus.Installed } is IntelStatus.Installed)
        val generation = resetAndAwait(activeGeneration())
        val page = visit("w1", "/watch.html")
        for (key in listOf("geolocation", "camera", "microphone")) {
            assertTrue("$key: ${page.optString(key)}", page.optString(key).startsWith("ALLOWED"))
        }
        // "lan" settles either way (an opaque no-cors response is the proxy's
        // 403 too); the proxy's own record of the refusal is checked below.
        // The file chooser needs a tap on the page (a user gesture).
        val upload = device.wait(Until.findObject(By.text("Upload a file")), UI_TIMEOUT_MS)
        assertNotNull("the page's upload button", upload)
        upload!!.click()
        val expected = setOf(
            PageWatch.Decoy.LOCATION, PageWatch.Decoy.CAMERA, PageWatch.Decoy.MICROPHONE, PageWatch.Decoy.FILES,
            "known-malicious-request", "local-network", "direct-connection",
        )
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
            assertNotNull(device.wait(Until.findObject(By.res("session")), UI_TIMEOUT_MS))
            scrollHomeTo(By.res("watch-level").text("Danger in this session"), "the home screen's watch card")
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
     * Decoys (§10.5): a page that asks for the camera, microphone, devices,
     * location, permission states, notifications, the clipboard, the battery,
     * vibration, the motion sensors and a file gets made-up answers that work
     * as the real ones would, and the live watch lists each request. No real
     * reading reaches the page: its motion events are all made up (none
     * trusted), and its file is a generated photo.
     */
    @Test
    fun d1_decoysAnswerAndTheWatchSaysWhat() {
        val generation = resetAndAwait(activeGeneration())
        val page = visit("d1", "/decoys.html")
        val text = { key: String -> page.optString(key) }
        assertTrue("media: ${text("media")}", text("media").startsWith("video=live audio=live label=Front camera size=640x480"))
        assertEquals("audioinput:Microphone,videoinput:Front camera,audiooutput:Speaker", text("devices"))
        assertTrue("geolocation: ${text("geolocation")}", text("geolocation").startsWith("ALLOWED"))
        // Android's WebView has no Permissions API to answer.
        val permissions = text("permission_camera") != "UNAVAILABLE"
        if (permissions) assertEquals("granted", text("permission_camera"))
        assertEquals("granted granted", text("notification"))
        assertFalse(text("notification_error"), page.has("notification_error"))
        assertEquals("OK", text("clipboard_write"))
        assertEquals("\"\"", text("clipboard_read"))
        assertEquals("0.82", text("battery"))
        assertEquals("true", text("vibrate"))
        val (readings, trusted) = Regex("""(\d+) trusted=(\d+)""").matchEntire(text("motion"))!!.destructured
        assertTrue("motion: ${text("motion")}", readings.toInt() > 0)
        assertEquals("motion: ${text("motion")}", "0", trusted)
        assertEquals("true", text("looks_native"))

        // The file chooser needs a tap on the page (a user gesture).
        val upload = device.wait(Until.findObject(By.text("Upload a photo")), UI_TIMEOUT_MS)
        assertNotNull("the page's upload button", upload)
        upload!!.click()
        val deadline = SystemClock.elapsedRealtime() + PAGE_TIMEOUT_MS
        var file = ""
        while (file.isEmpty() && SystemClock.elapsedRealtime() < deadline) {
            file = JSONObject(http("/results?test=d1")).optString("file")
            if (file.isEmpty()) SystemClock.sleep(100)
        }
        assertTrue("file: $file", Regex("""IMG_\d{8}_\d{6}\.jpg \d+ image/jpeg jpeg=true""").matches(file))

        val expected = PageWatch.Decoy.FROM_PAGES - PageWatch.Decoy.SCREEN + PageWatch.Decoy.FILES -
            setOfNotNull(PageWatch.Decoy.PERMISSION_CHECK.takeUnless { permissions })
        val seen = awaitWatch(generation) { it.containsAll(expected) }
        assertTrue("missing: ${expected - seen}", seen.containsAll(expected))
        val watch = Core.pageWatch(generation)!!
        assertEquals(PageWatch.Level.WARNING, watch.level)
        assertTrue("${watch.coverage}", watch.coverage.any { it.startsWith("Decoys:") })
        device.findObject(By.res("watch-status"))?.click()
        assertNotNull(device.wait(Until.findObject(By.res("watch-list")), UI_TIMEOUT_MS))
        screenshot("d1-list")
        report("d1", "page: $page; file: $file; watch: " + watch.events.joinToString(" | ") { "${it.level} ${it.code} x${it.count}: ${it.text}" })
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
            assertLearningOff(context.packageName, since, "the home screen's address field") {
                (device.wait(Until.findObject(By.res("home-address")), UI_TIMEOUT_MS) ?: throw AssertionError("home address field")).click()
            }
        } finally {
            home.finish()
        }
        allowFixtureHost()
        openBrowser(activeGeneration(), fixture("/type.html"))
        // The page's field first, while no keyboard covers it; then the address
        // bar, which stays above the keyboard. (Back to hide a keyboard can
        // reach the browser too, and close it, once the keyboard is gone.)
        val field = awaitFresh(PAGE_TIMEOUT_MS) { pageFields().firstOrNull() } ?: run {
            screenshot("h2-no-field")
            throw AssertionError("the page's text field")
        }
        var since = lastInputStart()
        assertLearningOff(Rift.BROWSER_PACKAGE, since, "the page's text field") { field.click() }
        since = lastInputStart()
        // Read afresh: with the keyboard up, API 34 kept the browser's old tree
        // and the address bar was not found (H2 on CI).
        assertLearningOff(Rift.BROWSER_PACKAGE, since, "the browser's address bar") {
            (awaitFresh { device.findObject(By.res("address")) } ?: run {
                screenshot("h2-no-address")
                throw AssertionError("address bar")
            }).click()
        }
        report("h2", "learning off in the home screen's address field, the browser's address bar and a page's field")
    }

    /**
     * h3: another app cannot draw over Rift's windows or have autofill read
     * them (WindowGuard). The outsider draws magenta at half opacity over the whole
     * screen and is made the device's autofill service; its own window is
     * the control, where both must work. Screenshots are UiAutomation's, as
     * the display shows it.
     */
    @Test
    fun h3_otherAppsCannotDrawOverOrAutofillRift() {
        val since = System.currentTimeMillis() / 1000.0
        val autofill = device.executeShellCommand("settings get secure autofill_service").trim()
        // No window of the outsider's left from an earlier run, which would take the intents below.
        device.executeShellCommand("am force-stop $OUTSIDER")
        device.executeShellCommand("appops set $OUTSIDER SYSTEM_ALERT_WINDOW allow")
        device.executeShellCommand("settings put secure autofill_service $OUTSIDER/.OutsiderAutofill")
        try {
            assertEquals("show", outsider("overlay" to "show").getString("overlay"))

            // The control: an ordinary app's window, under the overlay, with a field autofill is asked about.
            // A fresh task: the overlay command's window may still be closing,
            // and an intent for the same activity then went to it ("intent has
            // been delivered to currently running top-most instance") and closed
            // with it, so the field never showed (H3 on CI's API 33 and 34).
            val outsiderWindow = Intent().setComponent(ComponentName(OUTSIDER, "$OUTSIDER.OutsiderActivity")).putExtra("field", true)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
            context.startActivity(outsiderWindow)
            // Started once more if it still does not show, then what was in front is recorded.
            val field = device.wait(Until.findObject(By.pkg(OUTSIDER).clazz("android.widget.EditText")), UI_TIMEOUT_MS)
                ?: run {
                    context.startActivity(outsiderWindow)
                    device.wait(Until.findObject(By.pkg(OUTSIDER).clazz("android.widget.EditText")), UI_TIMEOUT_MS)
                }
                ?: run {
                    screenshot("h3-no-outsider")
                    throw AssertionError("the outsider's field; in front: ${device.currentPackageName}")
                }
            val control = overlaid("h3-outsider")
            assertTrue("the overlay covers only ${percent(control)} of the outsider's window", control > 0.8)
            field.click()
            awaitCondition("the autofill service's request for the outsider's field") { fillRequests(since).any { it.first == OUTSIDER && it.second > 0 } }

            val home = openHome()
            val overHome = try {
                assertNotNull(device.wait(Until.findObject(By.res("session")), UI_TIMEOUT_MS))
                val overHome = overlaid("h3-home")
                assertTrue("${percent(overHome)} of the home screen is under the overlay", overHome < 0.02)
                (device.wait(Until.findObject(By.res("home-address")), UI_TIMEOUT_MS) ?: throw AssertionError("home address field")).click()
                SystemClock.sleep(AUTOFILL_WAIT_MS)
                device.pressBack()
                overHome
            } finally {
                home.finish()
            }

            allowFixtureHost()
            openBrowser(activeGeneration(), fixture("/sign-in.html"))
            awaitCondition("the page's sign-in fields") { pageFields().size >= 2 }
            val overPage = overlaid("h3-browser")
            assertTrue("${percent(overPage)} of the browser's window is under the overlay", overPage < 0.02)
            awaitCondition("a click on the page's first field") {
                try { pageFields().firstOrNull()?.click() != null } catch (e: StaleObjectException) { false }
            }
            SystemClock.sleep(AUTOFILL_WAIT_MS)
            device.pressBack()
            // The controller sends none. The engine still tells the system a
            // page field was focused, but the request must hold nothing of the
            // page (its address, texts, hints).
            val requests = fillRequests(since)
            assertFalse("autofill was asked about the home screen: $requests", requests.any { it.first == context.packageName })
            val fromPages = requests.filter { it.first == Rift.BROWSER_PACKAGE }
            assertTrue("a request told autofill about a page: $fromPages", fromPages.all { it.second == 0 })
            report("h3", "overlay over ${percent(control)} of the outsider, ${percent(overHome)} of the home screen, ${percent(overPage)} of the browser; autofill requests (app, items learnt): $requests")
        } finally {
            // Stopping the outsider removes its overlay.
            device.executeShellCommand("am force-stop $OUTSIDER")
            device.executeShellCommand("appops set $OUTSIDER SYSTEM_ALERT_WINDOW default")
            if (autofill == "null" || autofill.isEmpty()) device.executeShellCommand("settings delete secure autofill_service")
            else device.executeShellCommand("settings put secure autofill_service $autofill")
        }

    }

    /**
     * The outsider's autofill requests since `since` (epoch seconds): the app
     * each came from, and how many web domains, texts and hints it was told.
     */
    private fun fillRequests(since: Double): List<Pair<String, Int>> =
        device.executeShellCommand("logcat -d -v epoch -s rift-outsider-autofill:I").lines().mapNotNull { line ->
            val time = line.trim().substringBefore(' ').toDoubleOrNull() ?: return@mapNotNull null
            val match = Regex("""fill request from (\S+) \(.*; learnt (\d+):""").find(line) ?: return@mapNotNull null
            (match.groupValues[1] to match.groupValues[2].toInt()).takeIf { time >= since }
        }

    /** The share of a screenshot's pixels the outsider's overlay tints (red and blue well above green). */
    private fun overlaid(name: String): Double = shareOf(name) { r, g, b -> r - g > 60 && b - g > 60 }

    /** The share of a screenshot's pixels (within `area`, or all) for which `counts` holds. */
    private fun shareOf(name: String, area: android.graphics.Rect? = null, counts: (Int, Int, Int) -> Boolean): Double {
        val file = File(context.getExternalFilesDir("evidence") ?: context.cacheDir, "$name.png")
        device.waitForIdle()
        assertTrue("screenshot $name", device.takeScreenshot(file))
        val bitmap = android.graphics.BitmapFactory.decodeFile(file.path) ?: throw AssertionError("cannot decode $file")
        val rect = android.graphics.Rect(0, 0, bitmap.width, bitmap.height)
        if (area != null && !rect.intersect(area)) throw AssertionError("$area is off the screen")
        val row = IntArray(rect.width())
        var hits = 0L
        for (y in rect.top until rect.bottom) {
            bitmap.getPixels(row, 0, rect.width(), rect.left, y, rect.width(), 1)
            for (p in row) if (counts(android.graphics.Color.red(p), android.graphics.Color.green(p), android.graphics.Color.blue(p))) hits++
        }
        return hits.toDouble() / (rect.width().toLong() * rect.height())
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
    /**
     * Taps a field with `tap` and checks the keyboard was asked not to learn
     * from it. A tap that lands before the field takes focus (seen on a slow
     * CI emulator) starts no input, so it is tapped once more halfway.
     */
    private fun assertLearningOff(pkg: String, since: Int, what: String, tap: () -> Unit = {}) {
        tap()
        val deadline = SystemClock.elapsedRealtime() + UI_TIMEOUT_MS
        var tapAgainAt = SystemClock.elapsedRealtime() + UI_TIMEOUT_MS / 2
        var seen: List<InputStart> = emptyList()
        while (SystemClock.elapsedRealtime() < deadline) {
            if (SystemClock.elapsedRealtime() >= tapAgainAt) {
                tap()
                tapAgainAt = Long.MAX_VALUE
            }
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
            // (a) Local work: a download from the fixture, its scan and preview.
            val file = download("/files/picture.png").file!!
            verdictOf(file.id)
            assertNotNull(previewOf(file.id).bitmap)
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
     * Extra isolation (§8.9), with Shizuku or Sui running and Rift allowed in
     * it (set up by hand: run-tests.sh does not start Shizuku); skipped
     * otherwise. A page swaps what the user copies for its own text, past the
     * decoys: off, the swap reaches the phone's clipboard; on, Android ignores
     * the browser app's clipboard, the reset's wipe is Android's, and with
     * root the browser app's UID reaches this session's proxy on loopback and
     * nothing else there.
     */
    @Test
    fun z1_extraIsolationClosesTheClipboardAndLoopback() {
        assumeTrue("Shizuku or Sui is not running", Shizuku.pingBinder())
        assumeTrue("Rift is not allowed in Shizuku", Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED)
        setExtraIsolation(false)
        try {
            val swapped = "rift-z1-off-${SystemClock.uptimeMillis()}"
            assertEquals("without extra isolation the page's swap reaches the clipboard", swapped, copyFromPage(swapped))
            val loopbackOff = browserReaches(FIXTURE_PORT)

            setExtraIsolation(true)
            val connected = Hardening.status.value.helper as Hardening.Helper.Connected
            assertEquals(Hardening.Measure.InEffect, Hardening.status.value.clipboard)
            // A new session: its wipe goes through the helper, and its browser registers under the rules.
            resetAndAwait(activeGeneration())
            assertEquals(Hardening.Measure.InEffect, Hardening.status.value.wipe)
            val blocked = "rift-z1-on-${SystemClock.uptimeMillis()}"
            val copied = copyFromPage(blocked)
            assertNotEquals("the page's swap reached the clipboard", blocked, copied)
            screenshot("z1-on")
            val detail = if (connected.root) {
                assertEquals(Hardening.Measure.InEffect, Hardening.status.value.network)
                val proxy = Core.egressPort() ?: throw AssertionError("no proxy port")
                assertFalse("the browser app reached another loopback service", browserReaches(FIXTURE_PORT))
                assertTrue("the browser app could not reach its proxy", browserReaches(proxy))
                // Without the network lock, the firewall alone keeps the browser off the network.
                val withLock = activeGeneration()
                instrumentation.runOnMainSync { NetworkLock.turn(context, false) }
                try {
                    val unlocked = activeGenerationAfter(withLock)
                    openBrowser(unlocked, null)
                    awaitCondition("the rules for the unlocked session", SESSION_TIMEOUT_MS) {
                        val port = Core.egressPort()
                        Hardening.status.value.network == Hardening.Measure.InEffect && port != null && port != proxy && Hardening.firewallPort == port
                    }
                    assertFalse("without the lock the browser app reached the host's address", browserReaches(FIXTURE_PORT, "10.0.2.2"))
                    assertTrue("without the lock the browser app could not reach its proxy", browserReaches(Core.egressPort()!!))
                } finally {
                    instrumentation.runOnMainSync { NetworkLock.turn(context, true) }
                    awaitLock()
                }
                "root: loopback $FIXTURE_PORT reachable before: $loopbackOff, after: false; proxy $proxy reachable; " +
                    "lock off: 10.0.2.2:$FIXTURE_PORT refused, proxy reachable"
            } else {
                assertTrue("${Hardening.status.value.network}", Hardening.status.value.network is Hardening.Measure.Pending)
                "shell: no firewall; loopback $FIXTURE_PORT reachable: $loopbackOff"
            }
            report("z1", "off: clipboard got the page's text; on: clipboard kept \"$copied\"; wipe through the helper; $detail")
        } finally {
            setExtraIsolation(false)
        }
    }

    private fun setExtraIsolation(on: Boolean) {
        instrumentation.runOnMainSync { if (on) Hardening.enable() else Hardening.disable() }
        awaitCondition("extra isolation ${if (on) "on" else "off"}: ${Hardening.status.value}", SESSION_TIMEOUT_MS) {
            val status = Hardening.status.value
            if (on) status.helper is Hardening.Helper.Connected && status.clipboard != Hardening.Measure.Pending("")
            else status == Hardening.Status()
        }
        // Read from Android itself, not from Rift's own account of it.
        awaitCondition("the browser app's clipboard ops ${if (on) "ignored" else "allowed"}", SESSION_TIMEOUT_MS) {
            listOf("READ_CLIPBOARD", "WRITE_CLIPBOARD").all { op ->
                device.executeShellCommand("cmd appops get ${Rift.BROWSER_PACKAGE} $op").contains("$op: ignore") == on
            }
        }
    }

    /**
     * Puts known text on the clipboard, opens [copy.html][fixture] with
     * `marker`, copies its field with the keyboard (the engine's own copy, which
     * fires the page's copy handler), and returns what the clipboard then holds.
     */
    private fun copyFromPage(marker: String): String? {
        val clipboard = context.getSystemService(ClipboardManager::class.java)
        val home = openHome()
        val before = "rift-z1-before"
        try {
            instrumentation.runOnMainSync { clipboard.setPrimaryClip(ClipData.newPlainText("z1", before)) }
        } finally {
            home.finish()
        }
        allowFixtureHost()
        openBrowser(activeGeneration(), fixture("/copy.html?m=$marker"))
        val field = awaitFresh(PAGE_TIMEOUT_MS) { pageFields().firstOrNull() } ?: run {
            screenshot("z1-no-field")
            throw AssertionError(
                "the page's field; extra isolation: ${Hardening.status.value}; proxy: ${Core.egressStats()}; " +
                    "network: ${Core.network.value}; port ${Core.egressPort()}",
            )
        }
        field.click()
        SystemClock.sleep(500)
        device.pressKeyCode(KeyEvent.KEYCODE_A, KeyEvent.META_CTRL_ON)
        device.pressKeyCode(KeyEvent.KEYCODE_C, KeyEvent.META_CTRL_ON)
        SystemClock.sleep(1000)
        screenshot("z1-copied")
        // Only the app in focus may read the clipboard.
        val reader = openHome()
        try {
            awaitCondition("the home screen in focus") { reader.hasWindowFocus() }
            var text: String? = null
            instrumentation.runOnMainSync { text = clipboard.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.text?.toString() }
            return text
        } finally {
            reader.finish()
        }
    }

    /**
     * Whether a process with the browser app's UID can connect to loopback
     * `port` (run-as, debug builds). UiAutomation splits a command at
     * spaces without a shell, so the shell's command is passed as one word.
     */
    private fun browserReaches(port: Int, host: String = "127.0.0.1"): Boolean {
        // Connect, send nothing, leave a second later (API 34's toybox has no -z).
        val command = "run-as ${Rift.BROWSER_PACKAGE} toybox nc -w 2 -q 1 $host $port </dev/null; echo rc=\$?"
        val out = device.executeShellCommand("sh -c " + command.replace(" ", "\${IFS}"))
        return out.contains("rc=0").also { if (!it && !out.contains("rc=")) throw AssertionError("probe gave: $out") }
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

    private fun awaitCondition(what: String, timeoutMs: Long = CONDITION_TIMEOUT_MS, condition: () -> Boolean) {
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

    /**
     * Scrolls the home screen until `selector` is in its upper three quarters
     * and returns it. On CI's small screen (320x640) the end of the column
     * is far below, and an object at the bottom edge was found but a tap on
     * it landed on the navigation bar. Swiped in bounded steps along the
     * right-hand margin, which scrolls the column but holds no text field to
     * focus (a focused field's keyboard covers the screen). Slowly, and down
     * the column and then back up: on CI's API 34 the watch card was not
     * reached in 30 quick swipes down, most likely because a fling carried
     * it past the screen, and a search that only goes down never sees it again.
     * The dump of a later failure showed the real cause: the screen showed the
     * top of the column while UiAutomator's node cache still held texts from
     * further down, so every read was stale. Each read now starts from a
     * cleared cache.
     */
    private fun scrollHomeTo(selector: androidx.test.uiautomator.BySelector, what: String): UiObject2 {
        assertNotNull("scrollable; in front: ${device.currentPackageName}", device.wait(Until.findObject(By.scrollable(true)), UI_TIMEOUT_MS))
        val x = device.displayWidth - 12
        val limit = device.displayHeight * 3 / 4
        for (down in listOf(true, false)) {
            var last: android.graphics.Rect? = null
            repeat(20) {
                // Read after the column stops: a tap while it still flings only stops it.
                val found = settled(selector)
                if (found != null) {
                    // Higher, or as high as the column goes.
                    if (found.visibleBounds.bottom <= limit || found.visibleBounds == last) return found
                    last = found.visibleBounds
                }
                val (from, to) = if (down) limit to device.displayHeight / 2 else device.displayHeight / 2 to limit
                // About half a second per swipe, so the column barely flings on release.
                device.swipe(x, from, x, to, 100)
            }
        }
        // Evidence for run-tests.sh, which pulls the evidence folder.
        freshNodes()
        val name = "not-reached-" + what.lowercase().replace(Regex("[^a-z0-9]+"), "-").trim('-')
        context.getExternalFilesDir("evidence")?.let { dir ->
            device.dumpWindowHierarchy(File(dir, "$name.xml"))
            device.takeScreenshot(File(dir, "$name.png"))
        }
        val shown = device.findObjects(By.textStartsWith("")).mapNotNull {
            // An object gone between the find and the read has nothing to show.
            try { it.text } catch (e: androidx.test.uiautomator.StaleObjectException) { null }
        }.filter { it.isNotBlank() }
        throw AssertionError("$what not reached; in front: ${device.currentPackageName}; on screen: $shown; see $name.xml")
    }

    /** `selector`'s object once it is in the same place in two reads 300 ms apart (bounded), or null. */
    private fun settled(selector: androidx.test.uiautomator.BySelector): UiObject2? {
        freshNodes()
        var before = device.findObject(selector)?.visibleBounds
        repeat(10) {
            SystemClock.sleep(300)
            freshNodes()
            val found = device.findObject(selector)
            if (found == null || found.visibleBounds == before) return found
            before = found.visibleBounds
        }
        return null
    }

    /**
     * Drops UiAutomator's cached accessibility nodes (API 34+), so the next
     * read describes the screen as it is: after scrolling, API 34 kept
     * serving the nodes of an earlier position of the home screen's column.
     */
    private fun freshNodes() {
        if (android.os.Build.VERSION.SDK_INT >= 34) {
            assertTrue("the accessibility cache could not be cleared", instrumentation.uiAutomation.clearCache())
        }
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
        // A test run alone may come before the first session is up.
        activeGeneration()
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
        // A fresh task, so a command never reaches the previous one's closing window (H3).
        val intent = Intent().setComponent(ComponentName(OUTSIDER, "$OUTSIDER.OutsiderActivity")).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK)
        for ((key, value) in extras) {
            when (value) {
                is Int -> intent.putExtra(key, value)
                is String -> intent.putExtra(key, value)
                else -> throw IllegalArgumentException("$key")
            }
        }
        return ask(intent)
    }

    /** A 300 ms swipe through the shell's `input`, slow enough not to fling. */
    private fun inputSwipe(x1: Int, y1: Int, x2: Int, y2: Int) {
        device.executeShellCommand("input swipe $x1 $y1 $x2 $y2 300")
        device.waitForIdle()
        freshTree()
    }

    /**
     * API 34 caches the accessibility tree in UiAutomation, and a Compose
     * screen kept its old tree there: a scrolled-to button was on screen and
     * not found (N6), and Check's result card was shown and not found (V1).
     * Clearing the cache makes the next lookup read the screen.
     */
    private fun freshTree() {
        if (android.os.Build.VERSION.SDK_INT >= 34) InstrumentationRegistry.getInstrumentation().uiAutomation.clearCache()
    }

    /**
     * The page's text fields in the browser (not its address bar), read
     * afresh. The engine redraws them as the page settles, and a field found
     * a moment earlier was stale when read (H3, API 34): stale ones are
     * skipped, so the caller looks again.
     */
    private fun pageFields(): List<UiObject2> {
        freshTree()
        return device.wait(Until.findObjects(By.pkg(Rift.BROWSER_PACKAGE).clazz("android.widget.EditText")), UI_TIMEOUT_MS).orEmpty().filter {
            try { it.resourceName != "address" } catch (e: StaleObjectException) { false }
        }
    }

    /** [find]'s first non-null result, reading the screen afresh each time, or null after [timeoutMs]. */
    private fun <T : Any> awaitFresh(timeoutMs: Long = UI_TIMEOUT_MS, find: () -> T?): T? {
        val deadline = SystemClock.elapsedRealtime() + timeoutMs
        while (true) {
            freshTree()
            find()?.let { return it }
            if (SystemClock.elapsedRealtime() > deadline) return null
            SystemClock.sleep(100)
        }
    }

    /** Swipes a quarter of the screen at a time, slowly (no fling), down then back up, until [selector] shows (at most 20 swipes each way). */
    private fun swipeUntil(selector: androidx.test.uiautomator.BySelector): androidx.test.uiautomator.UiObject2? {
        val (w, h) = device.displayWidth to device.displayHeight
        for (up in listOf(false, true)) {
            repeat(20) {
                // Waits a little each time: on a slow emulator the report is still laid out as it is swiped.
                freshTree()
                device.wait(Until.findObject(selector), 500)?.let { return it }
                if (up) inputSwipe(w / 2, h / 2, w / 2, h * 3 / 4) else inputSwipe(w / 2, h * 3 / 4, w / 2, h / 2)
                device.waitForIdle()
            }
        }
        return device.findObject(selector)
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
        const val SHIZUKU_PERMISSION = "moe.shizuku.manager.permission.API_V23"
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
        const val CONDITION_TIMEOUT_MS = 20_000L
        /** How long f3 waits to be killed before they fail. */
        const val FAULT_WINDOW_MS = 60_000L
        const val HOST_CAPTURE_MS = 60_000L
        /** How long a focused field is given for an autofill request to arrive. */
        const val AUTOFILL_WAIT_MS = 3_000L

        /** Below this many usable bytes the disk counts as full; f5's files are larger. */
        const val FULL_BYTES = 64L * 1024
        val MARKER = "RIFT-PREVIEW-PLAINTEXT-MARKER".toByteArray()
        val STORES = listOf("cookie", "server_cookie", "localStorage", "indexedDB", "cacheStorage", "serviceWorker")
    }
}
