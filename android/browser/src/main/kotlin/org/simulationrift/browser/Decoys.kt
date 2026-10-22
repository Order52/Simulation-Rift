package org.simulationrift.browser

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.Shader
import android.graphics.pdf.PdfDocument
import android.net.Uri
import android.webkit.WebView
import androidx.webkit.JavaScriptReplyProxy
import androidx.webkit.WebMessageCompat
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import java.io.File
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import org.json.JSONException
import org.json.JSONObject
import org.simulationrift.bridge.PageWatch

/**
 * Decoys (§10.5): a page that asks for the camera, the microphone, the
 * location, files, notifications, the clipboard or the motion sensors is
 * given something made up, and Rift's live watch is told what it asked for.
 * Nothing real is ever given: the browser app holds none of those
 * permissions, and the engine's own requests are still refused
 * ([BrowserActivity]'s Chrome client), which is what a page that gets past
 * the script meets.
 *
 * The script (assets/decoys.js) runs before any page script in every frame.
 * Its reports come back over one WebMessageListener, under a name that is
 * new for each session and removed from the page before the page runs. The
 * listener takes strings only and exposes no object, so a page can at most
 * add made-up decoy reports about itself: each is checked here against
 * [PageWatch.Decoy], bounded, and attributed to the origin the engine gives.
 */
internal class Decoys(private val context: Context, private val report: (kind: String, origin: String, detail: String) -> Unit) {

    private val random = SecureRandom()
    private val channel = "r" + hex(12)
    private val place = PLACES[random.nextInt(PLACES.size)]

    /** Installs the script and its listener on `view`; false if this WebView cannot run them before pages do. */
    fun install(view: WebView): Boolean {
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT) ||
            !WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)
        ) {
            return false
        }
        val rules = setOf("*")
        WebViewCompat.addWebMessageListener(view, channel, rules, ::onMessage)
        WebViewCompat.addDocumentStartJavaScript(view, script(), rules)
        return true
    }

    private fun script(): String = context.assets.open("decoys.js").bufferedReader().use { it.readText() }
        .replace("__RIFT_CHANNEL__", channel)
        .replace("__RIFT_LAT__", "%.5f".format(Locale.ROOT, place.first + (random.nextDouble() - 0.5) * 0.02))
        .replace("__RIFT_LON__", "%.5f".format(Locale.ROOT, place.second + (random.nextDouble() - 0.5) * 0.02))
        .replace("__RIFT_CAMERA_ID__", hex(32))
        .replace("__RIFT_MIC_ID__", hex(32))
        .replace("__RIFT_GROUP_ID__", hex(32))

    @Suppress("UNUSED_PARAMETER") // the listener's signature
    private fun onMessage(view: WebView, message: WebMessageCompat, sourceOrigin: Uri, isMainFrame: Boolean, reply: JavaScriptReplyProxy) {
        val data = message.data?.takeIf { it.length <= MAX_MESSAGE_CHARS } ?: return
        val parsed = try {
            JSONObject(data)
        } catch (e: JSONException) {
            return
        }
        val kind = parsed.optString("k").takeIf { it in PageWatch.Decoy.FROM_PAGES } ?: return
        val detail = parsed.optString("d").take(MAX_DETAIL_CHARS)
        // The engine's word for where the message came from, not the page's.
        report(kind, sourceOrigin.toString(), detail)
    }

    /**
     * A made-up file for a page's file chooser, of the kind it accepts: a
     * photo, a PDF or a text note, written into the browser app's cache
     * (wiped with the rest of its data at the end of the session).
     */
    fun file(acceptTypes: Array<String>): File {
        val accepts = acceptTypes.flatMap { it.split(',') }.map { it.trim().lowercase(Locale.ROOT) }.filter { it.isNotEmpty() }
        val wants = { prefix: String, extension: String -> accepts.any { it.startsWith(prefix) || it == extension } }
        val dir = File(context.cacheDir, "decoys").apply { mkdirs() }
        val stamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.ROOT).format(Date(System.currentTimeMillis() - (random.nextDouble() * MAX_AGE_MS).toLong()))
        return when {
            wants("image/", ".jpg") || wants("image/", ".png") -> File(dir, "IMG_$stamp.jpg").also(::writePhoto)
            wants("application/pdf", ".pdf") -> File(dir, "Scan_$stamp.pdf").also(::writePdf)
            else -> File(dir, "notes.txt").also { it.writeText(NOTE) }
        }
    }

    private fun writePhoto(file: File) {
        val bitmap = Bitmap.createBitmap(1200, 900, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bitmap)
        val paint = Paint()
        paint.shader = LinearGradient(0f, 0f, 0f, 900f, Color.rgb(150, 180, 210), Color.rgb(90, 95, 80), Shader.TileMode.CLAMP)
        canvas.drawRect(0f, 0f, 1200f, 900f, paint)
        paint.shader = null
        repeat(3000) {
            val v = 60 + random.nextInt(120)
            paint.color = Color.argb(40, v, v, v)
            canvas.drawRect(random.nextFloat() * 1200, random.nextFloat() * 900, 0f, 0f, paint)
        }
        file.outputStream().use { bitmap.compress(Bitmap.CompressFormat.JPEG, 85, it) }
        bitmap.recycle()
    }

    private fun writePdf(file: File) {
        val pdf = PdfDocument()
        val page = pdf.startPage(PdfDocument.PageInfo.Builder(595, 842, 1).create())
        val paint = Paint().apply { textSize = 14f }
        NOTE.lines().forEachIndexed { i, line -> page.canvas.drawText(line, 60f, 80f + i * 22f, paint) }
        pdf.finishPage(page)
        file.outputStream().use { pdf.writeTo(it) }
        pdf.close()
    }

    private fun hex(bytes: Int): String = ByteArray(bytes / 2).also(random::nextBytes).joinToString("") { "%02x".format(it) }

    companion object {
        private const val MAX_MESSAGE_CHARS = 1024
        private const val MAX_DETAIL_CHARS = 200
        /** A made-up file looks taken some time in the last 40 days. */
        private const val MAX_AGE_MS = 40 * 86_400_000L

        private const val NOTE = "Shopping list\n- milk\n- bread\n- coffee\n- batteries (AA)\n"

        /** City centres; a session's decoy location is near one of them. */
        private val PLACES = listOf(
            48.8566 to 2.3522, // Paris
            51.5072 to -0.1276, // London
            40.7128 to -74.0060, // New York
            35.6762 to 139.6503, // Tokyo
            52.5200 to 13.4050, // Berlin
            -33.8688 to 151.2093, // Sydney
            43.6532 to -79.3832, // Toronto
            41.9028 to 12.4964, // Rome
        )
    }
}
