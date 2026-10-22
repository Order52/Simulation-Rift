package org.simulationrift.browser

import android.webkit.WebResourceRequest
import java.util.Locale

/** What a request is for, as the filter engine's request kinds name it (§10.9). */
internal object ContentKind {

    private val IMAGES = setOf("png", "jpg", "jpeg", "gif", "webp", "svg", "ico", "avif", "bmp")
    private val FONTS = setOf("woff", "woff2", "ttf", "otf", "eot")
    private val MEDIA = setOf("mp4", "webm", "m4v", "mp3", "ogg", "m4a", "wav", "m3u8", "mpd")

    fun of(request: WebResourceRequest): String {
        val headers = request.requestHeaders
        // The engine's own word, when it gives one.
        when (headers["Sec-Fetch-Dest"]?.lowercase(Locale.ROOT)) {
            "script", "worker", "sharedworker", "serviceworker" -> return "script"
            "style" -> return "stylesheet"
            "image" -> return "image"
            "font" -> return "font"
            "iframe", "frame", "fencedframe" -> return "subdocument"
            "audio", "video", "track" -> return "media"
            "empty" -> return "xmlhttprequest"
        }
        val extension = request.url.lastPathSegment?.substringAfterLast('.', "")?.lowercase(Locale.ROOT).orEmpty()
        val accept = headers["Accept"].orEmpty().lowercase(Locale.ROOT)
        return when {
            extension == "js" || extension == "mjs" -> "script"
            extension == "css" -> "stylesheet"
            extension in IMAGES || accept.startsWith("image/") -> "image"
            extension in FONTS -> "font"
            extension in MEDIA -> "media"
            accept.startsWith("text/html") -> "subdocument"
            else -> "other"
        }
    }
}
