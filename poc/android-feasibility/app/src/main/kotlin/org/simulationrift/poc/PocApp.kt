package org.simulationrift.poc

import android.app.Application
import android.webkit.WebView

class PocApp : Application() {
    override fun onCreate() {
        super.onCreate()
        // Must run before any WebView use in this process. Each generation gets
        // its own directory, so a reset never reuses state from an old session.
        if (getProcessName().endsWith(":browser")) {
            WebView.setDataDirectorySuffix(Generation.suffix(Generation.read(this)))
        }
    }
}
