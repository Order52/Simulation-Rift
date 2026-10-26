package org.simulationrift.browser

import android.app.Activity
import android.os.Bundle

/**
 * Starts the browser app's default process and does nothing else. Some
 * phones (Huawei's App launch, Xiaomi's Autostart, ColorOS's auto launch)
 * refuse to start an app for another app's bindService, but let an app in
 * front open another app's screen; once this process runs, the controller
 * binds to SessionService in it. No window, no file: it finishes at once,
 * in the process that never loads WebView.
 */
class WakeActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        finish()
    }
}
