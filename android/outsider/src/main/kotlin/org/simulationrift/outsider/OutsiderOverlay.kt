package org.simulationrift.outsider

import android.app.Service
import android.content.Intent
import android.graphics.Color
import android.graphics.PixelFormat
import android.os.IBinder
import android.view.View
import android.view.WindowManager

/**
 * h3: an overlay over the whole screen, as an app with "display over other
 * apps" can draw: magenta at half opacity, not touchable, so touches still
 * pass through it (below the system's 0.8 limit for that). Over Rift's
 * windows the system must hide it. `stop` removes it.
 */
class OutsiderOverlay : Service() {
    private var overlay: View? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val windows = getSystemService(WindowManager::class.java)
        if (intent?.getBooleanExtra("stop", false) == true) {
            overlay?.let(windows::removeView)
            overlay = null
            stopSelf()
            return START_NOT_STICKY
        }
        if (overlay == null) {
            val view = View(this).apply { setBackgroundColor(Color.MAGENTA) }
            val params = WindowManager.LayoutParams(
                WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
                WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE or WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                    WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
                PixelFormat.TRANSLUCENT,
            ).apply {
                alpha = 0.5f
                title = "rift-outsider-overlay"
            }
            windows.addView(view, params)
            overlay = view
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        overlay?.let { getSystemService(WindowManager::class.java).removeView(it) }
        overlay = null
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
