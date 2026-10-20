package org.simulationrift.outsider

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor

/**
 * Another app's VPN (S28). Establishing it revokes whichever VPN ran
 * before, as any VPN app would. It applies to this app's own traffic only.
 */
class OutsiderVpn : VpnService() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.getBooleanExtra("stop", false) == true) {
            tun?.close()
            tun = null
            stopSelf()
            return START_NOT_STICKY
        }
        if (tun == null) {
            tun = Builder()
                .setSession("Rift outsider test VPN")
                .addAddress("10.112.0.1", 32)
                .addRoute("10.112.0.0", 24)
                .addAllowedApplication(packageName)
                .establish()
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        tun?.close()
        tun = null
        super.onRevoke()
    }

    private companion object {
        @Volatile var tun: ParcelFileDescriptor? = null
    }
}
