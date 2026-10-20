package org.simulationrift.browser

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import androidx.webkit.ProxyConfig
import androidx.webkit.ProxyController
import androidx.webkit.WebViewFeature
import java.util.concurrent.Executor
import org.simulationrift.bridge.Rift

/**
 * The browser's side of the network lock (§8.8). The controller enforces
 * the lock; these checks make the browser refuse to load a page when it is
 * not in effect, and leave when it stops being in effect.
 */
object NetworkLock {

    /**
     * Sends every WebView request in this process to the egress proxy,
     * loopback included (`removeImplicitRules`: PoC A8 found that Chromium
     * otherwise connects to loopback and link-local addresses directly).
     * Calls `done` with null once the override is in effect, or with the
     * reason it cannot be.
     */
    fun applyProxy(port: Int, executor: Executor, done: (String?) -> Unit) {
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)) {
            done("this WebView cannot be given a proxy")
            return
        }
        val config = ProxyConfig.Builder()
            .addProxyRule("${Rift.PROXY_HOST}:$port")
            .removeImplicitRules()
            .build()
        try {
            ProxyController.getInstance().setProxyOverride(config, executor) { done(null) }
        } catch (e: IllegalArgumentException) {
            done("the proxy was refused: ${e.message}")
        }
    }

    /**
     * Whether this app's default network is a VPN. The controller has just
     * confirmed that its own browser-only VPN is up, and a device runs one
     * VPN at a time, so a VPN here is the lock.
     */
    fun defaultIsVpn(context: Context): Boolean {
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        val network = connectivity.activeNetwork ?: return false
        return connectivity.getNetworkCapabilities(network)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }

    /**
     * Calls `lost` (on a ConnectivityManager thread) as soon as the default
     * network is anything but a VPN. Returns the callback to unregister.
     */
    fun watch(context: Context, lost: () -> Unit): ConnectivityManager.NetworkCallback {
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                if (!capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) lost()
            }
        }
        context.getSystemService(ConnectivityManager::class.java).registerDefaultNetworkCallback(callback)
        return callback
    }

    fun unwatch(context: Context, callback: ConnectivityManager.NetworkCallback) {
        context.getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(callback)
    }
}
