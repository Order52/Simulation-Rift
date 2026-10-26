package org.simulationrift.bridge

import android.os.Bundle

/**
 * The controller's answer to a browser that registers for a session: how to
 * reach the network (§8.8), or why it may not browse at all.
 */
sealed interface SessionGrant {
    /**
     * The egress proxy of this session and the isolation it runs under.
     * `proxyToken` is a secret: it is used only to answer the proxy's own
     * challenge (host [Rift.PROXY_HOST], realm `proxyRealm`).
     * `outdatedWebView` lets a debug build browse in a WebView that lacks
     * fixes for exploited bugs, for testing on emulator images that cannot
     * update it; a release build never sends it, and a release browser
     * ignores it (§8.4).
     */
    data class Granted(val proxyPort: Int, val proxyToken: String, val proxyRealm: String, val mode: NetworkMode, val outdatedWebView: Boolean = false) : SessionGrant {
        override fun toString() = "Granted(port=$proxyPort, realm=$proxyRealm, mode=$mode, outdatedWebView=$outdatedWebView)"
    }

    /** `reason` is already safe to show. */
    data class Refused(val reason: String) : SessionGrant

    fun toBundle(): Bundle = Bundle().apply {
        when (val g = this@SessionGrant) {
            is Granted -> {
                putInt(PORT, g.proxyPort)
                putString(TOKEN, g.proxyToken)
                putString(REALM, g.proxyRealm)
                putString(MODE, g.mode.name)
                putBoolean(OUTDATED, g.outdatedWebView)
            }
            is Refused -> putString(REFUSED, g.reason)
        }
    }

    companion object {
        private const val PORT = "port"
        private const val TOKEN = "token"
        private const val REALM = "realm"
        private const val MODE = "mode"
        private const val REFUSED = "refused"
        private const val OUTDATED = "outdated"

        /** Anything that does not decode is a refusal: never browse without the lock's terms. */
        fun fromBundle(bundle: Bundle?): SessionGrant {
            bundle ?: return Refused("The protection core did not answer.")
            bundle.getString(REFUSED)?.let { return Refused(it) }
            val port = bundle.getInt(PORT, 0)
            val token = bundle.getString(TOKEN)
            val realm = bundle.getString(REALM)
            val mode = NetworkMode.entries.firstOrNull { it.name == bundle.getString(MODE) }
            if (port !in 1..65535 || token.isNullOrEmpty() || realm.isNullOrEmpty() || mode == null) {
                return Refused("The protection core sent an invalid session grant.")
            }
            return Granted(port, token, realm, mode, bundle.getBoolean(OUTDATED, false))
        }
    }
}

/** How the browser's network is bounded in a session (§8.8). */
enum class NetworkMode {
    /** The egress proxy behind the browser-only VPN: the normal mode. */
    LOCKED,

    /**
     * Proxy only, chosen by the user for one session when the VPN cannot run.
     * WebRTC can reach the local network and escaped code is not bounded;
     * the trusted bar says so for the whole session.
     */
    REDUCED,
}
