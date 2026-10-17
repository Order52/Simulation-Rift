package org.simulationrift.app;

import org.simulationrift.app.IBrowser;

/**
 * The core's interface for :browser (§8.3 c). It offers navigation decisions
 * and session requests only: nothing here reaches the vault, keys or export.
 * Every call names the caller's generation, and the core ignores or blocks
 * anything from a generation that is not current.
 */
interface ICore {
    /**
     * Returns false if `generation` is not the active session. The browser
     * must then exit without touching WebView, so it cannot recreate the data
     * directory of a disposed session.
     */
    boolean register(long generation, IBrowser browser);

    /** The renderer-sandbox precondition result (§8.4, INV-7). */
    void reportSandbox(long generation, boolean verified, String detail);

    /** A main-frame navigation decision, encoded by NavigationDecision. */
    Bundle decide(long generation, String url);

    /** The URL to decide for text typed in the address bar. */
    String typedAddress(String input);

    oneway void requestReset(long generation);

    /** The renderer died: the session is torn down (INV-7). */
    oneway void rendererGone(long generation, boolean crashed);
}
