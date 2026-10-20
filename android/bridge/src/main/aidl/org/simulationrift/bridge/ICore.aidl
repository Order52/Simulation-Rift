package org.simulationrift.bridge;

import org.simulationrift.bridge.IBrowser;

/**
 * The controller's interface for the browser app (§8.3). It offers
 * navigation decisions and session requests only: nothing here reaches the
 * vault, keys, files or export. The service requires the signature
 * permission, and every call is checked for the browser app's UID and
 * signer. Every call names the caller's generation, and the core ignores or
 * blocks anything from a generation that is not current.
 */
interface ICore {
    /**
     * The session grant, encoded by SessionGrant: the egress proxy's port,
     * token and realm and the network-lock mode, or why browsing is refused.
     * After a refusal the browser must exit without touching WebView, so it
     * cannot recreate a disposed session's data directory.
     */
    Bundle register(long generation, IBrowser browser);

    /** The renderer-sandbox precondition result (§8.4, INV-7). */
    void reportSandbox(long generation, boolean verified, String detail);

    /**
     * The network precondition result (§8.8, INV-14): whether the proxy
     * override is in place and whether the browser's default network is the
     * network lock.
     */
    void reportNetwork(long generation, boolean proxied, boolean locked, String detail);

    /** A main-frame navigation decision, encoded by NavigationDecision. */
    Bundle decide(long generation, String url);

    /** The URL to decide for text typed in the address bar. */
    String typedAddress(String input);

    /**
     * The engine reported a download (§8.5). The core fetches it again itself
     * into the session's encrypted quarantine; `cookie` is the engine's cookie
     * header for `url` only. Results appear in the trusted home screen.
     */
    oneway void submitDownload(long generation, String url, String cookie, String userAgent, String referer, String contentDisposition);

    oneway void requestReset(long generation);

    /** The renderer died: the session is torn down (INV-7). */
    oneway void rendererGone(long generation, boolean crashed);

    /**
     * The engine reported something a page tried that only it can see, and
     * that was refused (§10.5): `kind` is one of PageWatch.Attempt, `origin`
     * the page's origin as the engine gave it. The core validates both and
     * counts repeats; a report can add to this session's watch only.
     */
    oneway void reportAttempt(long generation, String kind, String origin);

    /** This session's page watch, encoded by PageWatch; empty for any other generation. */
    Bundle pageWatch(long generation);
}
