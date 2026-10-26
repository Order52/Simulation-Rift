package org.simulationrift.bridge;

import org.simulationrift.bridge.IBrowser;

/**
 * The controller's interface for the browser app (§8.3). It offers
 * navigation decisions and session requests only: nothing here reaches
 * quarantined files or the threat database. The service requires the signature
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

    /**
     * The user chose to open `url`, which the core blocked as known
     * malicious, after the warning (§10.4). The core decides it again, and
     * only for a link it blocks as listed resets the session and opens it
     * in the new one: this window is closed.
     */
    oneway void inspectAnyway(long generation, String url);

    /** The renderer died: the session is torn down (INV-7). */
    oneway void rendererGone(long generation, boolean crashed);

    /**
     * The engine reported something a page tried that only it can see, and
     * that was refused (§10.5): `kind` is one of PageWatch.Attempt, `origin`
     * the page's origin as the engine gave it. The core validates both and
     * counts repeats; a report can add to this session's watch only.
     */
    oneway void reportAttempt(long generation, String kind, String origin);

    /**
     * A page was given a decoy instead of what it asked for (§10.5): `kind`
     * is one of PageWatch.Decoy, `origin` the page's origin as the engine
     * gave it, `detail` a short note (a notification's title, what a page
     * tried to put on the clipboard). The core validates and bounds all three.
     */
    oneway void reportDecoy(long generation, String kind, String origin, String detail);

    /** This session's page watch, encoded by PageWatch; empty for any other generation. */
    Bundle pageWatch(long generation);

    /**
     * What a loaded page asks for and calls itself (§10.5), read by a script
     * in it: `names` is its title, site name and first heading. The page can
     * change what the script reads, so the core only adds warnings from it,
     * and bounds every part. `counts` is what the page is made of, as JSON
     * (rift_core::pagemodel::PageCounts), for Rift AI's page model (§16.1).
     */
    oneway void reportPage(long generation, String url, String names, boolean password, boolean card, String counts);

    /** The test-open report for this session (§10.11), encoded by TestReport; empty for any other. */
    Bundle testOpenReport(long generation);

    /**
     * Whether the content filters (§10.9) are on and loaded now. Asked once
     * for each page, so the browser does not make a call for every request
     * while they are off.
     */
    boolean filtersOn(long generation);

    /**
     * Whether pages' dialog boxes (alert, confirm, prompt, "Leave this
     * page?") are dismissed unseen: on with "Skip sign-ins and pop-ups"
     * (§10.9). Asked with filtersOn, once for each page.
     */
    boolean quietDialogs(long generation);

    /**
     * Whether a subresource request is blocked by the content filters:
     * `page` is the address of the page that makes it, `kind` one of the
     * filter engine's request kinds. The core bounds and validates both.
     */
    boolean blockRequest(long generation, String url, String page, String kind);

    /**
     * What to hide on the page at `url`, encoded by PageHiding: style rules
     * the core made itself from the lists, and the exceptions to pass back
     * to [genericHiding].
     */
    Bundle hidingFor(long generation, String url);

    /** The style rules for the class names and ids a page uses; bounded like the rest. */
    String genericHiding(long generation, in List<String> classes, in List<String> ids, in List<String> exceptions);
}
