# Report: the Android browser in its own app behind a network lock (architecture 2.1)

**Status (20 Oct 2026):** built and tested on Android emulators. The browser now runs as a separate app, `org.simulationrift.browser`, under its own UID, and the system wipes it at every reset. Its only route to the network is the controller's authenticated egress proxy (`rift-core::egress`), enforced by a VPN that applies to the browser app alone and forwards nothing. This replaces v2.0's `:browser` process, which ran under the controller's UID. The design and the measurements behind it are PoC A8 ([phase 0](phase-0.md), findings 13–16) and architecture §8.2–§8.4, §8.8 and §15. "Verified" means tested on the emulators named below. Nothing here claims perfect isolation: the residual risks are listed at the end.

## What was built

| Part | What it does | Where |
|---|---|---|
| `:bridge` library | What both apps share: the Binder interfaces (`ICore`, `IBrowser`, `ISession`), the decision and session-grant codecs (anything malformed decodes as a block or a refusal), the package identities, and `Rift.requireCaller`, which checks the caller's UID **and** signer on every call. Its manifest makes both apps define the `signature` permission `org.simulationrift.permission.RIFT`. No WebView, no Rust. | `android/bridge` |
| Browser app | `BrowserActivity` in `:web`, `SessionService` in the default process (pid, inventory, system wipe; never loads WebView). Permissions: `INTERNET`, `ACCESS_NETWORK_STATE`, Rift's permission. No launcher entry; both components require Rift's permission. The `androidx.startup` initializers are removed, so a fresh instance writes no file. | `android/browser` |
| Browser start-up | Register with the core and receive the session grant (proxy port, token, realm, lock mode) or a refusal; set the data-directory suffix; check the renderer sandbox; apply `ProxyController.setProxyOverride(127.0.0.1:<port>)` with `removeImplicitRules()` **before any WebView exists**; check that the default network is a VPN; report to the core; then create the WebView. The proxy's 407 challenge is answered only for host `127.0.0.1` and the session's realm; every other credential request is cancelled. A default-network callback ends the process the moment the network is no longer a VPN. | `BrowserActivity.kt`, `NetworkLock.kt` |
| Controller: network lock | `NetworkLockService` (`VpnService`): routes `0.0.0.0/0` and `::/0`, DNS inside the tun's range, `addAllowedApplication(org.simulationrift.browser)` only. It reads and drops every packet (poll with a deadline, so a closed tun ends the loop) and publishes counts and the first 32 destinations at most once a second. `onRevoke` ends the session. After a revocation Rift never takes the VPN back without the user. | `NetworkLockService.kt` |
| Controller: core | `CoreService` exported under Rift's permission, every call checked for the browser's UID and signer. `register` starts the session's proxy and returns the grant, or refuses when the lock is off and the user did not choose reduced isolation. `decide` blocks every navigation unless the browser reported the proxy in place and (in locked mode) its default network is the lock and the lock is still up. | `Core.kt`, `CoreService.kt` |
| Controller: reset | `AndroidBrowserDisposal` asks the browser to finish, has its `SessionService` call `clearApplicationUserData()`, waits for the binding to die and for `ACTION_PACKAGE_DATA_CLEARED`, then binds a fresh instance and requires a new pid and an inventory with no file at all. Then it checks the controller's own inventory against the allowlist. The browser is also wiped before the first session of every launch. | `AndroidBrowserDisposal.kt` |
| Controller: UI | A network card: the lock's state, the consent button, the explicit "reduced isolation for this session" choice when the lock cannot run, what the lock dropped, and the proxy's counts and recent refusals. The browser's trusted bar labels a reduced session for its whole life. | `MainActivity.kt`, `BrowserActivity.kt` |
| No WebView in the controller | The controller no longer depends on `androidx.webkit`. `build.sh` refuses a build in which any controller or bridge source names `android.webkit`, the APK contains `androidx.webkit`, or a Rift class in it references `android.webkit` (checked with `dexdump`). | `android/build.sh` |
| Test apps and probes | The **outsider** app, signed with a throwaway key that `build.sh` generates under `android/build/` (S24, S28). A debug-only **escape probe** that runs, in the browser's `:web` process, what code there could try after an engine escape (S23, S26). The fixture server records every `/hit/…` request and every UDP datagram on 3478. | `android/outsider`, `android/browser/src/debug`, `android/fixtures` |

## Results

All on the API 36 arm64 emulator (Android 16, WebView 133.0.6943.137), full suite in one run: 31 instrumented tests and the host-driven S13 and S14 passed ([evidence](evidence/phase3-android-split-api36/)). Quoted values are from that run.

| ID | Test | Result |
|---|---|---|
| S23 | Code in the browser's `:web` process (the escape probe) reads Rift's files, binds a private service, calls the core with a stale generation | **Pass.** The process ran as `org.simulationrift.browser:web` with its own UID. `files/rift`, `session.marker`, `shared_prefs` and the device-protected directory: `ENOENT`. `PreviewService`: "Not allowed to bind to service". Stale generation: `register` refused, `decide` blocked (`stale-session`). |
| S24 | Another app (different signer) binds the browser or the core, starts the browser, uses the proxy | **Pass.** Rift's permission was not granted to it. Both binds and the activity start: `SecurityException` ("requires org.simulationrift.permission.RIFT"). The proxy answered `HTTP/1.1 407 Proxy Authentication Required` without a token and with a wrong one, and counted both. |
| S25 | A page fetches loopback and private addresses | **Pass.** The fixture server received only the control request (`/hit/control` through the allowed name `localhost`). `127.0.0.1`, `10.0.2.2` (the emulator's host), `[::1]` and a WebSocket to `127.0.0.1` never arrived; the proxy listed each refusal. |
| S26 | A page uses WebRTC; browser-process code opens sockets and resolves names directly | **Pass.** WebRTC's only candidates were the lock's own addresses (`10.111.0.1`, `fd00:7269:6674::1`), none of the device's eight. No UDP datagram reached the STUN fixture. Direct TCP to the host and to `1.1.1.1:443` timed out; DNS failed ("Unable to resolve host"). The lock dropped 50 packets to 7 destinations. **Loopback connected** (reported, not asserted: §8.3). |
| S27 | Reset after a page set cookies and storage | **Pass.** The browser held 72 files before the reset and none after it, in a new process (pid 19395 → 21104). Reset 0.9 s. |
| S28 | The lock is lost mid-session (another app's VPN starts) | **Pass.** Rift's VPN was revoked, the session ended, the browser was wiped, and the next session started. Rift did not take the VPN back on its own. A browser started without the lock refused to load pages ("The network lock is off…"). |
| S28b | Reduced isolation | **Pass.** Chosen for one session, the browser labelled it; the next session was locked again. |
| S12 | Reset destroys every session store | **Pass**, now through the system wipe (reset 1.7 s in this run, 0.7–1.2 s in others). |
| S13 | Kill the controller while RESETTING | **Pass.** After the restart, recovery wiped the browser (pid 10706 → 10910 in one run, no files) before the next session, and a root listing of the browser's directories from outside the app found no file. |
| S1–S10, S14–S16, S19, S21, N1–N4, P1, P2 | The Phase 2 and 3 suite, rerun on the new design | **Pass.** Page loads, downloads, previews and scans all go through the proxy now. |
| — | Unit test of the sandbox check (`WebViewSandboxTest`) | **Pass** (JVM, run by `build.sh`). |
| — | No WebView in the controller | **Pass.** The source and `dexdump` checks find no Rift class touching `android.webkit` and no `androidx.webkit`; the same check flags the browser APK, as a control. |

## Findings

1. **A `ResultReceiver` subclass cannot cross into another app.** The test's anonymous receiver failed to unparcel in the browser (`ClassNotFoundException`). The test re-parcels it as a plain `ResultReceiver`, which carries only the binder.
2. **A VPN app must call `VpnService.prepare()` itself**, even with consent pre-granted. The outsider's first version skipped it, never established its VPN, and so never revoked Rift's. S28 now does what any VPN app does.
3. **Publishing a state update per dropped packet overloaded the emulator.** The first full run left the controller's render thread at about 76% CPU while the composer and allocator services were busy, until system services stopped answering. The drain thread now counts locally and publishes once a second at most. It also leaves the loop when `poll` reports an error on the tun, rather than spinning.
4. **What the lock actually drops.** In S26 the lock dropped TCP to the emulator host (10.0.2.2:8766) and to a public address (1.1.1.1:443), UDP to the STUN fixture (10.0.2.2:3478), DNS to the lock's own resolver address (UDP 10.111.0.2:53), DNS-over-TLS probes (TCP 10.111.0.2:853), and IPv6 multicast (MLD, router solicitation). None of it reached the host.
5. **androidx.core adds a permission of its own** (`<package>.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION`, signature-level, for unexported receivers). S2 accepts exactly that one besides the declared three.
6. **Tests that open fixture pages must allow `localhost` first.** The proxy refuses local names in a fresh session, as INV-13 requires, so several v2.0 tests had to say so explicitly. The refusal is now part of S9: the proxy refuses the page, and the core separately refuses the transfer.

## Verified

- On the API 36 arm64 emulator: everything marked Pass above.
- The browser app cannot read the controller's files or bind its private services (S23), and other apps cannot use either app or the proxy (S24).
- With the lock on, pages reached only public destinations and allowed host names (S25), and neither WebRTC nor direct sockets from the browser's process reached a host or public address (S26).
- Android's own wipe left the browser app with no file at all after every reset and recovery in these runs (S12, S13, S27).
- The controller APK contains no WebView code (build check, with a control).

## Unverified

- **Physical phones.** Emulators only, as for Phases 2 and 3.
- **API 30 with the new apps.** The browser refuses to browse on API 30's WebView 91 (below the minimum), so the network path cannot run there; the lock and the wipe were measured there in PoC A8 only.
- **Every WebView version answers the proxy challenge the same way.** Measured on WebView 91 (A8) and 133.
- **Android's always-on VPN setting and per-profile (work profile) users.** Not tested: with another always-on VPN the lock should be unavailable and the UI should say so.
- **The controller dying mid-session.** The browser is designed to exit when its core binding dies, and the next launch wipes it; this ordering is tested only through S13 (a kill during reset).

## Could be improved

- Loopback stays reachable from escaped browser code (S26: `tcp.loopback` connected). No Android mechanism closes loopback for one app; the Linux design (§9.2) closes it with a network namespace.
- The browser answers no site's HTTP authentication. A per-site prompt in the trusted UI could allow it without ever offering the proxy token.
- The reset now takes about 0.7–1.2 s (the system wipe and a fresh instance), against 0.3–0.5 s before. Pre-starting the next browser instance during the wipe would hide most of it.
- The escape probe and outsider results come back over a `ResultReceiver` from an activity. A bound service would avoid the activity start and its window transition.
