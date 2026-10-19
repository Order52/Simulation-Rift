# PoC A8: a browser with its own UID, wiped by the system, behind a network lock

Phase 0 follow-up (20 Oct 2026). The question: can Rift isolate the browser
from its own data and from the network more strongly than a separate process
in the same app (boundary B2, "weak" in architecture §4)?

Three small apps, built by `build.sh`:

| App | Package | Signer | Plays |
|---|---|---|---|
| controller | `org.simulationrift.poc.controller` | debug key | Rift's trusted controller: holds a canary file, defines a `signature` permission, exports `CoreService` under it, keeps `HiddenService` private, runs a loopback HTTP proxy that checks every destination, and a deny-all VPN for the browser UID |
| browser | `org.simulationrift.poc.browser` | the same debug key | the browser: `SessionService` in its default process (never loads WebView), `WebActivity` with WebView in `:web`, which first probes what code in that process can reach |
| outsider | `org.simulationrift.poc.outsider` | a throwaway key made by `build.sh` | another app on the device (T7) |

`run-poc.sh <out-dir>` runs on one attached emulator:

1. A page with no network boundary (baseline).
2. The browser wipes itself with `ActivityManager.clearApplicationUserData()`; the controller times the process death and the first answer of a fresh process, and lists what the fresh process finds on disk.
3. The page behind the proxy with Chromium's implicit bypass rules (loopback, link-local).
4. The page behind the proxy with those rules removed (`ProxyConfig.Builder.removeImplicitRules()`).
5. The same with proxy authentication (Basic, a token the browser answers in `onReceivedHttpAuthRequest`).
6. Ten page-then-wipe cycles, for timing and for state left between sessions.
7. A VPN (`VpnService`, `addAllowedApplication(browser)` only) whose tun the controller reads and drops; consent through `appops set … ACTIVATE_VPN allow`.
8. The outsider tries every door.

The page (`fixtures/page.html`) reports cookies and storage left from earlier
runs, fetches `10.0.2.2` (the emulator host, a private address) and
`127.0.0.1`, and gathers WebRTC candidates against a STUN server on
`10.0.2.2:3478`. The fixture server logs every request and every UDP datagram
that **arrives**, which is the ground truth: the page's own "FETCHED" only
means the `no-cors` fetch completed, which includes the proxy's 403.

Results: [`docs/reports/evidence/phase0-A8-browser-split-api30/`](../../docs/reports/evidence/phase0-A8-browser-split-api30/),
`…-api36/`, summarized in [`docs/reports/phase-0.md`](../../docs/reports/phase-0.md) §A8.
