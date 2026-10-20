# Phase 5: the Linux app on Qt (design revision and PoCs)

**Status (21 Oct 2026): proposed, not externally reviewed; PoCs Q1–Q4 pass.** On 20 Oct the Linux app moved from GTK4 + WebKitGTK to Qt, and was made the last step after Android (architecture §22). §9 of the [architecture](../architecture.md) still describes the reviewed GTK4 design. This document proposes its replacement and lists the questions that have to be answered by measurement before any app code is written. Nothing here is verified unless a PoC row below says so.

## What carries over unchanged

These do not depend on the toolkit:

- **Flatpak first.** One tested runtime, patched by its maintainers, rather than whatever web engine a distribution ships.
- **The shared Rust core** (`rift-core`, `rift-protocol`, `rift-update`, the vault format). Linux runs the same code as Android.
- **Worker lockdown (L2) and sealed-memfd output (L3).** Workers run `rift-worker` under seccomp and Landlock, spawned by the controller with a socketpair. Both PoCs pass natively, in Docker, and inside a Flatpak sandbox (Q4).
- **The network-lock idea (L4).** The browser runs in a Flatpak sub-sandbox with no network (`flatpak-spawn --sandbox --no-network`), and reaches the web only through the controller's checking proxy. On Linux this is stronger than on Android, because the sub-sandbox has no loopback shared with other apps.

## What changes

| | GTK4 design (v2.0) | Qt proposal |
|---|---|---|
| Web engine | WebKitGTK 6.0: web processes in bubblewrap with seccomp, network process unsandboxed | **Qt WebEngine 6.10** (Chromium). Renderers sandboxed by Chromium's seccomp-bpf sandbox, which in Flathub's BaseApp spawns them as sandboxed Flatpak instances. The network service runs in the browser process. |
| Runtime | GNOME runtime | **KDE runtime 6.10** with `io.qt.qtwebengine.BaseApp` 6.10 (Freedesktop SDK 25.08) |
| UI | gtk4-rs, libadwaita | **QML (Qt Quick)**, with the trusted logic in Rust through **cxx-qt** (QObjects implemented in Rust, in process; no C ABI layer) |
| Sandbox check (INV-7) | Inspect each WebKitWebProcess in `/proc` | Inspect each renderer in `/proc` (Q1: the app sees them): more seccomp filters than the app, and mount and pid namespaces of its own; refuse the sandbox switches at start |
| Permissions | WebKit `permission-request`: deny | `QWebEnginePage::permissionRequested`: deny all (location, camera, microphone, notifications, clipboard read, screen capture) |
| Downloads | Cancel the engine download; the core re-fetches | The same: `QWebEngineProfile::downloadRequested` is refused, and the URL goes to the core's checked transfer |
| Session data | Ephemeral `WebKitNetworkSession` | An off-the-record `QWebEngineProfile` (nothing written to disk), in a browser process that ends at every reset |

## Proposed process layout

```
┌─ Flatpak app (KDE 6.10 + QtWebEngine BaseApp) ──────────────────────────────┐
│ controller [TRUSTED]: QML UI · rift-core through cxx-qt · egress proxy       │
│      │ unix socket (exposed path)              │ socketpair + SCM_RIGHTS     │
│ ┌────▼─ browser host: flatpak-spawn --sandbox --no-network ──┐  ┌──────────▼─┐│
│ │ Qt WebEngine browser process (network service in process), │  │ rift-worker││
│ │ a forwarder from its own loopback to the unix socket       │  │ seccomp +  ││
│ │   │ portal: sandboxed instance per zygote                  │  │ Landlock   ││
│ │ ┌─▼─ renderers: Chromium seccomp-bpf ──┐                    │  └────────────┘│
│ └─┴───────────────────────────────────────┴───────────────────┘                │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Questions to answer first

| ID | Question | Pass criterion | State |
|---|---|---|---|
| Q1 | Is Qt WebEngine's renderer sandbox active in the Flathub BaseApp, and what can the app itself see of it? | From the host: every renderer has a seccomp filter of the engine's own on top of Flatpak's, `NoNewPrivs: 1`, and mount and pid namespaces of its own. With `QTWEBENGINE_DISABLE_SANDBOX=1` the same probe reports them not sandboxed (negative control). Recorded: what the app can see from inside its own sandbox. (Revised after the first run; see below.) | **Passes, with a weaker sandbox than planned** (CI, 20 Oct): see below |
| Q2 | Does Qt WebEngine run in a `--no-network` sub-sandbox, with its renderers still sandboxed, and load pages through a forwarder to the controller's proxy? (L4 for Qt) | Pages load through the proxy. Direct connections and DNS from the sub-sandbox fail. The renderers stay confined as in Q1. Added: a process the browser host spawns through the portal has no network either. | **Passes** (CI, 20 Oct): see below |
| Q3 | Does a cxx-qt QML app linking `rift-core` build in the KDE SDK with the Rust extension? | It builds and calls into the core. Size and build time recorded. | **Passes** (CI, 20 Oct): see below |
| Q4 | Does the worker lockdown hold inside Flatpak? (L2) | open, socket, execve, ptrace and kill denied inside a Flatpak; allowed work succeeds. | **Passes** (CI, 20 Oct): see below |

**Why Q1 decides the sandbox check.** With the BaseApp's Flatpak sandbox support, renderers are spawned through the Flatpak portal into sandbox instances of their own, each with its own pid namespace. From inside the app's sandbox, Rift's controller may not see them at all, so the WebKit approach (inspect each web process in `/proc`) may not carry over. If it does not, the options are, in order of preference:

1. a check that the browser host can make of its own children, if the portal reports them;
2. a fail-closed start condition: refuse when the sandbox switches (`QTWEBENGINE_DISABLE_SANDBOX`, `--no-sandbox`, `QTWEBENGINE_CHROMIUM_FLAGS`) are present, and when the portal's sandbox spawn is unavailable;
3. stating plainly that the check is weaker on Linux than on Android.

## App design (proposed after Q1–Q4)

The PoCs settle the questions this design depended on: all four pass (results below).

**Processes.**

| Process | Runs | Sandbox | Holds |
|---|---|---|---|
| controller `rift` | Rust `main`, QML UI through cxx-qt, the platform facade (`rift-ffi`'s Rust API, the same code the Android app calls through UniFFI) | the Flatpak app sandbox, with the network | the vault, intelligence, settings, the egress proxy, the worker supervisor |
| browser host `rift-browser`, one per session | Rust `main`, Qt WebEngine Widgets in C++ through cxx | `flatpak-spawn --sandbox --no-network`: its own network namespace with only loopback, no app data, display and GPU shared, a session bus for the portal | one off-the-record profile; nothing that outlives the session |
| renderers | Chromium | the engine's sandbox, spawned through the portal: seccomp-bpf on Flatpak's, mount, pid, IPC and network namespaces of their own (Q1, Q2) | one site's page |
| workers `rift-worker` | Rust | Landlock and seccomp, rlimits, no network (Q4) | one file |

**The session channel.** The controller makes a `SOCK_SEQPACKET` socketpair and gives one end to `flatpak-spawn` as stdin, which the portal hands to the browser host as its stdin. Taking it with a safe `dup` of fd 0 means neither side adopts a raw fd. Messages are postcard, one per datagram, in a new `rift_protocol::session` module:

- browser to controller: `Hello`; `Decide { id, url, main_frame, user_gesture, redirect }` (sent synchronously from `acceptNavigationRequest`); `Renderer { pid, report }`; `Download { url }`; `Connection` with one TCP socket attached (`SCM_RIGHTS`); `Closing`;
- controller to browser: `Answer { id, navigation }` (`Proceed`, `Confirm` with reasons, or `Block`, already escaped as on Android); `Load { url }`; `Close`.

**Network lock (L4).** The browser host's forwarder listens on 127.0.0.1 in its own network namespace. Qt's application proxy points there. Each accepted connection is sent to the controller as a `Connection` message, and the controller serves it with `rift_core::egress::ForwardedEgress`: the same checks as on Android, with no listener and no token, because the socketpair authenticates the browser host. Nothing else can reach the proxy: it has no address.

**Sandbox check (INV-7).** At start, the browser host refuses to run if `QTWEBENGINE_DISABLE_SANDBOX`, `QTWEBENGINE_CHROMIUM_FLAGS` or a `--no-sandbox`/`--single-process` argument is present. For each renderer pid it reads `/proc/<pid>/status` and `/proc/<pid>/ns/*` before the page is shown. The page stays hidden unless the renderer has more seccomp filters than the browser host, `NoNewPrivs: 1`, and mount and pid namespaces of its own (Q1). It reports each result to the controller, which ends the session on a failure. The rule lives in shared Rust (`rift_core::sandbox`), so the probe that tests it and the app run the same code.

**Engine settings.** Off the record. All permissions are denied (`QWebEnginePage::permissionRequested`). Downloads are cancelled, and their URL goes to the controller's checked transfer. Navigations are decided by the controller. The browser host's window draws Rift's own toolbar and interstitials from the controller's facts, as `:browser` does on Android: Rift's code, co-resident with the engine's browser process, and confined with it.

**Workers.** `rift-worker` as a Linux binary: the lockdown from the L2 PoC (Landlock, seccomp, rlimits), its socket on stdin, pixels in a sealed memfd (L3). The controller spawns it directly. It needs no portal, and the Flatpak sandbox is its outer layer (Q4).

**Build.** One Cargo workspace under `linux/`, separate from the product workspace because it needs Qt at build time. The Flatpak manifest builds it with the SDK's Rust extension (Q3), from vendored crates for a release.

**Order of work.**
1. Session: browser host, channel, forwarded proxy, navigation decisions, renderer check; a controller with a URL field, status and reset. Tested end to end in CI as Q2 was.
2. Intelligence: the built-in pack, import and online updates (`rift-update`), and page-watch denials shown in the controller.
3. Workers, file scanning and preview; the vault (passphrase first; a platform key from the Secret portal is a later option).

## Results

### Q1: the renderer sandbox in a Flatpak (passes; weaker than planned)

`linux-qt-poc` run 39507119054 (commit c88381e): Qt 6.10.3 from `io.qt.qtwebengine.BaseApp` 6.10 on `org.kde.Platform` 6.10, under Xvfb with a session bus. The probe app (`poc/linux-qt/probe`) opens a local page in an off-the-record profile, and `host-probe.py` reads every engine process from the host while the page is open. Evidence: [`evidence/phase-5/q1-renderer-sandbox.txt`](evidence/phase-5/q1-renderer-sandbox.txt).

| | As shipped | `QTWEBENGINE_DISABLE_SANDBOX=1` |
|---|---|---|
| Renderer's seccomp filters | **2** (Flatpak's, plus Chromium's) | 1 (Flatpak's only) |
| Renderer's namespaces, compared with the app | **mount, pid and IPC of its own**; user and network shared | all shared |
| Zygotes | one in the app's namespaces, one in the renderer's; 1 filter each | in the app's namespaces |
| Page loaded | yes | yes |
| Host probe verdict | 1 of 1 renderers sandboxed by the engine | 0 of 1 (as expected) |

**What this means.**

- **The engine's sandbox is active by default.** The renderer runs in a sandbox instance spawned through the Flatpak portal, with mount, pid and IPC namespaces of its own and Chromium's seccomp-bpf policy stacked on Flatpak's.
- **It is weaker than the pass criterion first written.** The renderer shares the app's user namespace and its **network namespace**. Chromium's renderer policy should block socket creation, but no namespace stops a renderer that escapes its seccomp policy from reaching the network. That is the case Q2's sub-sandbox exists for: inside it, the shared network namespace has none.
- **The escape hatch is visible.** With the variable set, the renderer has only Flatpak's filter and no namespaces of its own, so a check can tell the two apart.
- **The app can see the renderer from inside its own sandbox** (the portal exposes the pids), with the same fields the host sees: filter count 2 against its own 1, and mount, pid and IPC namespaces different from its own. So the INV-7 check can carry over in the form Android and the WebKit design use: inspect each renderer, and refuse to show pages unless it has more filters than the app and namespaces of its own. This is option 1 above, and better than expected.

**First run.** Run 39505969652 passed while measuring nothing (0 renderers in both cases). Chromium rewrites its argv as one space-joined title, so the host probe never found `--type=renderer`, and the in-app probe read `/proc` with `QFile::atEnd()`, which is true at once on `/proc` files. Both were fixed, the first criterion (user and network namespaces of its own) was replaced by the filter-count one after seeing that every Flatpak process already has `Seccomp: 2`, and the run now fails unless both cases give the expected verdict. Evidence: [`evidence/phase-5/q1-first-run.txt`](evidence/phase-5/q1-first-run.txt).

**Not shown.** Only one renderer and one page were measured, on GitHub's VM under Xvfb, without a GPU process. A real desktop session, Wayland, a GPU and other distributions are still to do.

### Q2: the network lock for Qt (passes)

`linux-qt-poc` run 39511905939 (commit 593a447). `poc/linux-qt/q2-netlock`: the app's main process (`controller.py`, standing in for Rift's controller) keeps the network. It starts the browser host with `flatpak-spawn --sandbox --no-network --sandbox-flag=share-display --sandbox-flag=share-gpu --sandbox-flag=allow-dbus` and one end of a socketpair. The browser host's forwarder listens on its own loopback and hands each accepted connection to the controller (`SCM_RIGHTS`). The controller answers it as an HTTP proxy that knows one name, `rift-probe.test`, mapped to a page server on the host's loopback. qt-probe uses the forwarder as Qt's application proxy. Evidence: [`evidence/phase-5/q2-network-lock.txt`](evidence/phase-5/q2-network-lock.txt).

| Inside the browser host's sub-sandbox | Result |
|---|---|
| Network interfaces (`/proc/net/dev`) | `lo` only |
| DNS (`dl.flathub.org`) | fails: no resolver reachable |
| TCP to a public address (1.1.1.1:443) | fails: network unreachable |
| TCP to the page server on the host's loopback | fails: refused (its own loopback) |
| A process it spawns through the portal, plain or `--sandbox`, connecting to either | fails the same way: the portal gives a no-network caller's children no network |
| `flatpak-spawn --host` | refused: the app may not talk to `org.freedesktop.Flatpak` |
| The page, through the forwarder and the controller | **loads** (X11 and offscreen), and the controller logged both requests |
| The same page without the proxy | does not load (negative control) |
| Renderers | 2 seccomp filters against the browser host's 1, `NoNewPrivs: 1`, and mount, pid, IPC and **network** namespaces of their own |

**What this means.** In the sub-sandbox, a compromised browser process (where Qt WebEngine's network service runs) or an escaped renderer can reach only what the controller's proxy lets through. It cannot reach the host's loopback services or the local network, and it cannot get a network back through the portal. On Android, loopback is still shared with other apps. Here the renderers also lose Q1's one gap, the shared network namespace.

**Runs before this one.** In run 1 nothing loaded: the probe had no display, and `/sys/class/net` showed the host's interfaces, not the sandbox's (it now reads `/proc/net/dev`). In run 2 the offscreen cases passed and X11 failed: the session bus had started before Xvfb, so the D-Bus-activated portal had no `DISPLAY` and gave the sub-sandbox no X socket. On a desktop the bus knows the display. Evidence: [`evidence/phase-5/q2-run2.txt`](evidence/phase-5/q2-run2.txt).

**Not shown.** The proxy here is a stand-in, not rift-core's (the app will use `ForwardedEgress`, which has unit tests of its own). Wayland, a GPU and a desktop distribution are not covered. `allow-dbus` gives the browser host the app's filtered session bus, so it can call the same portals as the app. Which portals the app may use is therefore part of the browser host's attack surface, and must be kept to what Rift needs.

### Q3: a cxx-qt QML app over rift-core (passes)

`linux-qt-poc` run 39510673541 (commit 8e0bb7f). `poc/linux-qt/q3-cxx-qt` is a Cargo-only cxx-qt 0.10 app: a `RiftCore` QObject implemented in Rust, whose `canonicalize` QML calls in process. It was built as a Flatpak on `org.kde.Sdk` 6.10 with `org.freedesktop.Sdk.Extension.rust-stable` (25.08) and run offscreen. Its three answers match rift-core's on the host. Evidence: [`evidence/phase-5/q3-cxx-qt.txt`](evidence/phase-5/q3-cxx-qt.txt).

- **Compiler.** The SDK extension has rustc 1.98.1. The workspace declared 1.99, the pinned development toolchain, so the first run stopped before compiling. rift-core and its dependencies build with 1.98.1. The workspace now declares `rust-version = "1.98"`, and the `msrv` CI job checks it, so the Linux release can build with the SDK's compiler.
- **Cost.** `cargo build --release` took 6 min 4 s on GitHub's runner (the whole Flatpak build, with SDK downloads, 444 s). The stripped binary is 1.5 MB. It links `libQt6Qml`, `Gui`, `Core`, `Network` and `DBus` from the runtime.
- **Not shown.** A real window, and anything beyond a QString round trip through the bridge. The build fetched crates from the network; a Flathub build must vendor them.

### Q4: worker lockdown inside a Flatpak sandbox (passes)

`linux-qt-poc` run 39506105945 (commit e26c627) on Ubuntu 24.04 (kernel 6.17, Flatpak 1.14.6). The L2 PoC (`poc/linux-worker-lockdown`) ran inside `flatpak run --command=… org.freedesktop.Platform//25.08`: the same bubblewrap and seccomp setup as an app on the KDE 6.10 runtime, which is built on it. Evidence: [`evidence/phase-5/q4-worker-lockdown.txt`](evidence/phase-5/q4-worker-lockdown.txt).

- **fd-only** (Landlock fully enforced, seccomp on): opening the canary, `/etc/passwd` and `/`, creating a file, inet and unix sockets, spawning a process, ptrace and signals to the parent, executable memory and a 1 GiB allocation were all denied. Reading the input fd, a YARA-X scan and sealed-memfd output worked.
- **ro-dir**: the same, plus a read of the one allowed directory.
- **strict**: a forbidden `socket()` kills the worker with SIGSYS.
- **none** (negative control): everything is allowed, except ptrace of the parent, which Flatpak's own seccomp filter already denies. That row is inconclusive about Rift's filter, and fd-only denies it in any case.

What this does not show: the PoC ran in the Freedesktop runtime directly, not in Rift's app with the QtWebEngine BaseApp, and in GitHub's VM rather than on a desktop distribution.

## Risks already known

- **Qt WebEngine lags Chrome.** Each Qt WebEngine release is based on an older Chromium, with security fixes backported. Rift needs a minimum Qt WebEngine patch release as a release parameter, as it has a minimum WebView version on Android, and the Flatpak must follow the BaseApp's updates.
- **The BaseApp is a community build.** `io.qt.qtwebengine.BaseApp` is maintained on Flathub, not by the Qt Company. Its sandbox support needs a session bus and the Flatpak portal; when sandboxing is impossible, a build may disable it with an environment variable, which Rift must detect and refuse.
- **cxx-qt is still pre-1.0.** Its API changes between releases. It is pinned, and the binding layer is kept thin.
- **No local Linux desktop.** The PoCs run in GitHub Actions on Ubuntu 24.04 under Xvfb, without a GPU. Fedora and a real desktop session are still needed before a release (as for L1 under GTK).

## Sources

- [Flathub `io.qt.qtwebengine.BaseApp`](https://github.com/flathub/io.qt.qtwebengine.BaseApp): branches 6.10 and 6.11 on the 25.08 runtime; "support for spawning sandboxed Flatpak instances is included, and will be used by QtWebEngine to sandbox Chromium's render processes".
- [Qt WebEngine platform notes (6.8)](https://doc.qt.io/qt-6.8/qtwebengine-platform-notes.html): `QTWEBENGINE_DISABLE_SANDBOX` and `--no-sandbox`.
- [KDAB cxx-qt](https://github.com/KDAB/cxx-qt): Rust ⇄ C++ bindings for Qt; QObjects in Rust usable from QML.
