# Phase 5: the Linux app on Qt (design revision and PoCs)

**Status (21 Oct 2026): proposed, not reviewed; PoCs started.** On 20 Oct the Linux app moved from GTK4 + WebKitGTK to Qt, and was made the last step after Android (architecture §22). §9 of the [architecture](../architecture.md) still describes the reviewed GTK4 design. This document proposes its replacement and lists the questions that have to be answered by measurement before any app code is written. Nothing here is verified unless a PoC row below says so.

## What carries over unchanged

These do not depend on the toolkit:

- **Flatpak first.** One tested runtime, patched by its maintainers, rather than whatever web engine a distribution ships.
- **The shared Rust core** (`rift-core`, `rift-protocol`, `rift-update`, the vault format). Linux runs the same code as Android.
- **Worker lockdown (L2) and sealed-memfd output (L3).** Workers run `rift-worker` under seccomp and Landlock, spawned by the controller with a socketpair. Both PoCs pass natively and in Docker; L2 inside Flatpak is still open.
- **The network-lock idea (L4).** The browser runs in a Flatpak sub-sandbox with no network (`flatpak-spawn --sandbox --no-network`), and reaches the web only through the controller's checking proxy. On Linux this is stronger than on Android, because the sub-sandbox has no loopback shared with other apps.

## What changes

| | GTK4 design (v2.0) | Qt proposal |
|---|---|---|
| Web engine | WebKitGTK 6.0: web processes in bubblewrap with seccomp, network process unsandboxed | **Qt WebEngine 6.10** (Chromium). Renderers sandboxed by Chromium's seccomp-bpf sandbox, which in Flathub's BaseApp spawns them as sandboxed Flatpak instances. The network service runs in the browser process. |
| Runtime | GNOME runtime | **KDE runtime 6.10** with `io.qt.qtwebengine.BaseApp` 6.10 (Freedesktop SDK 25.08) |
| UI | gtk4-rs, libadwaita | **QML (Qt Quick)**, with the trusted logic in Rust through **cxx-qt** (QObjects implemented in Rust, in process; no C ABI layer) |
| Sandbox check (INV-7) | Inspect each WebKitWebProcess in `/proc` | To be designed from Q1. The renderers may run in sandbox instances the app cannot see. |
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
| Q1 | Is Qt WebEngine's renderer sandbox active in the Flathub BaseApp, and what can the app itself see of it? | From the host: every renderer has `Seccomp: 2`, `NoNewPrivs: 1`, and user, mount and network namespaces of its own. With `QTWEBENGINE_DISABLE_SANDBOX=1` the same probe reports them not confined (negative control). Recorded: which engine processes the app can see from inside its own sandbox. | Running in CI (`.github/workflows/linux-qt-poc.yml`) |
| Q2 | Does Qt WebEngine run in a `--no-network` sub-sandbox, with its renderers still sandboxed, and load pages through a forwarder to the controller's proxy? (L4 for Qt) | Pages load through the proxy. Direct connections and DNS from the sub-sandbox fail. The renderers stay confined as in Q1. | Not started; depends on Q1 |
| Q3 | Does a cxx-qt QML app linking `rift-core` build in the KDE SDK with the Rust extension? | It builds and calls into the core. Size and build time recorded. | Not started |
| Q4 | Does the worker lockdown hold inside Flatpak? (L2) | open, socket, execve, ptrace and kill denied inside a Flatpak; allowed work succeeds. | Not started (passes natively and in Docker) |

**Why Q1 decides the sandbox check.** With the BaseApp's Flatpak sandbox support, renderers are spawned through the Flatpak portal into sandbox instances of their own, each with its own pid namespace. From inside the app's sandbox, Rift's controller may not see them at all, so the WebKit approach (inspect each web process in `/proc`) may not carry over. If it does not, the options are, in order of preference:

1. a check that the browser host can make of its own children, if the portal reports them;
2. a fail-closed start condition: refuse when the sandbox switches (`QTWEBENGINE_DISABLE_SANDBOX`, `--no-sandbox`, `QTWEBENGINE_CHROMIUM_FLAGS`) are present, and when the portal's sandbox spawn is unavailable;
3. stating plainly that the check is weaker on Linux than on Android.

## Risks already known

- **Qt WebEngine lags Chrome.** Each Qt WebEngine release is based on an older Chromium, with security fixes backported. Rift needs a minimum Qt WebEngine patch release as a release parameter, as it has a minimum WebView version on Android, and the Flatpak must follow the BaseApp's updates.
- **The BaseApp is a community build.** `io.qt.qtwebengine.BaseApp` is maintained on Flathub, not by the Qt Company. Its sandbox support needs a session bus and the Flatpak portal; when sandboxing is impossible, a build may disable it with an environment variable, which Rift must detect and refuse.
- **cxx-qt is still pre-1.0.** Its API changes between releases. It is pinned, and the binding layer is kept thin.
- **No local Linux desktop.** The PoCs run in GitHub Actions on Ubuntu 24.04 under Xvfb, without a GPU. Fedora and a real desktop session are still needed before a release (as for L1 under GTK).

## Sources

- [Flathub `io.qt.qtwebengine.BaseApp`](https://github.com/flathub/io.qt.qtwebengine.BaseApp): branches 6.10 and 6.11 on the 25.08 runtime; "support for spawning sandboxed Flatpak instances is included, and will be used by QtWebEngine to sandbox Chromium's render processes".
- [Qt WebEngine platform notes (6.8)](https://doc.qt.io/qt-6.8/qtwebengine-platform-notes.html): `QTWEBENGINE_DISABLE_SANDBOX` and `--no-sandbox`.
- [KDAB cxx-qt](https://github.com/KDAB/cxx-qt): Rust ⇄ C++ bindings for Qt; QObjects in Rust usable from QML.
