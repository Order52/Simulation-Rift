# Simulation-Rift: current status

**As of 21 Oct 2026** (`main` at the commit that last changed this file). Simulation-Rift is in development: Phases 3 and 4 of the roadmap are built and tested on emulators (Phases 0–7, [architecture §22](docs/architecture.md)). It is **not** a usable or audited security product. Every claim below means "tested in the stated environment", nothing more. The full history, all findings and the per-phase evidence are in [`docs/reports/project-status.md`](docs/reports/project-status.md) and the reports next to it.

## In one paragraph

The Android debug build works end to end on emulators, and its browser is now isolated by the operating system rather than by "deleting cookies". The browser is a **separate app with its own Linux user ID**, so code that escapes the web engine cannot see Rift's files, keys or quarantine. A **network lock** gives it no route to any network except Rift's own checking proxy: a VPN that applies only to the browser and drops every packet, plus a loopback proxy that needs a per-session token and refuses local and private addresses. At every reset **Android itself wipes the browser app** (all its processes are killed and all its data deleted), and Rift checks that a fresh instance holds no file at all. While a page is open, the browser's bar shows a **live status of the session**: whether a page has loaded from an address the threat database lists, asked for your location, camera, microphone or files, probed your local network or tried to connect around the proxy (WebRTC), and what each download's scan found. It says "Danger", "Warning" or "Nothing suspicious seen so far", never "safe", and comes only from Rift's own enforcement points, not from anything the page says. Downloads are re-fetched into encrypted per-session quarantine, previewed and scanned in isolated worker processes. Files you choose to keep go into an **encrypted vault** whose key is held by Android's keystore behind your screen lock or fingerprint (or by a passphrase), and which locks when Rift leaves the screen. The only threat database is a harmless demo one. Nothing has run on a physical phone. Hardening has started on Android. **The Linux app (Qt, Flatpak) is now built** and passes an end-to-end test in CI: each session's browser runs in a Flatpak sub-sandbox with **no network at all** except Rift's proxy (not even the host's loopback), its renderers are sandboxed by the engine and checked before a page is shown, and files are scanned in workers that confine themselves with Landlock and seccomp. Its vault, previews and local-host exception have not been tried in a real window, and it has not run on a desktop distribution.

## Phases

| Phase | State |
|---|---|
| 0: Feasibility (14 proofs of concept) | **Mostly done.** All pass in at least one environment, including A8 (the browser split and the network lock). Open: the lookup benchmark on a phone, the Linux checks inside Flatpak, and L4 (the Linux network lock). |
| 1: Foundations (Rust core, protocol, formats) | **Done.** Unit, property and fuzz tests, strict lints, dependency policy. |
| 2: Android vertical slice | **Done on emulators** (API 33–36, both ABIs, 16 KB pages), now on architecture 2.1 (browser app and network lock, [report](docs/reports/browser-isolation.md)). Gate still open: a physical phone. |
| 3: Scanner and signed intelligence | **Done on emulators**, except real feeds and the signing-key ceremony. The release key policy is built and tested on the host: one key per holder, a 2-of-3 root, offline targets keys, and root rotation; a device starts each update from the newest root it has verified, so a rotation cannot be undone with the retired keys (finding 64, fixed; [policy](docs/reports/key-policy.md)). Scanning (two isolated workers at a time); signed updates imported from a folder you choose or fetched online through the core's own checked fetcher; refusals in one sentence; a warning when the clock is behind the database. |
| 4: Vault | **Done on the API 35 emulator** ([report](docs/reports/phase-4.md)). Keystore key behind BiometricPrompt, or a passphrase; keep, export (warned), remove; locks on request, in the background and after an idle limit you choose (1–30 minutes, 5 by default). Kept files can be previewed in an isolated worker until the vault locks; an optional recovery passphrase opens a vault whose key was lost. Open: a physical phone (the emulator's keystore is software only). |
| 6: AI experiment | Not started; optional and gated by design. |
| 7: Hardening and release | **Started on Android** ([report](docs/reports/phase-7.md)). Privacy checks: local work, updates and an idle session move no byte on any real network for either of Rift's apps, and nothing is scheduled (x1); browsing leaves only through the controller's proxy (x2). The dependency and licence inventory is written ([dependencies.md](docs/reports/dependencies.md)); it led to one crypto library (aws-lc-rs) instead of two. NAT64 addresses are now judged by the IPv4 address they carry, so IPv6-only networks work. Both apps carry generated third-party notices, shown under "Open-source licences" (l1). Android libraries are locked and scanned for advisories on every push (OSV). Killing the controller while it keeps files into the vault or installs the database leaves both whole (F1–F4, 8 of 8 kills each). On a full disk keeps, downloads and installs fail with a message, a reset fails closed, Retry recovers once there is space, and the vault and database stay whole (F5/F6); this found a misleading install message, now fixed. Cutting the emulator's power while it keeps files or installs the database loses no keep or install that had reported success (P1–P4, 4 of 4 cuts each). Trusted text now escapes every Unicode format character, not a hand-made list that missed some (finding 63). The first long fuzz campaign (an hour per target) led to a proxy fix: an address padded past what can be checked against the threat database is now refused instead of being checked by its host alone (finding 65). The live page watch is built (w1); building it found that addresses had never been checked against the installed threat database, which they now are, along with every request through the proxy. Open: fault rounds on a phone's real storage, the rest of the fuzz campaign's record, an external review. |
| 5: Linux app | **Built; end to end in CI** ([report](docs/reports/phase-5-qt-design.md#the-app-built-21-oct-2026)). Qt (QML through cxx-qt) and Qt WebEngine in Flatpak, on the shared core. The browser host runs in a no-network sub-sandbox and reaches the web only through the controller's proxy, which also gets loopback; renderers are checked before any page is shown; downloads go to quarantine and are scanned by workers confined with Landlock, seccomp and rlimits; a signed demo database is verified and compiled by a worker at start; crashes and a killed controller leave no session behind. Also built, but not tried in a real window: the passphrase vault, previews and the local-host exception. Open: a desktop distribution with Wayland and a GPU, online database updates, an external review. |

## How the browser is isolated (Android)

| Boundary | What enforces it | Tested by |
|---|---|---|
| Browser cannot read Rift's data | A separate APK, so a separate Linux UID; Rift's directories return `ENOENT` from the browser's process | S23 |
| Browser cannot use Rift's private services | Not exported; the one exported interface needs a `signature` permission and checks the caller's UID and signer on every call; it offers navigation decisions and session requests only | S23, S24 |
| Other apps cannot drive the browser or the core | The same permission and checks; the proxy answers 407 without the session token | S24 |
| Pages cannot reach your LAN, router or local services | Every engine request goes to Rift's proxy (Chromium's implicit loopback bypass removed), which refuses loopback, private and link-local addresses unless you allow a host name for the session | S9, S25 |
| WebRTC and escaped code have no network route | A VPN for the browser app only that forwards nothing: TCP, UDP and DNS are dropped; WebRTC sees only the VPN's own address | S26 |
| Nothing survives a reset | Android's own wipe of the browser app; a fresh instance must report zero files and a new process id; checked again from outside with root in S13 | S12, S13, S27 |
| Losing the lock ends the session | If another VPN starts, the session ends and the browser is wiped; Rift never takes the VPN back without you | S28 |
| No silent downgrade | Without the lock the browser refuses to load pages; "reduced isolation" is an explicit per-session choice, labelled for the whole session | S28, S28b |
| Listed hosts are not reached, even by a page's parts | The proxy checks every connection's destination against the threat database before resolving it (HTTPS by host only); an address too long to check is refused | w1, Rust tests |
| Page content stays out of shared system state | No recents screenshot of the browser window (API 33+); every text field, in pages and in Rift, asks the keyboard not to learn | h2; H1 (the stored snapshot is a blank fill, decoded with root) |

**What it does not do:** escaped browser code can still reach **loopback** (other apps' local servers on the phone), which no Android VPN covers; only one VPN can run on a device, so users of another VPN get reduced isolation or nothing; the proxy does not see inside HTTPS; and a WebView exploit still has the current session's own browsing data. These are listed in [architecture §24](docs/architecture.md).

## What works today (Android debug build)

| Feature | What it does | Tests |
|---|---|---|
| Disposable, isolated browser | System WebView in the separate browser app, behind the network lock; no native bridges or device permissions; refuses to browse if the engine sandbox or the lock cannot be confirmed, or WebView is too old. | S1, S2, S15, S23–S28, N1–N4 |
| Navigation policy | Blocks addresses the threat database lists and automatic external-app links, asks before lookalike addresses, marks unencrypted pages, explains every decision. | N1–N4, w1 |
| Live page watch | The bar shows the session's status and a list of what its pages tried (location, camera, microphone, files, local network, connections around the proxy, listed addresses and hosts, downloads and their verdicts), with what is not watched; the home screen shows it too. Only a reset clears it. | w1 |
| Download capture | Downloads are re-fetched by the Rust core (destination checks on every redirect, size limit, cookies only to their origin) into encrypted quarantine. Hostile names are display-only. | S8–S10 |
| Previews | Images and PDFs render in an isolated worker (no files, no network, seccomp on the parser thread, deadlines, unbound after each job). Text is shown as escaped plain text. | P1, P2, S3–S7, S19 |
| Scanning | Each download is checked by file hash and type in the core, then by YARA-X rules in a fresh isolated worker, two at a time, so a hung worker does not hold the queue. A scan keeps the database snapshot it started with. The best status is "Not flagged", never "safe". | S16a, S21a, S21b |
| Signed threat database | TUF updates from a folder you choose (system picker) or online through the core's checked fetcher. Tampered, rolled-back, expired or wrongly signed updates are refused with a one-sentence reason (the full error goes to the log) and the old database stays. Debug builds embed a signed demo database. | S16, S17, S21, S22 |
| Vault | "Keep in the vault" copies a quarantined file, sealed with age to an identity wrapped by an Android Keystore key (per-use authentication through the system prompt, device must be unlocked) or a passphrase. Nothing readable is written to disk. Locks on request, when Rift goes to the background, and after 5 minutes. Export only after a warning, to a place you choose. A kept file can be scanned again with the current database, in a fresh isolated worker. The background lock can be turned off and the idle limit set (1–30 minutes, never off). | S18, v1–v7 |
| Reset and recovery | Reset stops the proxy, crypto-shreds quarantine, has Android wipe the browser app and verifies the result. A kill in the middle of a reset is recovered on the next start; the browser is also wiped at every launch. | S12, S13, S14, S27 |

## Where it has been tested

| Environment | Result |
|---|---|
| Host: macOS arm64, and CI on Ubuntu and macOS | 178 Rust tests in the product workspace, `clippy -D warnings`, `fmt`, `cargo deny`, 12 fuzz targets (60 s each on every push) and the Linux worker lockdown pass. |
| Android API 36, arm64 (local emulator, WebView 133) | **Full suite on architecture 2.1 (before the Phase 3 import and online tests and the vault): 31 instrumented tests plus S13/S14 pass** ([evidence](docs/reports/evidence/phase3-android-split-api36/)). |
| Android API 35, 16 KB pages, arm64 (local emulator, WebView 124) | **Latest full run (Phase 7, with the full-disk rounds): 46 instrumented tests pass (the 8 host-run steps are skipped there and run from the host), and S13, S14, S16d, S16f, H1, 8 of 8 kills each in F2 and F4, and the full disk (F6)** ([evidence](docs/reports/evidence/phase7-full-disk-api35-16k/)). Before it, on `b3beb0c`: the same without F6 ([evidence](docs/reports/evidence/phase7-recents-api35-16k/)). Before it, on `e3f7fee` with the live page watch: 44 tests and the same host steps without H1 ([evidence](docs/reports/evidence/phase7-watch-api35-16k/)). On `f2f4311`: 43 tests and the same host steps ([evidence](docs/reports/evidence/phase7-faults-api35-16k/)). Earlier, the full suite with the vault: 38 instrumented tests pass, and S16f, S13 and S14. S16d failed in that run because the on-screen keyboard blocked the script's scrolling; after the script fix the host steps all pass** ([evidence](docs/reports/evidence/phase4-vault-api35-16k/)). |
| Android API 33 and 34, x86_64 (CI emulators, WebView 109 and 113) | **Full suite on architecture 2.1 passes** (CI run 39363201440, before the import, online and vault tests; [33](docs/reports/evidence/phase3-android-split-api33-x86_64/), [34](docs/reports/evidence/phase3-android-split-api34-x86_64/)), after the fixes for the first 2.1 run ([report](docs/reports/browser-isolation.md), findings 7–8). |
| Android API 30 | Browsing is refused as designed (WebView 91 is below the minimum); the browser split and the lock were measured there in PoC A8. |
| Physical Android phone | **Not tested.** |
| Linux desktop app (Flatpak, KDE 6.10 runtime, Qt WebEngine 6.10.2, Ubuntu 24.04 in GitHub's VM under Xvfb) | **End-to-end test passes** (`linux-app` workflow): page through the proxy, loopback refused, renderer and sub-sandbox checked from the host as root, demo database installed by a confined worker, browser crash and controller kill recovered, sandbox switches do not reach the browser ([evidence](docs/reports/evidence/phase-5/)). Its Rust tests (controller, browser host, worker) also run in the Flatpak SDK and in Docker. No desktop distribution, Wayland or GPU yet. |

## What is left

In order of priority:

Android first; Linux is the last step.

1. **Phase 3 leftovers:** ~~import screen~~, ~~online updates~~ and ~~clock warning~~ are done; open are the production key policy (offline keys, thresholds, rotation) and licensed real feeds.
2. ~~**Phase 4 leftovers:** key providers, lock/unlock, keep and warned export, plaintext inventory, previews of kept files, a recovery passphrase, the verdict a file had when kept, rescanning kept files, lock settings~~: all done on Android (v1–v7). A physical phone is still untested.
3. **Phase 7, hardening (Android):** ~~privacy checks~~ (x1, x2) are done; ~~a dependency and licence inventory with owners~~, ~~the in-app licence notices~~ and ~~an Android advisory check~~ and ~~kill-fault rounds~~, ~~a full disk~~ and ~~power cuts~~ (emulator) are done; open are long fuzz campaigns, the fault rounds on a phone, the rest of the release gates (§24; [their state](docs/reports/phase-7.md#release-gates-24)), and an external security review before any release claim.
4. **Phones:** physical devices (every emulator level has passed on 2.1), which also settle the keystore's hardware backing and the lookup benchmark.
5. **Phase 6 (optional):** the AI experiment, only if it adds measured value.
6. **Phase 5, Linux (Qt):** ~~revise §9 for Qt, PoCs Q1–Q4, build the app~~: done and tested end to end in CI. Open: the vault, previews and local-host exception in a real window, a desktop distribution with Wayland and a GPU, online database updates, PDF previews, and a platform key for the vault (the Secret portal).

## Main limitations

| Limitation | Workaround or way forward |
|---|---|
| No real threat coverage: only the demo database exists. | Real feeds need a licensing review; the demo label is shown on every verdict. |
| Emulators only; no physical phone. | Connect a phone with USB debugging and run `android/run-tests.sh <dir>` (S13/S14 need `adb root`). |
| Escaped browser code can reach loopback services on the device. | No Android mechanism closes loopback for one app; on Linux the browser's network namespace has only its own loopback (measured in CI). |
| One VPN per device: the lock cannot run next to another VPN. | Reduced isolation for one session, chosen and labelled; never automatic. |
| If the controller is killed mid-session, the lock goes with it until the next launch wipes the browser. | The browser exits when the core dies; Android's always-on VPN with "block connections without VPN" would close the gap (a device setting). |
| The live page watch cannot see what scripts do inside a page (fingerprinting, keystrokes, mining) or what a page writes to the clipboard; for HTTPS only hosts are checked against the database. | Stated in the watch itself; the network lock and the wipe at reset do not depend on the watch. |
| Sites that use HTTP authentication cannot be signed in to. | Only the proxy's own challenge is answered, so the token never reaches a site. |
| `blob:`, `data:` and POST downloads cannot be captured. | Stated as unsupported. |
| The Android worker is weaker than the Linux one (Android allows exec memory and `AF_UNIX`). | A seccomp filter on the parser thread; defence in depth, not a boundary. |
| The native code budget is tight: 19.2 MB (arm64) and 24.5 MB (x86_64) per ABI, against 25 MB. | The core's TLS and the update checks share one crypto library; measure every native addition. |
| Update expiry trusts the device clock; demo signing keys are one per role on one machine. | The clock is checked against the database's creation time (a fast clock cannot be detected offline); the production key policy is on the list. |
| The vault key's hardware backing is unverified (the emulator's keystore is software only). | The vault card shows the key's security level; a phone test settles it. |
| Removing the screen lock (or enrolling new biometrics) deletes the vault's key. | Set the optional recovery passphrase: it opens the vault, and a new key then protects it again. Without one, the vault is lost, as the app says when it is created. |
| Wasmtime advisories, pulled in through YARA-X. | Scoped exceptions in `cargo deny`, removed once YARA-X depends on Wasmtime ≥ 48.0.6. |
| Dev machine: Docker builds the Linux workspace only one job at a time (`-j 1`, out of memory otherwise) and cannot run Flatpak; Apple silicon cannot run x86_64 emulators. | CI runs the Flatpak and the emulators. |

## Build and test

| What | Command |
|---|---|
| Rust tests and lints | `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo deny check` |
| Android apps (debug): controller, browser, outsider test app | `sh android/build.sh` (demo signing keys go to `~/.local/share/simulation-rift/demo-keys`, the outsider's throwaway key to `android/build/`, both outside version control) |
| Android suite on one attached emulator | `sh android/run-tests.sh <evidence-dir>` (installs all three apps and grants the VPN consent a user would give) |
| Install only | `adb install -r android/app/build/outputs/apk/debug/app-debug.apk` and `adb install -r android/browser/build/outputs/apk/debug/browser-debug.apk`, then open Rift and allow the network lock |

Further reading: [architecture](docs/architecture.md); the detailed status and history in [project-status.md](docs/reports/project-status.md); the reports for phases [0](docs/reports/phase-0.md), [1](docs/reports/phase-1.md), [2](docs/reports/phase-2.md), [3](docs/reports/phase-3.md), [4](docs/reports/phase-4.md) and the [browser isolation](docs/reports/browser-isolation.md) report; the raw evidence in [`docs/reports/evidence/`](docs/reports/evidence/).
