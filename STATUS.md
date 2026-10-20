# Simulation-Rift: current status

**As of 20 Oct 2026** (`main` at the commit that last changed this file). Simulation-Rift is in development: Phases 3 and 4 of the roadmap are built and tested on emulators (Phases 0–7, [architecture §22](docs/architecture.md)). It is **not** a usable or audited security product. Every claim below means "tested in the stated environment", nothing more. The full history, all findings and the per-phase evidence are in [`docs/reports/project-status.md`](docs/reports/project-status.md) and the reports next to it.

## In one paragraph

The Android debug build works end to end on emulators, and its browser is now isolated by the operating system rather than by "deleting cookies". The browser is a **separate app with its own Linux user ID**, so code that escapes the web engine cannot see Rift's files, keys or quarantine. A **network lock** gives it no route to any network except Rift's own checking proxy: a VPN that applies only to the browser and drops every packet, plus a loopback proxy that needs a per-session token and refuses local and private addresses. At every reset **Android itself wipes the browser app** (all its processes are killed and all its data deleted), and Rift checks that a fresh instance holds no file at all. Downloads are re-fetched into encrypted per-session quarantine, previewed and scanned in isolated worker processes. Files you choose to keep go into an **encrypted vault** whose key is held by Android's keystore behind your screen lock or fingerprint (or by a passphrase), and which locks when Rift leaves the screen. The only threat database is a harmless demo one. Nothing has run on a physical phone. Hardening has started on Android; the Linux app has not. Linux comes last and will use Qt.

## Phases

| Phase | State |
|---|---|
| 0: Feasibility (14 proofs of concept) | **Mostly done.** All pass in at least one environment, including A8 (the browser split and the network lock). Open: the lookup benchmark on a phone, the Linux checks inside Flatpak, and L4 (the Linux network lock). |
| 1: Foundations (Rust core, protocol, formats) | **Done.** Unit, property and fuzz tests, strict lints, dependency policy. |
| 2: Android vertical slice | **Done on emulators** (API 33–36, both ABIs, 16 KB pages), now on architecture 2.1 (browser app and network lock, [report](docs/reports/browser-isolation.md)). Gate still open: a physical phone. |
| 3: Scanner and signed intelligence | **Done on emulators**, except the production key policy and real feeds. Scanning (two isolated workers at a time); signed updates imported from a folder you choose or fetched online through the core's own checked fetcher; refusals in one sentence; a warning when the clock is behind the database. |
| 4: Vault | **Done on the API 35 emulator** ([report](docs/reports/phase-4.md)). Keystore key behind BiometricPrompt, or a passphrase; keep, export (warned), remove; locks on request, in the background and after an idle limit you choose (1–30 minutes, 5 by default). Kept files can be previewed in an isolated worker until the vault locks; an optional recovery passphrase opens a vault whose key was lost. Open: a physical phone (the emulator's keystore is software only). |
| 6: AI experiment | Not started; optional and gated by design. |
| 7: Hardening and release | **Started on Android** ([report](docs/reports/phase-7.md)). Privacy checks: local work, updates and an idle session move no byte on any real network for either of Rift's apps, and nothing is scheduled (x1); browsing leaves only through the controller's proxy (x2). The dependency and licence inventory is written ([dependencies.md](docs/reports/dependencies.md)); it led to one crypto library (aws-lc-rs) instead of two. NAT64 addresses are now judged by the IPv4 address they carry, so IPv6-only networks work. Both apps carry generated third-party notices, shown under "Open-source licences" (l1). Open: fault injection, long fuzz campaigns, an advisory check for the Android dependencies, an external review. |
| 5: Linux app | Not started. **Last**, after all Android work, and **with Qt instead of GTK4** (decided 20 Oct 2026). The worker lockdown is proven in PoCs; the browser design will be revised for Qt before any code. |

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

**What it does not do:** escaped browser code can still reach **loopback** (other apps' local servers on the phone), which no Android VPN covers; only one VPN can run on a device, so users of another VPN get reduced isolation or nothing; the proxy does not see inside HTTPS; and a WebView exploit still has the current session's own browsing data. These are listed in [architecture §24](docs/architecture.md).

## What works today (Android debug build)

| Feature | What it does | Tests |
|---|---|---|
| Disposable, isolated browser | System WebView in the separate browser app, behind the network lock; no native bridges or device permissions; refuses to browse if the engine sandbox or the lock cannot be confirmed, or WebView is too old. | S1, S2, S15, S23–S28, N1–N4 |
| Navigation policy | Blocks automatic external-app links, asks before lookalike addresses, marks unencrypted pages, explains every decision. | N1–N4 |
| Download capture | Downloads are re-fetched by the Rust core (destination checks on every redirect, size limit, cookies only to their origin) into encrypted quarantine. Hostile names are display-only. | S8–S10 |
| Previews | Images and PDFs render in an isolated worker (no files, no network, seccomp on the parser thread, deadlines, unbound after each job). Text is shown as escaped plain text. | P1, P2, S3–S7, S19 |
| Scanning | Each download is checked by file hash and type in the core, then by YARA-X rules in a fresh isolated worker, two at a time, so a hung worker does not hold the queue. A scan keeps the database snapshot it started with. The best status is "Not flagged", never "safe". | S16a, S21a, S21b |
| Signed threat database | TUF updates from a folder you choose (system picker) or online through the core's checked fetcher. Tampered, rolled-back, expired or wrongly signed updates are refused with a one-sentence reason (the full error goes to the log) and the old database stays. Debug builds embed a signed demo database. | S16, S17, S21, S22 |
| Vault | "Keep in the vault" copies a quarantined file, sealed with age to an identity wrapped by an Android Keystore key (per-use authentication through the system prompt, device must be unlocked) or a passphrase. Nothing readable is written to disk. Locks on request, when Rift goes to the background, and after 5 minutes. Export only after a warning, to a place you choose. A kept file can be scanned again with the current database, in a fresh isolated worker. The background lock can be turned off and the idle limit set (1–30 minutes, never off). | S18, v1–v7 |
| Reset and recovery | Reset stops the proxy, crypto-shreds quarantine, has Android wipe the browser app and verifies the result. A kill in the middle of a reset is recovered on the next start; the browser is also wiped at every launch. | S12, S13, S14, S27 |

## Where it has been tested

| Environment | Result |
|---|---|
| Host: macOS arm64, and CI on Ubuntu and macOS | 163 Rust tests, `clippy -D warnings`, `fmt`, `cargo deny`, 7 fuzz targets (short runs) and the Linux worker lockdown pass. |
| Android API 36, arm64 (local emulator, WebView 133) | **Full suite on architecture 2.1 (before the Phase 3 import and online tests and the vault): 31 instrumented tests plus S13/S14 pass** ([evidence](docs/reports/evidence/phase3-android-split-api36/)). |
| Android API 35, 16 KB pages, arm64 (local emulator, WebView 124) | **Full suite with the vault: 38 instrumented tests pass, and S16f, S13 and S14. S16d failed in that run because the on-screen keyboard blocked the script's scrolling; after the script fix the host steps all pass** ([evidence](docs/reports/evidence/phase4-vault-api35-16k/)). |
| Android API 33 and 34, x86_64 (CI emulators, WebView 109 and 113) | **Full suite on architecture 2.1 passes** (CI run 39363201440, before the import, online and vault tests; [33](docs/reports/evidence/phase3-android-split-api33-x86_64/), [34](docs/reports/evidence/phase3-android-split-api34-x86_64/)), after the fixes for the first 2.1 run ([report](docs/reports/browser-isolation.md), findings 7–8). |
| Android API 30 | Browsing is refused as designed (WebView 91 is below the minimum); the browser split and the lock were measured there in PoC A8. |
| Physical Android phone | **Not tested.** |
| Linux desktop app | **Not built** (last; Qt). |

## What is left

In order of priority:

Android first; Linux is the last step.

1. **Phase 3 leftovers:** ~~import screen~~, ~~online updates~~ and ~~clock warning~~ are done; open are the production key policy (offline keys, thresholds, rotation) and licensed real feeds.
2. ~~**Phase 4 leftovers:** key providers, lock/unlock, keep and warned export, plaintext inventory, previews of kept files, a recovery passphrase, the verdict a file had when kept, rescanning kept files, lock settings~~: all done on Android (v1–v7). A physical phone is still untested.
3. **Phase 7, hardening (Android):** ~~privacy checks~~ (x1, x2) are done; ~~a dependency and licence inventory with owners~~ and ~~the in-app licence notices~~ are done; open are long fuzz campaigns, fault injection, an Android advisory check, the rest of the release gates (§24; [their state](docs/reports/phase-7.md#release-gates-24)), and an external security review before any release claim.
4. **Phones:** physical devices (every emulator level has passed on 2.1), which also settle the keystore's hardware backing and the lookup benchmark.
5. **Phase 6 (optional):** the AI experiment, only if it adds measured value.
6. **Phase 5, Linux (last, Qt):** revise the §9 design for Qt and its web engine, redo the Linux PoCs (sandbox check, network lock L4) against it, then build the app on the same Rust core.

## Main limitations

| Limitation | Workaround or way forward |
|---|---|
| No real threat coverage: only the demo database exists. | Real feeds need a licensing review; the demo label is shown on every verdict. |
| Emulators only; no physical phone. | Connect a phone with USB debugging and run `android/run-tests.sh <dir>` (S13/S14 need `adb root`). |
| Escaped browser code can reach loopback services on the device. | No Android mechanism closes loopback for one app; the Linux design closes it with a network namespace. |
| One VPN per device: the lock cannot run next to another VPN. | Reduced isolation for one session, chosen and labelled; never automatic. |
| If the controller is killed mid-session, the lock goes with it until the next launch wipes the browser. | The browser exits when the core dies; Android's always-on VPN with "block connections without VPN" would close the gap (a device setting). |
| Sites that use HTTP authentication cannot be signed in to. | Only the proxy's own challenge is answered, so the token never reaches a site. |
| `blob:`, `data:` and POST downloads cannot be captured. | Stated as unsupported. |
| The Android worker is weaker than the Linux one (Android allows exec memory and `AF_UNIX`). | A seccomp filter on the parser thread; defence in depth, not a boundary. |
| The native code budget is tight: 19.2 MB (arm64) and 24.5 MB (x86_64) per ABI, against 25 MB. | The core's TLS and the update checks share one crypto library; measure every native addition. |
| Update expiry trusts the device clock; demo signing keys are one per role on one machine. | The clock is checked against the database's creation time (a fast clock cannot be detected offline); the production key policy is on the list. |
| The vault key's hardware backing is unverified (the emulator's keystore is software only). | The vault card shows the key's security level; a phone test settles it. |
| Removing the screen lock (or enrolling new biometrics) deletes the vault's key. | Set the optional recovery passphrase: it opens the vault, and a new key then protects it again. Without one, the vault is lost, as the app says when it is created. |
| Wasmtime advisories, pulled in through YARA-X. | Scoped exceptions in `cargo deny`, removed once YARA-X depends on Wasmtime ≥ 48.0.6. |
| Dev machine: Docker cannot build the Linux-only tests (out of memory); Apple silicon cannot run x86_64 emulators. | CI runs both. |

## Build and test

| What | Command |
|---|---|
| Rust tests and lints | `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo deny check` |
| Android apps (debug): controller, browser, outsider test app | `sh android/build.sh` (demo signing keys go to `~/.local/share/simulation-rift/demo-keys`, the outsider's throwaway key to `android/build/`, both outside version control) |
| Android suite on one attached emulator | `sh android/run-tests.sh <evidence-dir>` (installs all three apps and grants the VPN consent a user would give) |
| Install only | `adb install -r android/app/build/outputs/apk/debug/app-debug.apk` and `adb install -r android/browser/build/outputs/apk/debug/browser-debug.apk`, then open Rift and allow the network lock |

Further reading: [architecture](docs/architecture.md); the detailed status and history in [project-status.md](docs/reports/project-status.md); the reports for phases [0](docs/reports/phase-0.md), [1](docs/reports/phase-1.md), [2](docs/reports/phase-2.md), [3](docs/reports/phase-3.md), [4](docs/reports/phase-4.md) and the [browser isolation](docs/reports/browser-isolation.md) report; the raw evidence in [`docs/reports/evidence/`](docs/reports/evidence/).
