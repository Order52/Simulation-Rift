# Rift — Architecture and Specification

**Version:** 2.5 (22 Oct 2026; v2.0 of 17 Oct 2026 superseded the v1.1 "Project Specification")
**Date:** 22 October 2026
**Changes in 2.5:** Decoys on Android (§10.5): a page that asks for the camera, microphone, screen, location, files, notifications, clipboard, motion sensors or battery is given something made up that works (a generated video, near-silence, a position near a city, a generated photo, an empty clipboard) and the live watch lists each request. The decoys are a script injected before every page and a strings-only message channel from it, so INV-6 now allows exactly that channel; the engine's own refusals stay underneath as the backstop. The file chooser returns a made-up file instead of being denied. A link shared to Rift gets a verdict sheet over the sharing app, with the reasons and Open safely (§10.1). Rift AI's passes are chosen on validation sites, it trains on October 2026's phishing links as well as December 2025's, and a time-separated test is reported (§16). The app is called Rift (formerly Simulation-Rift); package names are unchanged. Optional extra isolation with Shizuku or root (§8.9): Android ignores the browser app's clipboard, the reset's wipe is requested by the controller, and with root a firewall keeps the browser app's UID to its proxy on loopback. Rift is one file to install: its APK carries the browser's and installs it on first launch through Android's installer (§8.10), so the browser is still a separate app. The network lock has a switch (§8.8): off, every session runs with reduced isolation, labelled. Release builds carry arm64 code only (§18). Content filters (§10.9): ad, tracker, cookie-banner and sign-in-prompt lists from EasyList, Fanboy and uBlock Origin, matched in the controller, with the user's own rules. The home screen is five tabs (Home, Filters, Activity, Security, About) instead of one long scroll, and About names the authors. Link tools in Check and the share sheet (§10.10): ClearURLs cleaning, quick fixes, a trace of where a link goes with every hop checked, copy, share and open elsewhere.
**Changes in 2.4:** Rift AI is built and on by default on Android (§16, [rift-ai.md](reports/rift-ai.md)): a URL model trained on public phishing and malware feeds, run on the device, advisory only. The home screen separates **Check** (judge a link without opening it, with Rift AI's score and reasons) from **Open safely** (§10.1). A navigation Rift AI rates High asks before loading, and the live watch notes connections to hosts it rates High (§10.5). The model is trained by a Rust tool that shares its feature code with the app, not by Python and scikit-learn as 2.3 planned.
**Changes in 2.3:** Rift keeps nothing after a session. The Rift Vault (§14 of 2.2: keeping files in age-encrypted storage behind a Keystore key or a passphrase) is removed on both platforms, with its passphrases, lock policy and export; the age code that remains seals each session's quarantine (`rift-core::seal`). Android's home screen is redesigned around opening a link (§10.1), and gains a weekly summary of what Rift checked and stopped, kept as counts only (§10.8). Files can be opened with Rift or shared to it from other apps: each is copied into the session's quarantine and shown in a full-screen viewer (§8.2, §11.1). The Linux app is future work: its code and CI stay, and Android comes first (§9).
**Changes in 2.2:** the Linux app is built on Qt (QML through cxx-qt, Qt WebEngine from Flathub's BaseApp) instead of GTK4 and WebKitGTK. The browser host runs in a no-network Flatpak sub-sandbox and reaches the web only through a forwarded egress proxy in the controller. PoCs Q1–Q4 measured it ([phase-5-qt-design.md](reports/phase-5-qt-design.md)); §9, §6, B1, ADR-10 and the stack table are revised.
**Changes in 2.1:** the Android browser moves into its own APK (separate UID, wiped by the system at every reset) behind a network lock: a per-app VPN that forwards nothing, and an authenticated loopback proxy in the controller as the browser's only way out. PoC A8 measured both (ADR-04 revised, ADR-14, INV-14, B2/B8, §8.8, S23–S28).
**Status:** Approved baseline architecture. Phase 0 feasibility tests are in progress; every claim marked **[PoC]** is unverified until its Phase 0 report says otherwise.
**Platforms:** Android (API 30+, arm64-v8a first, x86_64 for emulators) and Linux (Flatpak, x86_64 and aarch64)
**Languages:** Rust (shared core, workers, Linux controller), Kotlin (Android UI and platform glue), QML and C++ (Linux UI and the Qt WebEngine host, kept thin), Python (standard library only: preparing the training data, never shipped)

> Rift (formerly Simulation-Rift) is a fully local, modular workspace for opening unfamiliar links, downloading untrusted files and viewing them safely, keeping nothing afterwards. It does this by combining OS-enforced isolation, offline-first threat detection, and signed data updates. It never promises perfect isolation. It makes specific, tested claims about named boundaries.

---

## Contents

1. [Principles](#1-principles)
2. [Scope](#2-scope)
3. [Threat model](#3-threat-model)
4. [Trust boundaries](#4-trust-boundaries)
5. [Security invariants](#5-security-invariants)
6. [Architecture overview](#6-architecture-overview)
7. [Shared Rust components](#7-shared-rust-components)
8. [Android platform](#8-android-platform)
9. [Linux platform](#9-linux-platform)
10. [Rift Browser](#10-rift-browser)
11. [Rift Files: intake, quarantine, preview, export](#11-rift-files-intake-quarantine-preview-export)
12. [Rift Scanner](#12-rift-scanner)
13. [Threat intelligence and signed updates](#13-threat-intelligence-and-signed-updates)
14. [Rift Vault (removed in 2.3)](#14-rift-vault-removed-in-23)
15. [Sessions](#15-sessions)
16. [Rift AI](#16-rift-ai)
17. [Privacy and network behaviour](#17-privacy-and-network-behaviour)
18. [Performance budgets](#18-performance-budgets)
19. [Technology stack](#19-technology-stack)
20. [Decision record](#20-decision-record)
21. [Repository and engineering conventions](#21-repository-and-engineering-conventions)
22. [Roadmap and phase gates](#22-roadmap-and-phase-gates)
23. [Acceptance test matrix](#23-acceptance-test-matrix)
24. [Residual risk register](#24-residual-risk-register)
25. [Licensing](#25-licensing)
26. [Future expansion](#26-future-expansion)
27. [Glossary](#27-glossary)
28. [References](#28-references)
29. [Appendix A: changes from v1.1](#appendix-a-changes-from-v11)

---

## 1. Principles

1. **Isolation, detection, encryption, and disposal are separate protections.** None of them replaces another. A scanner miss does not weaken isolation. A clean scan does not permit unsandboxed parsing. Encrypting a file does not make it harmless. Deleting a session is not forensic erasure.
2. **Every boundary is an OS mechanism.** Examples are a separate UID, SELinux domain, seccomp-bpf, Landlock, or the browser engine's sandbox. Rust modules, Kotlin classes, and FFI calls are not boundaries.
3. **Fail closed on confinement, fail visible on detection.** If mandatory confinement is unavailable, the feature is disabled. If detection fails, the result says "not fully scanned".
4. **Reuse established engines and formats.** We do not write a browser engine, PDF parser, image codec, rule engine, cipher, file-encryption format, or update framework.
5. **One implementation per concern across platforms** where the platform allows it. That means one rule engine, one worker codebase, one protocol, one storage format, and one URL algorithm.
6. **The simplest design that meets the requirement.** We add a trait only when there are two real implementations. We add a process only when it buys a boundary or a lifecycle guarantee. We add a dependency only when it removes more risk than it adds.
7. **Measured, not asserted.** Performance numbers are targets until they are measured on a named device. Security properties are claims until a test demonstrates them.

## 2. Scope

### 2.1 Use cases

| Use case | Behaviour |
|---|---|
| Open an unfamiliar link | Rift is chosen from the share sheet or an ACTION_VIEW intent. It runs a local URL check, then opens the link in a restricted, disposable browser session. |
| Download a file | The file goes into the session quarantine, never to public Downloads. |
| Import an attachment | Only the file the user hands over is copied into quarantine. Android: a file opened with Rift or shared to it from another app (a `content:` URI with a read grant). Linux: the file portal. Nothing else is indexed or enumerated. |
| Inspect a file | Scan status and coverage are shown. Supported formats get a confined preview. |
| Update intelligence | The user fetches or imports a signed pack. After that, the device works offline. |
| Reset | All session state is destroyed, downloads included. Nothing a session held is kept. |

### 2.2 V1 includes

- Browse, download, inspect and reset, end to end.
- Local URL checks: indicator lookup plus explainable heuristics.
- File checks: SHA-256 indicators, magic-byte type identification, and YARA-X rules.
- Confined preview of PDF, PNG/JPEG/WebP, and plain text. Markdown, HTML, and SVG are shown as plain text.
- A weekly summary of what Rift checked and stopped, as counts only (§10.8).
- Signed manual intelligence updates and signed offline import.
- Labelled demo intelligence packs.
- Per-platform security and performance evidence reports.

### 2.3 V1 excludes

- Executing downloaded programs (.exe, .apk, ELF, scripts, macros, installers).
- Archive extraction. Archives get outer-file checks only.
- Office previews. Office files are stored and statically checked only.
- Whole-device scanning or monitoring.
- Remote or cloud execution, VMs, and containers used as a user feature.
- Synthetic camera, microphone, or location devices. Real access is denied.
- Background update scheduling. Updates are manual in V1.
- Online reputation providers. The interface is reserved but not built.
- Any AI beyond the advisory URL model of §16: no page-content model, no on-device learning, no cloud model.
- Multiple concurrent sessions.
- Keeping files after a session. Versions 2.0–2.2 had an encrypted vault for that; 2.3 removed it, since a tool for opening untrusted things once gains little from storing them, and the vault's keys and passphrases were attack surface and burden.

"Any link" means public `http`/`https` URLs subject to policy. It does not mean every authentication flow, DRM stream, app scheme, or download mechanism works.

## 3. Threat model

### 3.1 Assets

In priority order:

1. The user's personal files and other apps' data.
2. Quarantined downloads, and the per-session keys that encrypt them.
3. Sensitive device capabilities: camera, microphone, location, contacts, SMS.
4. The integrity of Rift's code, policy, and intelligence.
5. The user's existing browser accounts. Rift never imports cookies, passwords, or extensions.
6. Device resources: storage, memory, battery.

### 3.2 Adversaries

| ID | Adversary | Capability assumed | In scope |
|---|---|---|---|
| T1 | Malicious website | Arbitrary HTML/JS/WASM; may hold a renderer exploit | Yes |
| T2 | Malicious file | Crafted input to any parser we run, including a parser RCE | Yes |
| T3 | Network attacker | Controls the path to sites and update servers | Yes |
| T4 | Compromised upstream feed or poisoned data | Inserts false indicators or malformed records | Yes (bounded by validation and signing) |
| T5 | Compromised signing key | Signs malicious metadata | Partially: TUF thresholds and root rotation limit the damage |
| T6 | Thief with a locked device or a copied storage image | Offline access to app storage | Yes |
| T7 | Other apps on the device | Android: separate UIDs. Linux: other Flatpaks are in scope; same-user host processes are **not** | Partially |
| T8 | Social engineering | Persuades the user to type secrets or export files | Warnings only |

### 3.3 Explicitly out of scope

- A compromised OS, kernel, firmware, or root user.
- Same-user non-sandboxed processes on Linux reading an open session's data or memory.
- Most hardware and micro-architectural side channels. Spectre-class leaks between sites are reduced by giving each session its own renderer, but are not eliminated.
- Undiscovered browser-engine or kernel sandbox escapes. These are residual risk (§24).
- Forensic recovery of deleted flash blocks. Crypto-shredding mitigates this for Rift's own files (§15).

## 4. Trust boundaries

| # | Boundary | Enforced by | Strength | Notes |
|---|---|---|---|---|
| B1 | Web content → app | Android: Chromium renderer in an `isolated_app` SELinux domain with seccomp-bpf. Linux: Qt WebEngine's renderer sandbox (Chromium's seccomp-bpf, in a portal-spawned Flatpak instance with mount, pid, IPC and network namespaces of its own; Q1, Q2) | Strong; exploit chains exist | One renderer per WebView profile, so there is no site isolation within a session. |
| B2 | Browser host → core and quarantine | Android: separate **APK and UID** (`org.simulationrift.browser`). Its data directory is private to it and Rift's is not even mounted in its namespace; the only door is one Binder service exported under a `signature` permission, which checks the caller's UID and signer on every call | Strong; kernel- and SELinux-enforced (PoC A8) | v2.0 used a separate process with the same UID, which was weak. An engine escape now lands in an app that holds no Rift data, keys or code beyond the browser's. The system wipes that app at every reset. |
| B3 | File content → app | Android: `isolatedProcess` service (random UID, `isolated_app` domain, no permissions). Linux: worker self-lockdown with seccomp-bpf allowlist, Landlock, rlimits, and no_new_privs | Strong for parse-only workers | Workers receive only file descriptors. |
| B4 | Website → sensors | Permissions are **absent from the manifest** (Android) or denied in WebKit permission callbacks (Linux) | Strong on Android (OS-enforced); policy-enforced on Linux | Callbacks deny as well, as defence in depth. |
| B5 | Offline attacker → quarantine | Each session's downloads are age-encrypted to a key that exists only in the controller's memory and is dropped at reset, before the files are deleted (crypto-shredding) | Strong once the session ends or the controller dies | While the session lasts, the key is in memory. Object count and sizes leak until reset. |
| B6 | Network or feed attacker → intelligence | TUF metadata (signatures, thresholds, expiry, rollback state), then strict bounded parsing | Strong while keys are protected | Signatures prove origin, not correctness. |
| B7 | Other apps → Rift's data | Android app sandbox (per-app UID). Flatpak's per-app home on Linux | Strong on Android; partial on Linux | Linux host processes of the same user can read `~/.var/app/<id>`. |
| B8 | Browser → network | Android: a VPN that applies to the browser app's UID only and forwards nothing, so the kernel routes all of its non-loopback traffic (TCP, UDP, DNS, WebRTC) into a dead end; the browser's only way out is the controller's loopback proxy (`rift-core::egress`), which needs a per-session token and applies INV-13 to every connection. Linux: §9.2 | Strong for page content; strong against direct sockets from escaped browser code except to **loopback** (PoC A8) | Pages cannot reach the LAN, the router, loopback services or cloud metadata addresses. The proxy sees host names and ports, not HTTPS content. Only one VPN can run on a device; without it the browser runs only in a stated reduced mode (§8.8). |

```text
                 ┌──────────────── TRUSTED (controller APK) ───────────┐
  user ──UI──▶   │ main process: UI · rift-core · quarantine · intel ·  │
                 │ updater · policy · egress proxy (127.0.0.1) · VPN    │
                 └───┬────────────────────┬──────────────────┬──────────┘
            B2 (strong: other UID,   B8: the only way    B3 (strong)
            signature-checked Binder) out (loopback)        │
                 ┌───▼────────────────────▼────┐   ┌────────▼─────────────┐
                 │ browser APK, own UID        │   │ rift-worker           │
                 │ :web  WebView host + network│   │ PDF · image · YARA-X  │
                 │ service; session service    │   │ no net · no fs · no   │
                 │ (wiped by the system)       │   │ keys                  │
                 └───┬─────────────────────────┘   └───────────────────────┘
                     │ B1 (strong)       all other traffic ──▶ VPN tun ──▶ dropped
                 ┌───▼────────────┐
                 │ renderer       │  ◀── T1 hostile web content
                 └────────────────┘
```

## 5. Security invariants

Each invariant has a test ID in §23. An invariant without a passing test is reported as **unverified**.

| ID | Invariant |
|---|---|
| INV-1 | Untrusted documents, images, and rules are parsed only inside a confined worker (B3). If confinement cannot be established, the operation is refused. There is no in-process fallback and no user override. |
| INV-2 | A worker receives only a read-only input fd, an output channel, and a bounded request. It never receives paths, directory fds, keys, network access, or a capability to open more resources. The controller verifies confinement *before* sending input. |
| INV-3 | Every worker message is size-checked before decoding (control messages ≤ 64 KiB) and validated after decoding: type, version, job ID, session generation, counts, dimensions, stride, and byte length. Worker output is untrusted. |
| INV-4 | Stored objects are immutable and identified by an app-generated ID. Each records the SHA-256 of its plaintext. A verdict is bound to (sha256, engine version, intel snapshot ID, policy version). Different bytes mean a different object and no inherited verdict. |
| INV-5 | A failed, timed-out, crashed, or unsupported check produces **Not fully scanned**. It never produces **Not flagged**. |
| INV-6 | The browser exposes no JavaScript interface (no Java object) to web content; its only message channel is the decoys' (§10.5): strings only, one-way, under a per-session name removed before page scripts run, each message checked against a fixed list of kinds, bounded, and attributed to the origin the engine reports. File and content access are disabled. `intent:`, `file:`, `content:`, and custom schemes are never forwarded automatically. Mixed content is never allowed. Multiple windows are disabled. A persistent trusted indicator survives fullscreen. The file chooser never gives a page a file of the user's: it gives a made-up one (§10.5). |
| INV-7 | Browsing is refused if the engine's renderer sandbox cannot be confirmed. On Android that means the renderer is not multi-process or WebView is below the minimum version. On Linux that means the WebKit sandbox is not active. If the renderer crashes, the session is torn down and the app does not crash. |
| INV-8 | Session reset terminates the session's processes, deletes session data, and verifies the deletion. Only then does it report success, and it advances the session generation. Results from older generations are rejected. A failed cleanup is shown as failed. On Android the browser app is wiped by the system (`clearApplicationUserData`), which kills all its processes and deletes all its data, at every reset and before the first session after a launch. |
| INV-9 | Quarantine plaintext is written to persistent storage only in encrypted form. Preview plaintext lives in RAM-backed fds (memfd/ashmem) **[PoC A7/L3]**. |
| INV-10 | An intelligence snapshot is activated only after full TUF verification, staging, schema validation, and smoke tests, all followed by one atomic pointer swap. Expired network metadata and rollbacks are rejected. Recovery is done with a new, higher-versioned release, never by resetting anti-rollback state. |
| INV-11 | In Local Protection mode, Rift's own code sends no content-specific requests (URLs, hashes, files) to any third party. Engine features that do, such as Safe Browsing, are disclosed and controlled by the user. |
| INV-12 | The app opts out of backup and device-to-device transfer for all data. No recents snapshot of either app's windows is stored (API 33+). |
| INV-13 | Controller-owned network transfers (downloads, updates) re-check every redirect hop. They resolve DNS once per hop and refuse loopback, private, link-local, and multicast destinations unless the user explicitly allows them. They enforce byte limits on the stream, not on `Content-Length`. |
| INV-14 | While a session is open, the browser has no network path except the controller's egress proxy (Android: the browser UID's traffic is routed into a VPN that forwards nothing, and WebView's proxy override has its implicit bypass rules removed; Linux: the browser host runs in a sub-sandbox with no network, and its connections reach the proxy only over its private socketpair). The proxy accepts only this session's token (Android) or the browser host's socketpair (Linux) and applies INV-13's destination rules to every connection. If the lock is lost, the session ends and the browser is wiped. Browsing without the lock is possible only in a reduced mode the user chooses for one session, which the trusted UI names. |

## 6. Architecture overview

```text
 ANDROID — two APKs, two UIDs                                LINUX — Flatpak (KDE runtime + QtWebEngine BaseApp)
 ┌─ controller APK, main process [TRUSTED] ─────┐   ┌─ rift controller [TRUSTED] ──────────────┐
 │ Kotlin/Compose UI · VPN for the browser UID  │   │ QML via cxx-qt · rift-core (direct Rust) │
 │ rift-core via UniFFI (rift-ffi) · egress     │   │ ForwardedEgress · worker supervisor      │
 └──┬──────────────────────┬────────────────────┘   └──┬────────────────────┬─────────────────┘
    │ Binder, signature    │ Binder + ParcelFileDescriptor  │ SEQPACKET on stdin │ socketpair + SCM_RIGHTS
    │ permission + UID chk │                          ┌──▼─ browser host ──────────┐ ┌▼─ rift-worker ──────┐
 ┌──▼─ browser APK ────────┐ ┌▼─ isolatedProcess ─────┐ │ flatpak-spawn --sandbox    │ │ seccomp + Landlock   │
 │ :web WebView host +     │ │ rift-worker-ffi (.so)  │ │ --no-network: Qt WebEngine │ │ rlimits, NNP         │
 │ network service; proxy  │ │ PdfRenderer (platform) │ │ browser process, forwarder │ │ PDFium · image ·     │
 │ is 127.0.0.1 (egress)   │ │ image · YARA-X(pulley) │ └──┬─────────────────────────┘ │ YARA-X(pulley)       │
 │ no Rift data, no keys   │ └────────────────────────┘ ┌──▼─ renderers ─────────────┐ └──────────────────────┘
 └──┬──────────────────────┘                            │ Chromium seccomp-bpf, own  │
 ┌──▼─ WebView renderer ───┐                            │ mnt/pid/ipc/net namespaces │
 │ isolated_app, seccomp   │                            └────────────────────────────┘
 └─────────────────────────┘
```

**Data flow for the main workflow:**

```text
link ─▶ url::canonicalize ─▶ intel lookup + heuristics ─▶ policy ─▶ browser session (gen N)
                                                                       │ download
                                                                       ▼
 transfer (core): per-hop destination check ─▶ stream with limit ─▶ SHA-256 ─▶ encrypt
   (session key) ─▶ commit immutable object ─▶ scan job (worker) ─▶ verdict(bound to hash+versions)
                                                                       │ user: preview
                                                                       ▼
            decrypt into memfd ─▶ worker renders one page ─▶ validated bitmap ─▶ trusted UI
                                                                       │ reset
                                                                       ▼
                            key dropped ─▶ session directory deleted (crypto-shredded)
```

## 7. Shared Rust components

The workspace has a few crates with explicit dependency direction: `rift-protocol` ← `rift-worker` ← `rift-worker-ffi`, `rift-protocol` ← `rift-core` ← `rift-ffi` / `rift-linux`. `rift-core` never depends on parser crates. On Android the two UniFFI libraries are loaded by different processes: `rift_ffi` (core) only in the main process, `rift_worker_ffi` (parsers and protocol, no core) only in the isolated worker.

### 7.1 `rift-core`: trusted logic (`#![forbid(unsafe_code)]`)

| Module | Responsibility |
|---|---|
| `object` | `ObjectId` (random 128-bit), `ObjectRecord` (sha256, size, detected type, source, owner), immutability rules. |
| `transfer` | Bounded streaming writer: limits, incremental SHA-256, encryption on write, commit or abort. Destination policy per hop (INV-13). |
| `session` | The state machine `Creating → Active → Resetting → Destroyed / CleanupFailed / RecoveryPending`; generations; the recovery marker. |
| `policy` | Pure functions `decide(Action, &Context) → Decision { Allow, Deny(Reason), Confirm(Warning) }`. No I/O, so it is exhaustively testable. |
| `url` | WHATWG parsing (`url` crate), Safe Browsing-style canonicalization and host/path expressions, and explainable heuristics (§12.2). |
| `urlmodel` | Rift AI (§16): the model file's validated format, the feature extraction shared with the trainer, sites by the Public Suffix List, scores and readable reasons. |
| `intel` | Snapshot store (memory-mapped sorted hash tables), lookups, and staging and atomic activation. |
| `update` | TUF client integration (`tough`) and offline import. |
| `scan` | Orchestration, cache keys, result vocabulary, coverage accounting. The engines themselves run in the worker. |
| `seal` | age encryption of each quarantined object to its session's in-memory key, with the object's hash, size and identity checked when it is opened. |
| `filetype` | Magic-byte identification over the first 8 KiB (`infer` crate). Bounded; no deep parsing. |
| `worker` | The `WorkerLauncher` trait and job lifecycle: deadline, cancellation, retirement, result validation. |

There are three traits, each with two or more real implementations:

- `WorkerLauncher`: Android Binder, Linux spawn, and a test fake.
- `KeyProvider`: Android Keystore, passphrase, and a test fake.
- `Clock`: system clock and test clock.

Everything else is a concrete type.

### 7.2 `rift-protocol`: the worker contract (`#![forbid(unsafe_code)]`)

- Encoding: `postcard` (serde). Frames are `u32` length-prefixed. The length is checked against a maximum of 64 KiB **before** allocation.
- Every request carries `protocol_version`, `job_id`, `session_generation`, and `limits` (deadline, max pixels, max matches).
- `Request` variants: `Hello` (confinement report), `ScanBytes { rules_digest }`, `RenderPdfPage { page, max_w, max_h }`, `DecodeImage { max_w, max_h }`, `PdfInfo`.
- `Response` variants: `Ready { confinement: ConfinementReport }`, `ScanResult { matches: Vec<RuleMatch> (bounded) }`, `Bitmap { w, h, stride, format }` (pixels travel out of band via fd), `PdfInfo { pages }`, `Error { code }`.
- `validate()` checks every invariant in INV-3. It is the primary fuzzing target.

### 7.3 `rift-worker`: untrusted-input processing

- Contains the parsers: YARA-X (`pulley` feature, minimal modules), the `image` crate (PNG, JPEG via zune-jpeg, WebP) with `Limits`, and PDFium on Linux (`pdfium-render`, dynamically loaded `libpdfium`).
- **Linux lockdown sequence:**
  0. Refuse to continue unless the process has exactly one thread. seccomp (without TSYNC) and Landlock confine only the calling thread, so a thread a library started earlier would stay unconfined.
  1. Close every fd except the IPC socket.
  2. Set rlimits: `AS`, `CPU`, `NOFILE`, `FSIZE=0`, `NPROC=0`, `CORE=0`.
  3. Set `PR_SET_NO_NEW_PRIVS`.
  4. Apply a Landlock ruleset with no access, or read-only access to font directories for PDF.
  5. Install a seccomp-bpf allowlist with no `open*` outside Landlock, no `socket`, `connect`, `execve`, `ptrace`, or `kill` of other processes, and no `clone` of new processes.
  6. Report `Ready` with a self-check.

  The controller cross-checks `/proc/<pid>/status` for `Seccomp: 2` and `NoNewPrivs: 1` before it sends any input.
- **Deadlines.** The Linux worker stays single-threaded, so it cannot use YARA-X's in-process timeout (it starts a timer thread, which the seccomp filter forbids; Phase 0 L2). The supervisor kills the worker when a job's deadline passes, and `RLIMIT_CPU` is the backstop. On Android the app cannot kill the isolated process directly, so the worker uses YARA-X's timeout there (`rift_worker::Deadline`).
- **Android:** the same Rust job code is loaded via JNI inside the isolated service. On Android the lockdown relies on `isolated_app`. A self-applied seccomp filter is a hardening option once ART's syscall needs are characterized.
- `unsafe` is confined to `lockdown` and FFI shims. Each block carries a `// SAFETY:` justification and is subject to review.
- Workers are **retired** after a document closes, after N jobs, or after any error. They are never trusted to reset their own state.

## 8. Android platform

### 8.1 Baseline

- **minSdk 30** (Android 11). From API 30 onward the WebView renderer is always out-of-process [R02].
- targetSdk is the latest stable API.
- arm64-v8a is the primary ABI; x86_64 is for emulators. Every native library must be 16 KB page-aligned [R11].
- Compatibility reports record the device, Android version, WebView provider and version, security patch level, and page size.

### 8.2 Manifest

- Permissions: `INTERNET`; `HIDE_OVERLAY_WINDOWS` in both apps (a normal permission that lets a window hide other apps' overlays, §10.7); and `POST_NOTIFICATIONS` if transfer progress notifications are adopted. The browser APK also requests `ACCESS_NETWORK_STATE` (a normal permission), so that it can confirm its default network is the lock before it loads a page (§8.8). Since 2.5 the controller also requests `REQUEST_INSTALL_PACKAGES`, to install the browser it carries (§8.10); the user grants it in Android's settings, and the browser app does not request it. **No** camera, microphone, location, contacts, SMS, storage, accessibility or device-admin permissions. Because the permissions are absent, the OS denies them regardless of WebView callbacks (B4).
- `android:allowBackup="false"` and `dataExtractionRules` that exclude everything (INV-12).
- `usesCleartextTraffic` is set only as required for user-initiated HTTP browsing. Rift's own traffic is HTTPS-only.
- Intent filters: `ACTION_VIEW` for http/https (Rift appears as a browser choice) and `ACTION_SEND` with `text/plain` (a link in shared text, §10.2). Since 2.3 also files: `ACTION_VIEW` of a `content:` URI for images, PDF and plain text, and `ACTION_SEND` of any type with `EXTRA_STREAM` (§11.1, intake). A share with a stream is taken as a file, otherwise as a link; `file:` URIs are never read (they reach the link check, which refuses the scheme).
- Components:
  - Two apps signed with the same key (ADR-04, revised in v2.1), shipped since 2.5 as one file: the controller's APK carries the browser's as an asset (§8.10). The controller, `org.simulationrift.app`, holds everything below except the browser. The browser, `org.simulationrift.browser`, holds only `BrowserActivity` (`android:process=":web"`) and `SessionService` (its default process, which never loads WebView). Both define the `signature` permission `org.simulationrift.permission.RIFT`; each exported component requires it, and each side also checks the calling UID's package and signer on every call. The browser has no launcher entry.
  - `MainActivity` (main process).
  - `NetworkLockService` (`VpnService`, `BIND_VPN_SERVICE`), the network lock (§8.8).
  - `PreviewService` with `android:isolatedProcess="true"`, `android:exported="false"`, and `android:useAppZygote="true"`. The zygote preload only loads the native libraries (`jnidispatch`, `rift_worker_ffi`): the zygote must stay single-threaded, so no JNA or UniFFI object is created there.
  - Debug builds add test workers from `src/debug` (probe, hanging, crashing, lying and unconfined services for S3–S7). The release manifest is checked to contain none of them.
  - `CoreService`, the browser→core interface, exported only under the `signature` permission.
  - Since 2.5, for extra isolation (§8.9): `ShizukuProvider`, exported under `INTERACT_ACROSS_USERS_FULL`; the helper `HardeningService`, which only Shizuku starts, in `:hardening` as shell or root; and the request for Shizuku's own permission `moe.shizuku.manager.permission.API_V23`.
  - The controller never depends on `androidx.webkit` and never loads WebView; `build.sh` refuses a build in which it does.

### 8.3 Processes and why

| Process | Holds | Why it exists |
|---|---|---|
| controller main | UI, rift-core, the session's quarantine key, intel, updater, egress proxy, network lock | Trusted controller. |
| browser `:web` | WebView host and its network service | The process an engine escape reaches. It runs under the browser APK's UID, which owns nothing of Rift's, and its traffic has no route except the egress proxy (§8.8). |
| browser default process | `SessionService`: hello, inventory, wipe | Lets the controller have the system wipe the browser app and check that a fresh instance holds nothing. Never loads WebView. |
| renderer | Web content | Provided and sandboxed by WebView (B1). |
| isolated worker | One job's input | B3. |

**What an engine escape reaches (v2.1, PoC A8).** Code running in the browser's `:web` process after an escape has the browser APK's UID. Measured from that process on API 30 and 36:

- Rift's data directories are not visible at all (`ENOENT`): quarantine, intel and session marker (and, before 2.3, the vault) are out of reach, and Keystore keys belong to the controller's UID.
- The controller's private services cannot be bound (`SecurityException`). The one exported interface, `CoreService`, offers only navigation decisions, typed-address normalization, download submission, the sandbox and network reports, reset and renderer-gone. It has no file operations, and every call is checked for the browser's UID and signer and the current session generation.
- TCP, UDP and DNS to anything but loopback are dropped by the network lock; through the proxy only public destinations (or the user's per-session exceptions) are reachable.

What it still has: the browser app's own state for the current session (the pages, cookies and downloads seen in it), the `INTERNET` permission (useless outside loopback while the lock holds), the ability to draw anything inside the browser window, and **loopback**, which no VPN covers: other apps' local servers on the device remain reachable from escaped code (not from pages, which the proxy refuses). Because the system wipes the app at each reset, the escape does not survive into the next session unless it also escapes Android's app sandbox.

v2.0 ran the browser as a process of the controller's own APK, so an escape had the controller's UID and could read its files. That weaker design is gone.

### 8.4 WebView configuration

- Preconditions (INV-7):
  - `WebViewCompat.getCurrentWebViewPackage()` is at or above the minimum supported version.
  - `WebViewCompat.isMultiProcessEnabled()` returns true **[PoC A1]**.
  - Otherwise browsing shows "unsupported device configuration".
- `setDataDirectorySuffix("s<generation>")` is called in `:web` before any WebView use. A new generation gets a fresh directory even if the system wipe of the old one were still pending.
- The network lock is set up before the first page (§8.8): `ProxyController.setProxyOverride` with the proxy at `127.0.0.1:<port>` and `removeImplicitRules()`, completed before any WebView is created; and the browser's default network must be the VPN. If `PROXY_OVERRIDE` is unsupported or either step fails, browsing is refused, as for an unconfirmed renderer sandbox.
- The proxy's 407 challenge is answered in `onReceivedHttpAuthRequest` only for host `127.0.0.1` and the session's random realm; every other credential request is cancelled, so the token never goes to a site.
- The controller never loads WebView, not even to ask about it (`isMultiProcessEnabled()` loads the provider). In v2.0 a test that did so created an unsuffixed `app_webview/`; the reset inventory refused it. In v2.1 the controller has no WebView dependency at all.
- Settings:
  - JavaScript on (sites need it). `allowFileAccess=false`, `allowContentAccess=false`.
  - `mixedContentMode=NEVER_ALLOW`, `setSupportMultipleWindows(false)`, `javaScriptCanOpenWindowsAutomatically=false`, `setGeolocationEnabled(false)`, `saveFormData=false`.
  - No `addJavascriptInterface`, no `addWebMessageListener`, no `addDocumentStartJavaScript`.
- Clients:
  - `shouldOverrideUrlLoading`: main-frame navigations go through `url` + `intel` + `policy`. Non-http(s) schemes are denied.
  - `onPermissionRequest`: deny. `onGeolocationPermissionsShowPrompt`: deny.
  - `onShowFileChooser`: deny unless the per-session toggle is on.
  - `onShowCustomView`: fullscreen keeps a trusted overlay indicator, or is denied.
  - `onReceivedSslError`: cancel.
  - `onRenderProcessGone`: destroy the WebView, end the session, return `true`.
- **Media Integrity API is disabled** (`WebSettingsCompat.setWebViewMediaIntegrityApiStatus(…, DISABLED)`). Phase 2 finding (S1): WebView 133 exposes `window.android.webview` to every page, and by default its token provider calls Play Integrity for the page. It is not an app bridge, but it is a page-reachable channel to a Google service, which INV-11 does not allow by default. With the setting, the object remains visible but answers "API disabled by application"; S1 asserts exactly that.
- **Attribution registration and enterprise sign-in links are off** (`setAttributionRegistrationBehavior(…, DISABLED)`, `setEnterpriseAuthenticationAppLinkPolicyEnabled(false)`, where the engine supports them). Pages cannot register ad attribution with the system's Measurement API, which would keep it outside the browser app's data and so past the wipe; and a device policy cannot let sign-in links open another app past the core's block on automatic external-app links. Both are settings only; no test observes their effect (the emulators have no Measurement API data and no device policy).
- **No autofill, no saved form data** (§10.7): the WebView describes no page to autofill, accepts no fill, and keeps no form data (`saveFormData = false`).
- `android.webkit.WebView.MetricsOptOut` is set in the manifest. The minimum WebView major version is 100, a release parameter reviewed against Chromium's security releases.
- **WebRTC** stays available to pages, but with the network lock its UDP has no route (A8: STUN to a private address was dropped, and the only host candidate a page sees is the VPN's own address, not the device's). In reduced mode it can reach the LAN and expose the local address; the trusted UI says so.
- **Safe Browsing** is a disclosed onboarding choice. It works by matching URL hash prefixes in Google Play services and can send prefixes to Google. If the user enables it, Local mode's claim (INV-11) states this explicitly.

### 8.5 Downloads **[PoC A3]**

`DownloadListener` supplies the URL, user agent, Content-Disposition, and MIME type. The browser sends `submit_download { url, cookie header for that URL only, user agent, referer }` to the core. The core performs the fetch under INV-13 and writes into session quarantine.

**Known unsupported in V1:** POST-generated responses, `blob:` and `data:` downloads, and single-use URLs already consumed by the engine. These show "this download cannot be captured safely". Rift adds no JavaScript bridge to support them.

PoC A3 (API 30 and 36) measured this. GET, Content-Disposition, redirect and cookie-gated downloads reach the listener, and the core's re-fetch returns the same bytes. A POST form response reaches the listener, but a re-fetch with GET gets HTTP 405, so the core must detect a failed or mismatched re-fetch and show the message above rather than store an error page. `blob:` and `data:` downloads **never call `DownloadListener`**: they fail silently in the engine, and Rift cannot show a message for an event it never sees. The product claim is therefore "Rift captures downloads that arrive at a URL; downloads generated inside the page are not supported." 

**Phase 2 implementation (`rift-core::download`).**
- HTTP client: `ureq` 3.4 without default features, with `rustls` (ring) and the bundled Mozilla roots (`webpki-roots`). It is blocking and small, and it lets Rift resolve names itself: a resolver wrapper runs the destination check (INV-13) on every address of every hop, so a redirect or DNS answer to a private address is refused before connecting. Redirects are followed by Rift (at most 10). The bundled roots mean Rift does not trust user-installed CAs for its own fetches; the cost is that root updates ship with Rift releases. `rustls-platform-verifier` remains the alternative if that proves wrong.
- The cookie header from the browser is sent only to the origin it was read for, never after a cross-origin redirect.
- The byte limit is applied to the stream, whatever `Content-Length` says. Reset sets a cancel flag that the transfer checks between chunks.
- Local and private destinations need the user's explicit exception, which applies to one host name for one session only (another name for the same address is still refused).
- Session quota: space is reserved before the transfer and the unused part released afterwards.

### 8.6 Isolated worker service **[PoC A4–A6]**

- The main process binds `WorkerService` (`BIND_AUTO_CREATE`; `bindIsolatedService` with a per-document instance name).
- It passes the request bytes, input `ParcelFileDescriptor` (read-only, seekable, RAM-backed), and an output `SharedMemory` region.
- PDF: platform `PdfRenderer` inside the service if PoC A4 passes on API 30–36. Otherwise bundled PDFium, the same as Linux.
- After a result arrives, the controller copies the validated pixels into a `Bitmap` and unbinds. The worker process is retired after the document closes.
- **What `isolated_app` does not deny (PoC A6).** The worker cannot open app files or external storage, create `AF_INET` sockets, or reach the clipboard. It **can** create `AF_UNIX` sockets and map executable memory. `pulley` itself needs neither, but ART's JIT in the same process needs executable memory, so a process-wide filter denying `PROT_EXEC` would break the runtime. The candidate hardening for Phase 2 is a seccomp filter installed by the native library on the thread that runs the parser only (no TSYNC), denying `socket`, executable mappings, `execve` and `ptrace`. It is weaker than the Linux worker's: threads share one address space, so code that has taken over the parser thread can still corrupt the others. It is adopted only if it is measured not to break ART, and is reported as defence in depth, not as a boundary.
- **Deadlines:** the isolated process runs under a different UID, and the app's `kill(2)` on it fails with `EPERM` (Phase 0 lifecycle test). The worker therefore enforces its own scan timeout (`Deadline::InProcess`, §7.3), which fired on time under Pulley. As the backstop, the controller unbinds after the deadline: Android then ends the isolated process within milliseconds, even mid-scan, and the controller's pending call fails with `DeadObjectException`.
- **Phase 2 implementation.**
  - One worker instance per preview (`bindIsolatedService`; instance names may contain only letters, digits and `_`).
  - Before any input is sent, the controller checks that the component is declared `FLAG_ISOLATED_PROCESS` and not exported, and that the worker's Hello reply reports a seccomp filter. Either failure disables previews; there is no in-process fallback (S7).
  - The input is a sealed memfd; the output is a `SharedMemory` region the controller creates (2048 × 2048 × 4 bytes, the protocol limit).
  - Requests and replies are `rift-protocol` frames. `rift-ffi`'s `PreviewJob` validates each reply against its request (job, generation, type, bitmap box) and against the region size.
  - The controller unbinds the worker before copying pixels, so nothing can race the copy, and treats the RGBA as untrusted data drawn into a fresh `Bitmap`.
  - Deadlines: 2 s for Hello, 12 s for rendering. Measured end-to-end preview time, including worker start, is 36–204 ms on the API 36 emulator.
  - Observed on the API 36 emulator: workers forked from the app zygote run as `u0_iN` with `Seccomp: 2` and `NoNewPrivs: 1`; app files are not even visible (ENOENT); `socket(AF_INET)` fails with `EPERM`; `AF_UNIX` sockets can still be created.
  - **Parser-thread filter (done).** `rift-worker-ffi` installs a seccomp filter (seccompiler, no TSYNC) on the binder thread that handles the render request, before it reads input. It denies `socket`, `socketpair`, `connect`, `execve(at)`, `ptrace`, `process_vm_readv/writev`, and `mmap`/`mprotect`/`pkey_mprotect` with `PROT_EXEC`, with EPERM. If it cannot be installed, the job fails. Measured: on the filtered thread AF_UNIX sockets and executable mappings fail with EPERM, while the rest of the process (ART) is unaffected. PdfRenderer loads PDFium lazily, which maps executable code, so the worker first renders a built-in one-page PDF and only then installs the filter (Phase 2 finding). This remains defence in depth, not a boundary (see above).
- **Cold start:** `useAppZygote` with the native library preloaded in the app zygote is required. Without it the median cold start on the API 36 emulator was 304 ms (budget 300 ms); with it, 45 ms (157 ms for the first worker, which also starts the zygote).

### 8.7 Keys

Rift holds no long-lived user keys and asks for no passphrase. Each session's quarantine is sealed to an age X25519 key generated in memory when the session starts and dropped at reset, before the session's files are deleted (§15). The only persistent keys are the threat database's trusted TUF root, which ships in the APK, and the APK signing keys, which never enter the repository.

Versions 2.0–2.2 also had a vault key in Android Keystore (auth-bound, StrongBox or TEE) and passphrase wrappings with a fixed scrypt factor; both went with the vault in 2.3. A vault left by an earlier build is deleted at start-up: its files, its lock settings and its Keystore entry.

### 8.8 Network lock **[PoC A8]**

The browser APK needs `INTERNET` for WebView to work at all, so its network has to be bounded from outside it. Two mechanisms, one for each way around the other:

- **Egress proxy (controller, `rift-core::egress`).** An HTTP proxy on `127.0.0.1` with a random port, a 256-bit token and a random realm per session. It accepts only `CONNECT host:port` (HTTPS, WebSockets) and absolute `http://` requests with a bounded head (16 KiB, 100 headers), resolves each name once, refuses the connection if any answer is non-public unless the user allowed that exact host name for the session (INV-13), and connects only to the addresses it checked. It does not decrypt TLS. Every refusal is kept for the trusted UI. Reset stops it, which closes every tunnel.
- **VPN for the browser UID (controller, `NetworkLockService`).** `VpnService.Builder` with routes `0.0.0.0/0` and `::/0`, a DNS server inside the tun's own range, and `addAllowedApplication(org.simulationrift.browser)` only, so no other app (Rift's controller included) is affected. The controller reads the tun and drops every packet, counting them for diagnostics. It forwards nothing, so there is no userspace TCP/IP stack in the trusted core. Loopback traffic is not routed through a VPN, which is why the proxy keeps working.

Without the VPN a proxy is not a boundary (A8 finding 15): WebRTC sends UDP around it, Chromium bypasses it for loopback unless told otherwise, and escaped native code ignores it. Without the proxy the VPN would allow nothing. Together, a page reaches only public addresses (or the user's exceptions) through a channel the controller checks, and escaped browser code reaches only loopback.

**Lifecycle.** The lock is established before the browser is started for a session, and the browser confirms its default network is the VPN before loading a page. If the VPN is revoked (another VPN app started, or the user turned it off), the controller ends the session and wipes the browser (S28). Consent is the system's one-time VPN dialog. Only one VPN can run on a device: a user who needs another VPN, or has one set as always-on, cannot have the lock. Such a user can choose **reduced isolation** for one session: proxy only, with a persistent label in the trusted bar saying that WebRTC can reach the local network and that escaped code is not network-bounded. There is no silent fallback.

**Switch (2.5).** The home screen's Protection card has a **Network lock** switch, on by default, for a user who needs another VPN all the time. Off is kept across launches (`files/rift/network-lock-off`, outside the session's data), stops the VPN, ends the current session, and every session after it runs with reduced isolation, labelled as above; pages still go only through the proxy. On deletes the file, starts the lock (asking for consent if needed) and ends the session again, so no session changes its isolation while it runs. Android stays bound to a VPN service while its tun is open, so off is sent to the service, which closes the tun itself (`stopService` alone left the VPN up; S28c found it). Tested by S28c.

**No browser, no lock.** The lock is not started while the browser app is not installed (the first launch, §8.10): Android would set up a VPN that applies to no app, and the home screen would have shown the lock as on. It starts once the install succeeds.

**What it does not do.** It does not filter content or hide traffic from the network (the update host and sites see the device's address as usual). It does not see inside HTTPS. It does not stop a page from reaching public addresses: that is browsing.

### 8.9 Extra isolation (Shizuku or root, optional) (2.5)

An app cannot change another app's app-ops or the kernel's firewall; shell and root can. A user who runs [Shizuku](https://shizuku.rikka.app) (started with adb, or with root) or Sui (a Magisk module) can turn on **Extra isolation** on the home screen. It is off by default, and Rift without it is as described everywhere else in this document.

- **Helper.** Shizuku starts `HardeningService` from Rift's APK in a process of its own (`org.simulationrift.app:hardening`) as shell (uid 2000) or root (uid 0), after the user allows Rift in Shizuku's own prompt. Rift's app process never holds these rights. The helper's interface (`IHardening.aidl`) has four operations, all on the browser app only, and answers the controller's UID only. It runs fixed Android tools (`cmd appops`, `pm`, `iptables`, `ip6tables`) with fixed arguments: the browser's package name and two numbers it checks (an app UID in the controller's user, a port from 1024). Nothing goes through a shell. Every change is read back before the home screen shows it as in effect; a failure is shown, and Rift then works as it does without the helper. Shizuku's library (`dev.rikka.shizuku:api`, `provider`, MIT) adds `ShizukuProvider`, exported under `INTERACT_ACROSS_USERS_FULL`, which only the system, shell and root hold, and a request for `moe.shizuku.manager.permission.API_V23`: Shizuku sends its binder only to apps that request it. That permission is Shizuku's own, exists only while Shizuku is installed, is granted only through Shizuku's prompt, and gives no access to the device; s02 allows it by name and no other non-platform permission. With the switch on, Rift asks through Shizuku's prompt once; after a denial Shizuku does not ask again, and the home screen says to allow Rift in the Shizuku app.
- **Clipboard (shell or root).** `READ_CLIPBOARD` and `WRITE_CLIPBOARD` set to `ignore` for the browser app: Android hands it an empty clipboard and drops its writes, whatever the engine or escaped code does. This closes the gap in §10.6. (`deny` would crash WebView, which reads the clipboard's description when its window gains focus.) Turning extra isolation off sets them back to `allow`, their default; `default` would store a mode the clipboard service also refuses. Copy and paste inside Rift's browser stop working while it is on.
- **Wipe (shell or root).** At each reset the controller has Android clear the browser app through the helper (`pm clear`) instead of asking the browser's session service to, so the wipe no longer needs the browser's cooperation. The checks after it are unchanged (§15): the system's data-cleared broadcast, a new process, no files. If the helper fails, the reset asks the browser as before.
- **Firewall (root).** A chain `rift_browser` in the `filter` table's `OUTPUT`, jumped to first for the browser app's UID: TCP to `127.0.0.1` on the session's proxy port and, while the network lock is on, anything routed into a VPN (`tun+`, the lock) go on; with the lock switched off (§8.8) a VPN may be the user's own, which would carry the browser past the proxy, so nothing goes into one; everything else is refused (TCP reset, ICMP unreachable), IPv4 and IPv6. It is rewritten for each session's port as the browser registers, before the browser is given the proxy. This closes the loopback gap (§24): escaped browser code can no longer reach other apps' local servers. And because packets that do not enter a VPN are refused, the browser stays off the network even while the VPN is gone. The rules do not survive a reboot. With a non-root Shizuku the home screen says this measure needs root.

With the lock off, the firewall is what keeps the browser off the network (Z1 checks that it cannot reach the host's address, and still reaches its proxy). The helper ends with Rift's process (`daemon(false)`). Shizuku started with adb must be started again after each reboot; until then the clipboard setting stays (app-ops persist), and the home screen says the helper is not running. Turning extra isolation off while the helper is away leaves its changes until it runs again, when Rift undoes them; the home screen says so. Tested by Z1 on API 34 (Shizuku as shell) and API 35 (Shizuku as root). Z1 needs Shizuku running and allowed, so the CI suites skip it.

### 8.10 One file to install (2.5)

The browser has to be a separate app with its own UID (ADR-04, §8.3), and Android installs one app per APK. So that the user installs one file, the controller's APK carries the browser's as an asset (`browser/rift-browser.apk`, about 2 MB in a release build), and installs it itself:

- **When.** Before each session Rift compares the SHA-256 of the APK it carries with the installed browser's. Not installed, or different (Rift was updated), and the home screen shows a setup card instead of a session: "Install" (or "Update"). Check works meanwhile; browsing does not.
- **How.** Android's "install unknown apps" permission for Rift (`REQUEST_INSTALL_PACKAGES`); without it, the card opens that setting, and the install continues on return. Rift copies the asset to its cache and checks it before installing: the package is `org.simulationrift.browser` and its signing certificates are exactly Rift's own. It is installed with a `PackageInstaller` session, and Android shows its own confirmation; on API 31+ an update of a browser Rift installed needs none. The result comes back through an explicit, unexported broadcast. Android checks again that an update is signed like the installed app.
- **Then.** The network lock starts (§8.8), and the first session begins.

Build: a debug build carries the debug browser (`:browser:assembleDebug`). A release build needs the browser signed with the release key first, passed as `-Prift.signedBrowserApk=<path>`; without it the build stops, so no release carries an unsigned or differently signed browser. Tested on API 34 by hand: the setup card, the setting, Android's confirmation, the browser installed, wiped, and session 1 locked with the VPN covering the browser's UID. The suites install the browser with adb from the same build, so the hashes match.

## 9. Linux platform

> **On the to-do list; not supported now (2.5).** Android comes first and Linux is not a release target. Its code stays, but it is no longer built or tested on each push (the `linux-app` workflow runs by hand only), so it may not build against the current core until it is picked up. It would follow the same scope (no vault since 2.3). Before 2.5 it was kept building and passing.
>
> **Revised 21 Oct 2026 (v2.2).** The Linux app uses Qt, not GTK4 and WebKitGTK, and is built last, after Android (§22). The reviewed v2.0 GTK4 design is in this file's history (v2.1, commit 2040c5c). The evidence for this section is PoCs Q1–Q4 in [phase-5-qt-design.md](reports/phase-5-qt-design.md), which also has the process and message details.

### 9.1 Distribution

**Flatpak first**, on the KDE runtime 6.10 with Flathub's `io.qt.qtwebengine.BaseApp` 6.10 (Freedesktop SDK 25.08), which the runtime's and BaseApp's maintainers keep patched. The declared test baselines are current Fedora Workstation and Ubuntu LTS, both with Flathub. Native packages are post-V1.

Why: distributions ship Qt WebEngine at different versions and with different sandbox setups. Ubuntu 23.10+ restricts unprivileged user namespaces through AppArmor [R13]. The BaseApp spawns renderers as sandboxed Flatpak instances through the portal, which works without user namespaces of the app's own (Q1). Flatpak gives one tested runtime. The release build uses the SDK's Rust extension, so the workspace's `rust-version` is that compiler's (1.98, Q3).

### 9.2 Browser

- **Engine.** Qt WebEngine Widgets 6.10 (Chromium-based), driven from a thin C++ layer called from Rust through cxx. One off-the-record `QWebEngineProfile` per session, in a browser host process that ends at every reset.
- **Browser host in a no-network sub-sandbox [PoC Q2].** The controller starts the browser host with `flatpak-spawn --sandbox --no-network`, sharing only the display and the (filtered) session bus. The GPU is not shared (the app renders in software), and the host's only files are its own state directory, which disposal deletes. The host has its own network namespace with only loopback, and no access to the app's data. Qt WebEngine's network service runs inside the browser host. A process the host spawns through the portal has no network either (Q2).
- **Network lock (INV-14 on Linux) [PoC Q2].** Qt's application proxy points at a forwarder on the browser host's own loopback. The forwarder passes each connection to the controller over the session channel (`SCM_RIGHTS`). The controller serves it with `ForwardedEgress`, which applies the same checks as Android's proxy but has no listener and asks for no token: the socketpair authenticates the browser host. Escaped code in the browser host or a renderer reaches only what the proxy lets through, not even the host's loopback. This is stronger than Android, where loopback is shared.
- **Session channel.** One `SOCK_SEQPACKET` socketpair, given to the browser host as its stdin. It carries postcard messages for navigation decisions, renderer reports, download hand-offs and forwarded connections.
- **The renderer sandbox must be active, not just configured (INV-7) [PoC Q1].**
  - Every renderer runs in a portal-spawned sandbox instance with Chromium's seccomp-bpf filter on top of Flatpak's, `NoNewPrivs`, and mount, pid, IPC and network namespaces of its own.
  - The browser host can see its renderers (Q1, Q2). Before a renderer's page is shown, it checks that renderer: more seccomp filters than its own, `NoNewPrivs: 1`, and mount and pid namespaces of its own. It reports the result to the controller, which ends the session on a failure.
  - At start it refuses the engine's switches: `QTWEBENGINE_DISABLE_SANDBOX`, `QTWEBENGINE_CHROMIUM_FLAGS`, `--no-sandbox` and `--single-process`. With the sandbox disabled, a renderer has only Flatpak's filter and no namespaces of its own, which the check tells apart (Q1's negative control).
  - Renderers share the app's user namespace. Their network namespace is the empty one of the sub-sandbox (Q1, Q2).
- **Permission requests** (`QWebEnginePage::permissionRequested`): deny all, including camera, microphone, location, notifications, screen capture and clipboard read.
- **Downloads:** `QWebEngineProfile::downloadRequested` is refused, and the URL goes to the core's checked transfer, as on Android.
- **Navigation:** `QWebEnginePage::acceptNavigationRequest` asks the controller synchronously, and the controller decides with the shared policy (§10). The browser host draws Rift's toolbar and interstitials from the controller's escaped facts.
- **Known limits.** Qt WebEngine lags Chrome. Its Chromium is older, with security fixes backported, so a minimum Qt WebEngine patch release is a release parameter. The BaseApp is a community build. `allow-dbus` gives the browser host the same filtered session bus as the app, so the portals the app may call are part of the browser host's surface.

### 9.3 Workers **[PoC L2]**

The controller spawns one `rift-worker` per job, directly inside the app's Flatpak sandbox, with a `SOCK_SEQPACKET` socketpair as stdin. stdout goes to `/dev/null`, stderr to the controller's log, and the environment is empty. Before it reads a request, the worker closes every other descriptor, sets rlimits (no new processes, no core, 1 GiB of address space, 30 s of CPU), `no_new_privs`, a Landlock ruleset that handles every filesystem, network and scope right and grants none, and a seccomp allowlist that kills on anything else. `openat` and `sched_getaffinity` fail with `EACCES` instead of killing, because the rule compiler asks for the CPU count through `/proc`. The controller requires the worker's hello to report seccomp, `no_new_privs` and Landlock, and kills it at each step's deadline. Input goes in as a sealed memfd; pixels come back in one (`F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL`), whose seals and size the controller checks before reading, so the content cannot change after validation. The controller encodes the pixels as a PNG for the UI and decodes nothing untrusted itself.

If Landlock or seccomp is unavailable, preview and scanning are disabled. Rift never runs a parser unconfined and never asks users to weaken system security.

Rift on Linux scans and previews images and text; PDF files are not previewed, as the worker has no PDF renderer there.

Bubblewrap is not used for workers. It needs user namespaces, which are blocked inside Flatpak and restricted on Ubuntu, and a seccomp allowlist is the stronger control for fd-only workers anyway. `flatpak-spawn --sandbox --no-network` may be added later as an extra layer.

### 9.4 Nothing kept

As on Android, nothing a session held is kept after it ends. The vault of 2.2 (passphrase only on Linux) is removed with its module, its QML and its end-to-end steps.

## 10. Rift Browser

### 10.1 Features

- Address bar, back/forward, reload, the session indicator, Reset, a downloads list, and a protection status chip.
- Trusted controls live outside web content and cannot be covered (INV-6). On Android the bar is drawn above the engine's area, which is clipped to its bounds: an engine that has not drawn a page yet fills its whole clip, and covered the bar until Phase 7 (finding 21). n5 checks that the bar is drawn.
- No password manager, no autofill, no import from other browsers, and no extensions.
- **Tabs (2.5).** The controller's screen has five tabs in a bar at the bottom instead of one long scroll: **Home** (the logo and status, the session card with the address field, the live check and the session's files), **Filters** (§10.9), **Activity** (the weekly summary, §10.8), **Security** (the network lock, extra isolation, the threat database and Rift AI) and **About** (who made Rift, what it does and does not do, the versions in this install, the licences). The text below describes the cards, not their place.
- **The controller's home screen (2.3).** One screen, light or dark with the system and in the wallpaper's colours where Android offers them (API 31+), with fixed colours for safe, warning and danger that the wallpaper never changes. From the top: the logo and one word on whether browsing is protected now; the session card with the address field, **Check** and **Open safely**, and "New session" (Check judges the link as Open safely would, without loading anything: the threat database's verdict, the policy's findings, Rift AI's 0–99 score with up to three reasons or "not scored" for the most visited sites, and how long it took; it never says "safe"); the live check (§10.5); the weekly summary (§10.8); the session's files, each with its scan verdict and "View safely", which opens a full-screen viewer (the verdict, then what the isolated worker drew, with pinch to zoom, or the escaped text). A file opened with Rift or shared to it from another app opens straight in the viewer; the protection details, folded unless the network lock needs the user; the threat database; the licences. Nothing on it needs a password.
- **Sharing a link to Rift (2.5).** Rift's one share target (`ShareActivity`, a translucent activity in a task of its own) checks a shared link at once, as Check does, and shows a sheet over the sharing app: the verdict (*Known malicious*, *Rift won't open this*, *Looks dangerous*, *Warning signs* or *No known threats found*, never "safe") with its main reason, **See what's wrong** for every finding and Rift AI's score with what raised it, and **Open safely** unless Rift would refuse the link. Nothing is loaded before Open safely, which hands the link to the home screen to open in a fresh session, where the core checks it again before loading. The sheet is drawn in the activity's own window, not a dialog, so the window guard (§10.7) covers it. A shared file is passed on to the home screen with its read grant and quarantined (§11.1). Links opened with Rift as the browser (`VIEW`) still open directly, checked by the core as every navigation is. Tested by n7, including a picture shared by another app through its grant.

### 10.2 Navigation rules

| Input | Rule |
|---|---|
| `https:` | Allowed, subject to intel and policy. |
| `http:` | Allowed with a "connection not encrypted" warning. Rift's own endpoints never use it. |
| `file:`, `content:`, `javascript:` typed in the address bar | Rejected. |
| `intent:`, `market:`, custom schemes | Never auto-forwarded. V1 shows "external app links are blocked". |
| `blob:`, `data:` in-page | Engine-internal use is allowed. Downloads from these sources are unsupported in V1. |
| Certificate error | Cancelled. There is no click-through in V1. |
| A link from another app (`ACTION_VIEW`, or shared text) | Opened in a new, wiped session if the current one has loaded any page, so links never share a session with pages opened before them. In shared text the first `http(s)://` link is used ("look at this: https://…"), with the defanged spellings of threat reports undone (`hxxps://`, `example[.]com`, `[:]`); text without a link is refused as "not a valid web address". Tested by n5. |
| Any address Rift loads itself (typed, shared, from another app) | Judged and loaded in the form the engine parses (WHATWG URL): see §10.3. |

### 10.3 URL checks and the honest coverage claim

Rift checks user-entered URLs, main-frame navigations that the engine reports, and every download URL and redirect hop that the core fetches.

Every check judges an address as the browser engine reads it. The core first parses it with the WHATWG URL standard (the `url` crate, which Chromium and Qt WebEngine follow), refuses what does not parse as an `http(s)` address, and runs the Safe Browsing canonicalization, the indicator lookup and the heuristics on that serialization. For addresses Rift loads itself, `typed_address` returns that same serialization, so the browser loads exactly what was judged. Until Phase 7 the looser Safe Browsing canonicalization read some addresses differently from the engine: `https://evil.example\@good.example/` was checked as `good.example` and opened as `evil.example`, and a host with spaces passed the check and then loaded nothing (Phase 7 finding 20).

Rift **does not** claim to inspect subresources, WebSockets, WebRTC, service-worker fetches, or POST navigations. WebView's callbacks have documented gaps, and WebRTC data channels can reach local-network addresses without a permission prompt.

Host-level enforcement of all engine traffic through `androidx.webkit.ProxyController` is a Phase 7 investigation. It is not a V1 claim. The diagnostics screen states the actual coverage. **Since architecture 2.1:** the browser app's WebView uses `ProxyController` with the implicit bypass rules removed, and the network lock makes the proxy its only route; x2 measured 0 bytes on real networks for the browser's UID while a page loaded through the proxy ([Phase 7](reports/phase-7.md)). That shows the route, not the destinations, which INV-13's tests cover. **Since Phase 7:** the proxy also checks the destination of every connection the engine makes (subframes, scripts, images, WebSockets, service-worker fetches) against the installed threat database before it resolves the name, and refuses a listed one. For HTTPS it sees only the host, so only host-level indicators can match; for plain HTTP the whole URL is checked. Until then, the navigation check itself had never consulted the installed database (Phase 7 finding 56).

### 10.4 Verdict handling

- **Known malicious:** blocked. A per-navigation "Inspect anyway in restricted session" is offered after a warning. It changes no confinement and grants no permission.
- **Suspicious:** an interstitial in the trusted UI lists the specific heuristic facts.
- **Not flagged:** proceeds and shows the database age. There is never a green "safe" badge.

### 10.5 Live page watch

While a page is open, the trusted UI shows, as it happens, what the page has tried to do and a status for the session. Most of it is built from **enforcement points the page cannot speak through**: native WebView callbacks in the browser app, and the controller's own proxy, network lock, navigation policy and download pipeline. The decoys below add what a page asks of the browser's JavaScript APIs; those reports come from a script running inside the page, so a page can avoid or forge them about itself, but cannot use them to hide what the enforcement points see.

**Decoys (2.5).** A page is never refused outright for a device feature; it is given something made up that works, so a phishing or spying page carries on as if it had won and shows what it was after. Before any page script, in every frame, the browser injects a script (`addDocumentStartJavaScript`, assets/decoys.js) that replaces the engine's functions on their prototypes, disguised as native:

| The page asks for | It gets |
|---|---|
| Camera, screen recording (`getUserMedia`, `getDisplayMedia`) | A live 640×480 video of a dim room with a moving light, drawn on a canvas |
| Microphone | A live track of near-silence with a little hiss |
| The list of cameras and microphones | One made-up camera, microphone and speaker |
| Location (`getCurrentPosition`, `watchPosition`) | A position near one of eight city centres, chosen per session, with jitter |
| Permission states, where the engine has the API (Android's WebView does not) | "granted" for the decoyed features |
| Notifications and push | Permission "granted"; nothing is shown; a push subscription fails as a push-service error |
| The clipboard | Reads find it empty; writes and `execCommand("copy")` report success and change nothing |
| Motion and orientation sensors | Readings of a phone lying still; the real sensors' (trusted) events are stopped before any page listener |
| Battery, vibration | 82 %, charging; vibration reports success and does nothing |
| A file (`<input type=file>`) | A generated photo (JPEG), a one-page PDF or a text note, by what the page accepts, written to the browser app's cache and wiped with it |

Each request is reported once every two seconds per kind over a `WebMessageListener` whose name is random per session and deleted from the page before the page runs; the browser accepts only known kinds and at most 1 KiB, takes the origin from the engine, and forwards it to the core (`ICore.reportDecoy`, checked and bounded again there). The file chooser is reported by the browser itself. The engine's refusals are kept underneath: a page that reaches the engine's own functions (from a frame the script does not cover) is still refused by `onPermissionRequest`, `onGeolocationPermissionsShowPrompt` and Android, and the watch says it asked "past Rift's decoys". Tested by d1 (every decoy answers, the watch lists each, no trusted motion event reaches the page) and s2 (the engine still refuses).

**Limits.** A page that looks closely can tell these are decoys (the video's frames come from a canvas; the timings are not a real device's). A page can post made-up decoy reports about itself. Where the WebView lacks document-start scripts or message listeners, there are no decoys, the engine's refusals apply, and the watch says so.

| What the page tries | Where Rift sees it | What happens |
|---|---|---|
| Open a known-malicious, suspicious or lookalike address; plain HTTP | Navigation policy (core) | Blocked, interstitial, or marked (§10.4) |
| Load anything (a frame, script, image, WebSocket) from a listed host, or a listed plain-HTTP URL | Egress proxy, with the threat database (core) | Refused before the name is resolved (§10.3) |
| Open an address Rift AI rates High | Navigation policy, with Rift AI (core) | Asks before loading, with the score and what stood out (§16) |
| Connect to a host (or plain-HTTP URL) Rift AI rates High | Egress proxy, with Rift AI (core) | Allowed, and noted as a warning (`ai-request`); never refused for it (§16) |
| Get the device's location | Decoys; past them, `onGeolocationPermissionsShowPrompt` (browser) | A made-up location. Past the decoys, denied: the browser app holds no location permission, so Android refuses even if the callback were bypassed |
| Use the camera, microphone or screen | Decoys; past them, `onPermissionRequest` (browser) | A made-up stream. Past the decoys, denied; the browser app holds none of these permissions |
| Use MIDI or protected media | `onPermissionRequest` (browser) | Denied |
| Read or write the clipboard, read the motion sensors or battery, send notifications, vibrate | Decoys (browser) | Made-up answers; nothing real is read or changed |
| Ask for a file from the device (upload) | `onShowFileChooser` (browser) | A made-up file (INV-6) |
| Go fullscreen (which would hide the trusted bar) | `onShowCustomView` (browser) | Refused (INV-6) |
| Open another app (`intent:`, `market:`, custom schemes) | Navigation policy (core) | Blocked |
| Reach the local network, the device itself, or a link-local address | Egress proxy (core) | Refused (INV-13) |
| Send traffic around the proxy (WebRTC, raw sockets, DNS) | Network lock (controller) | Dropped (INV-14) |
| Deliver a file | Download capture (core) | Fetched into encrypted quarantine, scanned in an isolated worker, verdict shown |
| Crash or compromise its renderer | `onRenderProcessGone` (browser) | Session ends and the browser app is wiped (INV-7); the home screen says why |

**Status.** *Danger*: a known-malicious address, request or downloaded file. *Warning*: a request for location, camera, microphone, MIDI or files; a link to another app; a suspicious or lookalike address; an address or connection Rift AI rates High; an attempt on the local network; traffic around the proxy; a suspicious file. *Note*: an unencrypted page and other address notes, a protected-media or fullscreen request, a download, and a file that was not flagged or not fully scanned. With no Danger or Warning the status is *Nothing suspicious seen so far*, shown with what is watched. There is never a "safe" status. The status is the **session's**, not the current page's: what one page did can stay in the session (its storage, a service worker, a compromised renderer), so only a reset clears it.

**Not seen** (the UI says so): most of what scripts do inside the page (fingerprinting, reading what is typed into the page, mining), the content of HTTPS traffic (so path-level indicators match plain HTTP only), and pop-ups (the engine refuses them without a callback). The network lock's own background traffic (router and neighbour discovery, multicast, and the system's DNS and private-DNS checks to the lock's resolver address) is dropped but not reported.

**Channel.** The browser reports what only the engine sees over the signature-checked Binder interface (`ICore.reportAttempt(generation, kind, origin)`: one-way, at most once a second per kind and origin; the core accepts only the current generation's registered browser and a known kind, and caps the origin). The core merges these with its own observations into one bounded log per session (64 kinds of event, repeats counted; a full list makes room for a higher level by dropping a lower one), which the browser's trusted bar polls once a second (`ICore.pageWatch`) and the home screen shows. The core reads its own sources (proxy refusals by sequence number, the lock's drops counted per session) when the log is read, so the browser cannot suppress them. Browser-reported events are only as trustworthy as the browser process: code that escaped the renderer *and* took over the browser process could suppress or forge them, which is why the core's own events and the wipe at reset do not depend on them. Tested by w1.

### 10.6 What stays out of the device

Besides the browser's separate UID, the network lock and the wipe (§8.3, §8.8, §15), the browser window keeps page content out of shared system state where Android allows it:

- **Recents:** both apps' windows disable their recents screenshot (`setRecentsScreenshotEnabled(false)`, API 33+), so page images, and the names and previews of downloaded files, are not stored by the system for the task switcher. Tested by H1 for the browser, which decodes the snapshot Android stores.
- **Keyboard:** every text field asks the keyboard not to learn (`IME_FLAG_NO_PERSONALIZED_LEARNING`): fields in pages (set by the browser's WebView) and Rift's own fields in both apps (set through Compose's `InterceptPlatformTextInput`), so addresses and words typed into a hostile page should not enter the keyboard's dictionary. Keyboards may ignore the flag. Tested by h2.
- **Clipboard:** the decoys (§10.5) answer a page's clipboard API and `execCommand("copy")` without touching the system clipboard. Not closed by default: a page that reaches the engine's own functions (past the decoys), or swaps what the user copies in a `copy` handler, can still write to it after a user gesture; there is no WebView control for it (§24). Extra isolation closes it with Android's own clipboard app-ops (§8.9).

### 10.7 Other apps on the same device

Every window of both apps is set up by one shared guard (`WindowGuard`, in `:bridge`) before it shows anything, against what another installed app can do without exploiting anything:

- **Overlays.** An app allowed to "display over other apps" could draw over Rift's trusted bar, its interstitials or the reduced-isolation choice, and mislabel them. Rift's windows hide every other app's overlay while they are shown (`setHideOverlayWindows`, API 31+, with the normal permission `HIDE_OVERLAY_WINDOWS`); on API 30 a touch that passed through another app's window is dropped instead (`filterTouchesWhenObscured`). Tested by h3: an outsider's overlay covering 97 % of its own window covers 0 % of Rift's home screen and browser in screenshots (97 % of both without the guard).
- **Autofill.** An autofill service is told about every focused field and the form around it, and can fill it or be offered what was typed. Rift has no password manager and no autofill (§10.1). Neither app's views are given to autofill: Compose's text fields are marked as holding no autofill data (`contentDataType = None`), as Compose reports them to autofill itself, and the WebView describes no page to autofill (no virtual structure) and accepts no fill. The engine still tells the system that a page field was focused, so the service learns that Rift's browser is in use and when a field has the focus, but nothing of the page: its address, texts and hints. Tested by h3 with an outsider's autofill service: without these, it was asked about the home screen's address field and the page's sign-in form.
- **Accessibility services.** A service with the accessibility permission can read every window, which is how most Android malware reads screens. On API 34+ both apps' windows are shown only to services that declare themselves tools for users with disabilities (`setAccessibilityDataSensitive`); a tool such as a screen reader still reads everything, and a malicious app can declare itself a tool, which Google Play reviews but the OS does not check. Tested by H4: an outsider's non-tool service reads its own window and nothing of Rift's (it read Rift's home screen without the guard).
- **Screen capture.** Neither window is secure (`FLAG_SECURE`), so that the user can take screenshots of pages and of what Rift found. Until 2.3 the controller's window was secure while the vault was unlocked.

None of this is a boundary against code running as Rift, and on API 30–33 the accessibility protection does not exist.

An "isolated volume" for the browser is not something an ordinary Android app can create: apps cannot mount file systems, and the Android Virtualization Framework's VM permission (`MANAGE_VIRTUAL_MACHINE`) is signature/privileged. The equivalent the platform allows is the browser app's own UID and data directory, which only it can read and which Android deletes at every reset. On Linux (Phase 5) the browser will run in its own namespaces.

### 10.8 Weekly summary

The Activity tab shows the last seven days: threats blocked, dangerous files, warnings and links checked in four tiles, threats, dangerous files and warnings per day in a bar chart (or a plain "nothing dangerous" line when there were none), and the number of files scanned.

- **What is counted.** Every event of the live watch (§10.5) at warning or danger level, the first time it is seen in a session for its subject: a confirmation the user may click through is a *warning*; a known-malicious or suspicious download is a *dangerous file*; anything else Rift stopped (a listed address or request, an app link, a request to the local network, a connection around the proxy, a permission) is a *threat blocked*. *Links checked* counts the core's main-frame decisions; *files scanned* counts verdicts. The same address blocked twice in one session counts once, so these are distinct events, not requests.
- **What is stored.** Counts per local day for 14 days, in `files/rift/stats` (Rift's own state, on the browser disposal's allowlist), written atomically: a header line, then `<epoch day> <count>…`. No address, host, file name or time of day. A damaged line is skipped and logged; a file of another format is not read. A clock set back drops the days it puts in the future.
- **Tested.** `TalliesTest` (JVM): round trip, window, damaged lines, saturation, merging a file read after counting began. On the API 35 emulator, w1's page produced 8 threats blocked, 2 dangerous files, 10 links and 3 files scanned, and the file held only `20747 8 0 2 10 3`.

### 10.9 Content filters (2.5)

Rift blocks ads and trackers and hides cookie banners, pop-ups and sign-in prompts ("Sign in with Google", Facebook's login widgets) in the sealed browser, using the community lists that already do this. **Rift writes no rules of its own**; the user may add some.

- **Lists.** Taken from their upstream projects: EasyList, EasyPrivacy, Fanboy's social and cookie lists (GPL v3 or CC BY-SA 3.0), and uBlock Origin's filters, annoyances, privacy, badware, unbreak and quick-fix lists (GPL v3); Fanboy's annoyances is on offer and off by default. The default set is every list but that one: 217,850 rules in about 7 MB. The lists are **not in the APK**: the Filters tab downloads them when the user taps, through the core's checked fetcher (INV-13), from the lists' own HTTPS addresses, at most 6 MB each. Nothing is fetched by itself (§17), and a fixed set of URLs is requested, so INV-11 holds: no address or file of the user's goes anywhere. Lists are kept in `files/rift/filters/` with the choices (a switch for all filtering, one for each list, the user's rules): they are settings, not browsing data, so a reset leaves them.
- **Engine.** The `adblock` crate (Brave's, MPL-2.0) in `rift-core::filters`, built from the lists in the controller process (measured on a host with the default lists: about 0.2 s to build and 60 MB of process memory, not yet measured on a phone). The browser app has no rule engine and does not load the Rust library (INV-6's neighbour): for each subresource request `shouldInterceptRequest` asks the controller over Binder (`ICore.blockRequest`: the address, the page's address and a request kind) and gets a yes or no, answered in about 10 µs by the engine. A blocked request gets an empty 403. The main frame is never blocked here: addresses are the core's to judge (§10.2). Whether the filters are on is asked before each page starts (`filtersOn`), so a window makes no calls while they are off and a change applies from the next page. (`onPageStarted` is too late: it comes after the page's first subresources, finding 89.)
- **Hiding.** The core returns, for a page's address, style rules it builds itself: one `selector{display:none!important}` per selector, because one bad selector spoils a whole rule. Every selector from a list must pass `safe_selector` (no `{`, `}`, `;`, `@`, `\`, `<`, control character, `url(` or `expression(`; at most 200 bytes), at most 3,000 selectors and 200 kB of CSS are returned, and procedural filters, scriptlets and `:style()` rules are not used. So a list can hide elements but cannot write a rule of its own into a page. The browser injects the rules as a style element when the page is first visible and again when it has loaded; it then reads the page's class names and ids back with a script's return value (at most 1,500 of each, 100 bytes each) and asks for the generic rules that match them (`genericHiding`). That is the only data that flows from a page to the core for this, and no object is exposed to the page: INV-6 is unchanged.
- **What it cannot do.** Lists are untrusted text. They can only take things away from a page; Rift's own checks run first, and the proxy applies INV-13 and the threat database to every connection whatever a list says, so no list can allow anything Rift refuses. A hostile or mistaken list can still hide or break a page, which the user sees and cures by turning it off. A request the engine does not route through `shouldInterceptRequest` (WebSockets, service workers) is not filtered. Skipping a sign-in prompt means hiding or blocking the widget that shows it: Rift does not sign in for anyone, and a login the site needs stays. Filtering does not make a page safe, and the live check (§10.5) does not depend on it. The counts (requests blocked since Rift started; blocked in a window) are shown on the Filters tab and in the browser's bar, and are not kept.
- **Failures.** The engine is native code fed with text from the network and the browser app. A failure inside it (a Rust panic reaches Kotlin as an exception) is caught at the controller's boundary, logged, and the filters do nothing for that call, so it cannot end the session's holder; filtering only takes things away, so doing nothing lets nothing through that Rift's own checks refuse.
- **Tested.** `rift-core::filters` unit tests (host, path and option rules, exceptions, third-party, request kinds, bad addresses, sanitising, bounds), a property test that no list, address or page name makes a panic or a rule that is not one plain selector, and the `filters` fuzz target (682,120 runs in four minutes without a finding; it runs for a minute on every push with the others). F1 on API 34 and 35 with the user's own rules (no list is downloaded in a suite): an ad script is blocked, an element is hidden by a site rule and a sign-in pop-up by a generic one, the article stays, the bar counts the blocked request; with filtering off the same page shows everything. By hand on API 34 with the ten real lists: the lists downloaded and loaded (217,850 rules), and a news site loaded with 12 requests blocked.

### 10.10 Link tools in Check (2.5)

Check (and the share sheet, §10.1) has tools for the link it judged, after URLCheck's: edit, clean, quick fixes, find where it goes, copy, share and open in another app. Each new address is checked again in place, with **Undo** back to the one before. Nothing is opened in Rift by any of them.

- **Cleaning.** Tracking parameters are taken off and redirect links (a search engine's `/url?q=…`, a mail tracker's) unwrapped with the ClearURLs project's rules (LGPL v3). **Rift writes no rules**, and the file is **not in the APK**: the Filters tab downloads `data.minify.json` from ClearURLs' own address when the user taps, through the core's checked fetcher, and keeps it in `files/rift/clean/` with the filter lists (a setting; a reset leaves it). `rift-core::clean` compiles it with the linear-time `regex` crate under bounds (2 MiB of text, 2,000 providers, 20,000 patterns of at most 2,000 characters each, 256 KiB per compiled pattern); a pattern the engine cannot compile is left out and counted. Parameter rules match whole names, case-insensitively, as ClearURLs does; a raw rule applies only if it leaves the site unchanged, and at most five redirect links are unwrapped. Kept parameters keep their spelling. The removed names and unwrapped addresses are escaped for display. The clean link is offered with what was removed ("Use the clean link"); it is never used without that tap. Measured on a host with the real file (206 providers, none left out): 20 ms to compile, 25–230 µs per link.
- **Quick fixes.** HTTPS for an `http` link, and the link without its query and fragment.
- **Where it goes.** On tap, the core follows the link's redirects without loading a page (`download::trace`): each hop is a GET without cookies, the body is not read, at most the redirect limit of hops, 10 s per connection and 30 s in all. **Each hop is checked as Check checks a link before it is contacted**, threat database and Rift AI included; a hop Rift would not open (listed, or not a web address) ends the trace there, uncontacted, and a hop that leaves the web (an app link) is shown and not followed. INV-13 applies to every hop, so a link that leads to the phone's own network is refused. The verdict at the top is the most serious of the link's and its hops' ("Where it goes: …" names the hop), so a clean-looking short link that leads to a listed or High-scored page is shown as that page. Tracing contacts the link's servers from the phone, which can tell a sender the link was followed or use up a one-time link: the screen says so before the tap, and it never runs by itself (§17).
- **Leaving Rift.** Copy and Share hand over the address shown. Open in another app needs a second tap after a warning that Rift's checks, sealed browser and network lock stop applying there; Rift's own activities are left out of the chooser.
- **Not done.** VirusTotal and a log of past checks, which URLCheck has: the first sends links to a third party (INV-11), the second would keep what the user checked. Unshortening services are not used: the trace asks the link's own servers.
- **Tested.** `rift-core::clean` unit tests and a property test that cleaning never changes the site; the `link_clean` fuzz target; `download` trace tests (hops and statuses, a screened hop not contacted, private addresses refused, an app link, the hop limit); `rift-ffi` tests that every hop is checked and a listed hop stops the trace. V3 on API 34: a wrapped link is unwrapped and cleaned, the clean link checked and undone, the quick fixes, the warning before another app, the same in the share sheet, a listed hop and a loopback link not contacted.

## 11. Rift Files: intake, quarantine, preview

### 11.1 Object lifecycle

```text
RECEIVING ─▶ COMMITTED(immutable, sha256) ─▶ SCANNING ─▶ SCANNED(verdict bound to versions)
    │ abort/limit                                   │
    ▼                                               ├─▶ PREVIEW (worker, on request)
 DISCARDED                                          └─▶ DELETE (at reset, with the session)
```

- Storage names are app-generated `ObjectId`s. Server-supplied filenames are only display metadata, normalized to remove control characters, path separators, bidi overrides, and excessive length.
- Limits are enforced on the stream: 100 MiB per object and 500 MiB per session by default. Space is reserved before starting.
- The hash covers the final stored plaintext. Commit happens only after a complete transfer.
- **Intake from other apps (Android, 2.3).** The controller reads only the URI it was granted, through the `ContentResolver`, and streams it in 256 KiB chunks into `Sessions::begin_intake` (rift-ffi `intake.rs`). Nothing is parsed on the way. The file is sealed and limited exactly as a download is (same reservation, 100 MiB limit, commit only when complete, cancelled at reset), then scanned and previewed. URIs whose provider belongs to Rift's own packages are refused, so another app cannot point Rift at Rift's own state (a confused deputy). The name and type the other app gives are display metadata only. The source is shown as "another app": the sender cannot be verified. Each intake reads on its own thread, so a provider that never finishes holds up only that file, never downloads. A file still arriving at reset is discarded.
- Quarantine files are encrypted with a **per-session ephemeral age identity** held only in memory. When a session is destroyed or the app is killed, the key is gone and leftover ciphertext is unreadable (crypto-shredding). The cost is that quarantine content does not survive a process kill. That is deliberate for disposable sessions.

### 11.2 Supported types

| Type | V1 treatment |
|---|---|
| PDF | Confined page rendering, one page per request, ≤ 4 Mpx output. No forms, attachments, JavaScript, or link launching. |
| PNG / JPEG / WebP | Confined decoding with dimension and allocation limits. |
| Text, logs, Markdown, HTML, SVG | Bounded UTF-8 (or lossy) **plain text**, never interpreted. Decoding happens in the worker or in the core under strict limits. Phase 2: in the core (`rift-core::text::plain_text`), first 64 KiB, after the object's hash is verified; line breaks and tabs kept, other control, bidi and invisible characters shown as `\u{…}`; a NUL byte in the first 8 KiB means binary. |
| Executables, APK, scripts, Office, archives, encrypted files, other | Stored, hashed, scanned on outer bytes, metadata shown. Disclosed as "preview not supported" or "contents not inspected". |

### 11.3 Preview handoff **[PoC A7/L3]**

The core decrypts the object into a RAM-backed fd: `memfd_create` on both platforms (`Os.memfd_create` on Android, API 30+), sealed against writing, growing and shrinking before it is passed (PoC A7). The fd is seekable, as `PdfRenderer` requires, and is closed when the job ends. On Android the decrypted copy also exists briefly in the controller's memory (at most 32 MiB; larger files are not previewed). S19 searches the app's data directory for plaintext after previews and finds none.

**Fallback if the Android PoC fails:** an unlinked-after-open file in `noBackupFilesDir`. This would be documented as a reduction of INV-9 rather than done silently.

### 11.4 No export

Files never leave Rift: they are viewed inside it (§11.3) and deleted with the session. Until 2.3 a file kept in the vault could be exported, after a warning, through SAF or the file portal. Reconstructed "safe PDF" export, Dangerzone-style, remains possible future work [R24].

## 12. Rift Scanner

### 12.1 Pipeline

1. **During transfer (core):** SHA-256 and magic-byte type. Extension mismatch is flagged.
2. **Hash lookup (core):** against the snapshot's file-hash table.
3. **Rules (worker):** YARA-X with the curated pack rules, bounded by deadline (15 s default) and match count.
4. **Result:** findings, coverage, and versions. The cache key is `(sha256, yara-x version, snapshot id, policy version)`.

A new snapshot invalidates cached conclusions as *current*. They remain visible as history. Rescans happen on request.

### 12.2 URL heuristics (V1, explainable, never "known malicious")

- IP-literal host. Userinfo in the URL (`user@host`). Non-default port.
- Punycode or mixed-script labels (UTS #39), and a confusable skeleton that equals a protected domain from the pack's brand list while the actual domain differs (`unicode-security` crate).
- Excessive subdomain depth, or an excessive length outlier.
- A known shortener host: "destination unknown until followed". No network expansion is done.
- No TLS.

Each heuristic yields a *Suspicious* flag naming the measured fact. Thresholds are pack data, not hard-coded.

### 12.3 Result vocabulary

| Status | Meaning | UI |
|---|---|---|
| Known malicious | A high-confidence indicator or rule matched | Block normal open; show the evidence; keep in quarantine |
| Suspicious | A heuristic or lower-confidence rule matched | Explain the measured facts |
| Not flagged | All configured checks completed with no match | Show coverage and database age; isolation unchanged |
| Not fully scanned | A check failed, timed out, or does not support the content | Name the missing coverage |
| Pending | Checks are still running | Progress; content stays in quarantine |

Each finding carries: source, rule or indicator ID, object hash, engine version, snapshot ID, timestamp, and limitations. There is no "100% safe" state.

## 13. Threat intelligence and signed updates

### 13.1 Snapshot store

- Each snapshot is a directory `intel/snapshots/<pack digest>/` with a pointer file `intel/current`. The pointer is replaced by write + fsync + rename. Directories are named by the SHA-256 over the pack's files, never by anything the pack says about itself. Every load validates the pack again and compares its digest with the directory name. Installs are staged in `intel/staging/` and moved into place before the pointer changes; leftovers are removed when the store opens. One previous snapshot is kept (Phase 3: `rift-core::snapshot`).
- A pack is exactly four files: `metadata.json`, `url-hashes.bin`, `file-hashes.bin` and `rules.yar` (`rift_core::pack::FILES`). This is also the TUF staging allowlist.
- **URL table:** sorted array of `(sha256(expression)[..16], meta_idx: u32)`. Expressions follow the Safe Browsing canonicalization and host-suffix × path-prefix scheme [R16]. A host-only expression is a domain-scoped indicator; a host+path expression is a path-scoped one.
- **File table:** sorted array of `(sha256[32], meta_idx: u32)`.
- **Binary format:** a header with magic `RIFTIDX1`, version, record size, and count. On install the store validates that `len == header + count × size` and that records are strictly sorted, both in O(n). The table is memory-mapped and binary-searched. Malicious URLs are not stored in cleartext.
- **Metadata:** JSON of at most 1 MiB with a strict schema: sources, snapshot times, coverage window, and notices.
- **Rules:** YARA source text (bounded size), compiled inside the worker.
- No SQLite, executable content, native libraries, scripts, pickles, or serialized engine artifacts are accepted from packs.

### 13.2 TUF

- Client: `tough` ≥ 0.24.0. This is above the 2026 advisory floors of 0.22.0 [R18].
- The initial root is embedded in the app. Persisted state holds the trusted root and versions. Rift saves the newest verified root itself (atomically) and starts each update from the newer of it and the embedded root; tough never reads back its own copy, so starting from the embedded root would let a mirror undo a rotation. Key policy and response plan: [key-policy.md](reports/key-policy.md).
- Roles: root and targets keys offline; snapshot and timestamp keys on the maintainer machine.
- Expiry: timestamp 7 d, snapshot 14 d, targets 90 d, root 365 d.
- Offline import is a TUF repository directory or archive verified through a file transport, using exactly the same code path. On Android the user chooses the repository folder in the system picker (no lasting access is kept); the controller copies only plain files of `metadata/` and `targets/`, within count and size bounds, into Rift's own storage, and verifies the copy.
- Online updates use the same code path with one other transport: rift-core's checked fetcher (INV-13 resolver, per-hop redirects, bounded bodies, no cookies), so updates add no HTTP or TLS stack. The update address is fixed at build time (an https base with `metadata/` and `targets/`); the production root is embedded the same way. A build without a root cannot install updates and says so. Refusals carry a reason (signature, rollback, expired, tampered, too large, damaged, unreadable, unreachable, rules rejected) that the UI shows as one sentence; the full error goes to the log.
- **Staging paths are never derived from repository target names** (Phase 0 finding, X2). `tough::TargetName` normalizes `../../x` to `x` instead of rejecting it, and keeps absolute names absolute, so `dir.join(name.resolved())` can escape. Rift stages only names from a fixed allowlist of pack files, and only when the raw name is already in normal form.
- Metadata size limits are set far below tough's defaults: timestamp 16 KiB, snapshot 64 KiB, targets 1 MiB, root 64 KiB.
- Flow: fetch bounded metadata → verify signatures, thresholds, versions, expiry, hashes, and lengths → download targets into staging → validate the binary tables and JSON schema → compile rules in a worker (smoke test) → run fixture lookups → atomic pointer swap → retain the previous snapshot until no job references it.
- Scans already in progress stay pinned to their starting snapshot.
- If the installed data has expired and no update is possible, Rift keeps using it offline with a prominent **stale** warning. Clock problems are surfaced to the user; the expiry check is never bypassed. A device clock more than an hour before the installed database's creation time is shown as a clock problem; an update refused as expired says that the clock may be wrong.

### 13.3 Sources and licensing

| Source | Data | Status |
|---|---|---|
| First-party demo pack | Harmless test indicators and rules (EICAR-style fixtures) | V1. Labelled "DEMO — not real coverage". |
| abuse.ch URLhaus / MalwareBazaar | URL and hash indicators | **Blocked for redistribution.** The Nov 2025 terms grant free access for not-for-profit use, route commercial use through Spamhaus, and require consent for adaptation or derived works [R17]. Options: written permission, or a direct adapter using the user's own auth key. |
| OpenPhish community | Phishing URLs | The terms need review before any use. |
| Curated YARA rules (e.g. signature-base) | File patterns | Per-rule license review. Signature-base defaults to DRL 1.1. |
| Google Safe Browsing (via WebView) | Phishing and malware URLs | An engine feature the user can enable (§8.4). It is not part of Rift's packs. |

No shared upstream API secret ships in the app. Scraped data is never substituted for licensed feeds.

## 14. Rift Vault (removed in 2.3)

Versions 2.0–2.2 let the user keep a downloaded file after its session in an encrypted vault: age objects and an HMAC-authenticated index, the identity wrapped by an auth-bound Android Keystore key or a passphrase (scrypt, fixed N = 2^17), an optional recovery passphrase, a lock policy, rescans with the current database, and a warned export. Phase 4 built and tested it on Android and Phase 5 on Linux; that design and its evidence are in this file's history (v2.2) and in the Phase 4 report.

2.3 removes it. Rift is for opening untrusted links and files once, safely; it keeps nothing afterwards, so it has no passphrases, no long-lived keys and no export. What remains of its code is the age sealing of each session's quarantine (`rift-core::seal`, §11.1), which keeps its checks: an object opens only under its session's key, with its recorded size, hash and identity, and truncation, tampering and swapped objects are detected (X1, S18). A vault left by an earlier build is deleted at start-up (§8.7).

## 15. Sessions

```text
CREATING ─▶ ACTIVE ─▶ RESETTING ─▶ DESTROYED
               │           └────▶ CLEANUP_FAILED (shown; retried on next launch)
               └─▶ RECOVERY_PENDING (marker found at launch)
```

- One active session at a time in V1.
- **Generation:** a `u64` persisted in a recovery marker. It changes on every reset, and any result carrying an older generation is rejected.
- **Android reset (v2.1):**
  1. Cancel transfers and retire workers; stop the session's egress proxy, which closes every tunnel.
  2. Drop the session key, which crypto-shreds quarantine.
  3. Ask the browser to finish (best effort), then have its `SessionService` call `clearApplicationUserData()` on the browser app. The system kills every process of the package and deletes all of its data: WebView's directories, `shared_prefs/` (where PoC A2 found `AwOriginVisitLoggerPrefs.xml`), caches, and anything a compromised browser wrote. The controller waits for the binding to die and for the system's `ACTION_PACKAGE_DATA_CLEARED` broadcast for the browser package, which marks the end of the deletion (10 s limit for each, then the reset fails).
  4. Bind a fresh `SessionService` and require its inventory to contain no file at all, in credential- and device-protected storage and the app's external directories (empty directories the platform creates, such as `cache/`, are allowed). A new process id is required. So that this holds, the browser APK removes the `androidx.startup` initializers, which would otherwise write files (such as the profile installer's marker) at every start.
  5. Verify the controller's own inventory against an **allowlist** of Rift's own files, as before: `files/rift/**`, `files/profileInstalled` and, in release builds, `files/profileinstaller_profileWrittenFor_lastUpdateTime.dat`. Since the controller never loads WebView, any WebView state there is a leftover.
  6. Increment the generation.

  The controller cannot inspect the browser's files itself (they belong to another UID), so step 4 trusts the fresh browser process's report. That process runs only the browser APK's code, started after the system deleted everything the old one could have changed. Tests cross-check it from outside with `run-as` (debug builds).
- **Before the first session after a launch,** the browser is wiped in the same way, so a crash, a kill or a lost reset in an earlier run leaves nothing behind.
- **Linux reset:** the same steps, with WebKit's `WebKitNetworkSession` set to ephemeral (`webkit_network_session_new_ephemeral`), which keeps data in memory, and termination of the web process.
- **Recovery on launch:** if the marker says ACTIVE or RESETTING, cleanup completes *before* any new session is presented as fresh **[PoC A2]**.
- Inactivity reset: 15 min by default, configurable. This is best effort under platform scheduling.

## 16. Rift AI

Built in 2.4 (Phase 6). The model, its data, its measured results and how to retrain it are in [rift-ai.md](reports/rift-ai.md).

**What it is.** A logistic-regression model over hashed lexical features of a URL (host n-grams, labels and words; path words, n-grams and shape; query keys; an embedded address), trained offline on public feeds of phishing and malware addresses and on ordinary pages from Common Crawl. It answers in about 2 µs on a computer, and a whole Check takes p95 64 µs on the Android emulator. It looks at the address only, never at the page.

**Advisory only.** It never blocks, grants permissions, changes confinement, overrides a known-malicious hit, or produces a "safe" label. A navigation it rates **High** gets a Confirm (an interstitial before loading: "closely resembles known phishing and malware links… A resemblance, not proof"). **Elevated** adds a note. Low is shown as "nothing it recognises", never as safe. The threat database and the policy decide first. Rift works fully without the model: if the file is missing or fails validation, Rift AI is off and the protection details say why.

**Where it is used.**

| Where | View | What happens at High |
|---|---|---|
| Check (home screen) | Whole address | Score, level, up to three reasons |
| Where it goes (Check, on tap, §10.10) | Every hop's whole address | The verdict names the hop; nothing is opened |
| Navigation (typed, from other apps, in-page main frame) | Whole address | Confirm before loading; the watch records `ai-suspicious` |
| Egress proxy (every connection of the page) | Host only for HTTPS, whole URL for plain HTTP | Allowed and recorded as `ai-request` (warning) |

**Sites and abstention.** Sites follow the Public Suffix List, private section included, so a site on a hosting platform (`someone.workers.dev`) is judged on its own. The model does **not score the 10,000 most visited sites** (Tranco): their real pages and the fakes hosted on them look alike as addresses, and scoring them produced false alarms on `mail.google.com` and `login.microsoftonline.com`. The UI says "not scored", and the threat database still checks them.

**The file.** `url-model.bin`: a 32-byte header (magic, feature schema, bits, scale, bias, thresholds), 2^bits little-endian `i16` weights, the suffix rules as text, and the sorted 64-bit keys of the most visited sites. It is at most 2 MiB, and every field is checked before use (`UrlModel::parse`; damaged files are refused in tests). The app ships it as an asset in 2.4; delivery in a signed pack (§13) is later work. Its SHA-256 appears in the protection details, and `rift-ffi` tests the shipped file's verdicts on fixed addresses.

**Training.** `tools/rift-train` (Rust) shares `urlmodel::for_each_feature` with the app, so training and use cannot disagree. Splits are by site (80/10/10), so the test measures sites the model never saw. The number of passes and the L2 strength are chosen on the validation split (best recall at 0.1% false positives), and thresholds are set there at 0.1% (High) and 1% (Elevated) false positives, averaged over the benign sources; the test split plays no part in either. On never-seen sites the model catches 56–59% of Phishing.Database pages at High and 82% at Elevated or High, and falsely flags 0.07% of ordinary pages at High. A time-separated test (trained on December 2025's links, tested on October 2026's) caught 48% of fakes on new sites at High, so the model is retrained on fresh feeds ([rift-ai.md](reports/rift-ai.md)).

**Learning.** The model learns when it is retrained on fresh feeds, and a new file ships with the app. It never trains on the device or on what the user opens. There is no telemetry (§17). VirusTotal is not used: its terms, a key in the app, and sending users' links to a third party all rule it out.

**Not done.** A time-separated test, and a comparison with Safe Browsing (§24).

## 17. Privacy and network behaviour

| Behaviour | Local Protection (default) |
|---|---|
| URL and file checks | On device |
| Content-specific queries by Rift | None |
| Intelligence updates | Manual. Contacts the configured update host, which sees connection metadata only. |
| Check's "Where it goes" (§10.10) | On tap only: asks each hop's own server for its redirect, without cookies, reading no page. That server sees a request from the phone. |
| Link cleaning rules | Manual download of ClearURLs' file from its own address |
| Offline import | Supported |
| File upload to scanners | Never |
| Engine Safe Browsing | User choice at onboarding; disclosed |
| Analytics and telemetry | None. Diagnostics export is local, redacted, and explicit. |

Online Enhanced Protection (opt-in reputation providers) is a reserved concept. It is not built until a provider with suitable terms exists [R25]. When it is built: it is opt-in per provider; Rift discloses exactly what is sent (hostname, full URL, or hash); and a timeout or rate limit is never treated as clean.

Traffic captures for (a) local scanning, (b) manual update, and (c) ordinary browsing are part of each platform's evidence report.

## 18. Performance budgets

These are targets until measured on the declared reference devices (to be named in the Phase 2 report). No result is claimed before measurement.

| Metric | Target |
|---|---|
| Cold start to interactive home | ≤ 1.0 s |
| New session to first paint (cold, including WebView init and the browser app's start) | ≤ 1.5 s |
| Local URL decision (canonicalize, lookups, heuristics) | p95 ≤ 5 ms |
| Hashing and encryption during transfer | Not the bottleneck at network speed; ≥ 200 MB/s on device |
| Worker cold start (Android, app zygote) | ≤ 300 ms |
| First PDF page (1–5 MB file), image preview | ≤ 1.5 s, ≤ 0.5 s |
| Idle CPU and wakeups | Zero: no services, polling, or schedulers in V1 |
| APK size added by Rift's native code (per ABI) | ≤ 25 MB. Since 2.5 release builds carry arm64 only (Android phones; x86_64 is for emulators): 47.8 MB → 23.2 MB for Rift's APK, the browser's included. Debug builds carry arm64 and x86_64 (`-Prift.abis` chooses). |
| Default intel pack; install time | ≤ 50 MB; ≤ 10 s |
| Worker memory | Linux: hard `RLIMIT_AS` of 512 MiB. Android: bounded by decoder limits and input caps. `RLIMIT_AS` breaks ART, so there is no hard cap there. |

Benchmarks separate engine cost (WebView, WebKit) from Rift's added cost. No security control is removed to improve a benchmark.

## 19. Technology stack

Versions are as of 17 Oct 2026 and are locked by `Cargo.lock` and Gradle catalogs. They are updated deliberately after advisory review.

| Concern | Choice | Version floor |
|---|---|---|
| Shared logic | Rust stable (pinned by `rust-toolchain.toml`) | — |
| Rust↔Kotlin | UniFFI | 0.32 |
| Android UI | Kotlin, Jetpack Compose, AndroidX WebKit; compileSdk 37 (required by Compose BOM 2026.09), targetSdk 36 | latest stable |
| Linux UI | Qt 6.10 (KDE runtime): QML through cxx-qt, Qt WebEngine Widgets for the browser host (§9; decided 20 Oct 2026, PoCs Q1–Q4 21 Oct) | cxx-qt 0.10 (pinned, pre-1.0) |
| Rule engine | `yara-x` with the `pulley` feature (no JIT) | 1.21 |
| PDF | Android `PdfRenderer` (PoC-gated); Linux PDFium via `pdfium-render` | 0.9 |
| Images | `image` (`png`, `zune-jpeg`, `image-webp`) | 0.25 |
| File encryption | `age` | 0.12 (pinned, pre-1.0) |
| Updates | `tough` / `tuftool` | 0.24 / 0.17 |
| Linux confinement | `landlock`, `seccompiler` (Firecracker's BPF compiler) | 0.4 / 0.5 |
| URL | `url`, `idna`, `unicode-security` | — |
| Hashing | `sha2` | — |
| Serialization | `serde`, `postcard`, `serde_json` (bounded) | — |
| Type detection | `infer` | — |
| HTTP for transfers | `ureq` with `rustls` (ring) and `webpki-roots` (§8.5); updates decided in Phase 3 | 3.4 (pinned) |

## 20. Decision record

Each decision lists what was chosen, what was rejected, why, and what would make us revisit it.

| ADR | Decision | Rejected alternatives | Rationale | Revisit if |
|---|---|---|---|---|
| 01 | Android engine: **WebView** | GeckoView; Custom Tabs; Chromium fork | WebView's renderer is always out-of-process and sandboxed on API 30+ [R02] and patched by Google independently of Rift. GeckoView's isolated content processes are opt-in or in progress, and its Android site isolation was shipped then rolled back in Firefox 147 [R04][R05]. GeckoView would also add a large per-ABI payload and make Rift responsible for monthly engine updates. Custom Tabs gives no download control. | GeckoView ships default isolated processes with Fission, *and* download capture (PoC A3) proves unacceptable. |
| 02 | Browser in its own process, disposed of by ending it and deleting all its data (v2.1: in its own app, wiped by the system; ADR-04) | ProfileStore-only disposal | Process death plus deleting the data works on every provider. It also keeps keys out of the escape-reachable process. | — |
| 03 | One rule engine: YARA-X (`pulley`) | libyara on Android plus YARA-X on Linux | One engine means one rule dialect, one test matrix, and a memory-safe implementation. `pulley` removes JIT; Cranelift on aarch64 had a 2026 sandbox-escape fix [R07]. YARA-X's C-API Android issue #344 is still open, so we use the Rust API [R06]. | PoC A5 fails (size or speed) → libyara on both platforms. |
| 04 | **Two APKs in V1** (revised 20 Oct 2026): the browser in its own app with its own UID, wiped by the system at each reset | Single APK with a `:browser` process (v2.0); work profile | The revisit condition of v2.0 was met: the product must protect the vault and Rift's data against a full browser-host compromise ("real isolation", not only disposal). PoC A8 showed the UID boundary hides Rift's data entirely and that the system wipe is reliable and fast (under 1.7 s to a clean instance). The cost: two APKs to install, sign with one key, and release together. | A platform mechanism gives a stronger per-session identity (for example a per-session user or a supported VM) to third-party apps. |
| 05 | Linux workers: seccomp + Landlock self-lockdown | Bubblewrap | Bubblewrap needs user namespaces, which Flatpak blocks and Ubuntu 23.10+ restricts [R13]. A syscall allowlist is the stronger control for fd-only workers. | — |
| 06 | Linux PDF: PDFium | Poppler (GPL), MuPDF (AGPL) | Permissive license, the same engine family as Android's PdfRenderer, and heavy fuzzing. | — |
| 07 | Vault: age format and an encrypted index file (**superseded in 2.3**: the vault is removed; age still seals the quarantine) | libsodium plus a custom format; SQLite with encrypted fields; SQLCipher | Avoids designing our own crypto format. Encrypting all metadata leaks less than per-field encryption. `sodiumoxide` has been archived since 2021. | More than 10,000 objects → SQLCipher. |
| 08 | Intel: memory-mapped sorted hash tables plus Safe Browsing canonicalization | SQLite; cleartext lists | Trivially validated, fast, compact, atomic to swap, and no complex parser in the update path. | — |
| 09 | TUF via `tough` | A hand-rolled signed manifest; `rust-tuf` | Root rotation, thresholds, and freeze and rollback protection come from an established framework. | — |
| 10 | Linux distribution: Flatpak first, on the KDE runtime with the QtWebEngine BaseApp (revised 21 Oct 2026; previously the GNOME runtime with WebKitGTK) | Distro packages | One tested Qt WebEngine, patched by the runtime and BaseApp maintainers, with renderers sandboxed through the portal (Q1). | — |
| 11 | AI deferred to Phase 6, gated (**built in 2.4**: an advisory URL model, trained in Rust on public feeds, §16) | AI in V1 | Uncertain marginal value over heuristics and Safe Browsing. Keeps V1 focused. Measured in 2.4: on never-seen sites it catches 57% of phishing at High, where the heuristics alone catch under 0.01%. | — |
| 12 | Images: Rust decoders | Platform BitmapFactory, ImageDecoder | Memory-safe decoders. The libwebp CVE-2023-4863 is a precedent for C codec risk. | — |
| 13 | License: MIT OR Apache-2.0 | GPL | Compatible with every chosen dependency (BSD, MIT, Apache, MPL). Can be revisited before outside contributions. | Maintainers choose otherwise. |
| 14 | Network lock: a deny-all VPN for the browser UID plus an authenticated loopback proxy in the controller (v2.1) | Proxy only; `shouldInterceptRequest` filtering; a VPN with a userspace TCP/IP stack that forwards checked traffic | A8: a proxy alone is bypassed by WebRTC, by Chromium's implicit loopback rule, and by escaped native code. Request interception sees URLs, not resolved addresses, and misses WebSockets and WebRTC. A forwarding VPN would put a TCP/IP stack in the trusted core; dropping everything needs none, because loopback is not routed through a VPN. | A supported per-app firewall API appears, or the one-VPN limit proves unacceptable (then: reduced mode only). |

## 21. Repository and engineering conventions

```text
Simulation-Rift/
  README.md  SECURITY.md  LICENSE-MIT  LICENSE-APACHE
  Cargo.toml  Cargo.lock  rust-toolchain.toml  deny.toml  .editorconfig
  crates/
    rift-protocol/   worker messages + validation (forbid unsafe)
    rift-core/       trusted logic (forbid unsafe)
    rift-worker/     parsers + Linux lockdown (unsafe confined, reviewed)
    rift-ffi/        UniFFI bindings: controller (Phase 2)
    rift-worker-ffi/ UniFFI bindings: Android worker (Phase 2)
    rift-linux/      Qt application             (Phase 5, last)
  android/           Gradle project             (Phase 2)
  tools/             maintainer pack builder (Phase 3), rift-train (§16)
  models/            Rift AI's model file, its report and notice (§16)
  poc/               Phase 0 evidence harnesses — not product code; removed when superseded
  docs/
    architecture.md  (this file)
    reports/         phase evidence reports (verified / unverified / improvements)
```

**Conventions:**

- `cargo fmt`, and `cargo clippy --all-targets -- -D warnings`.
- `cargo test` must pass. `cargo deny check` covers licenses, advisories, bans, and sources.
- `cargo-fuzz` targets for `rift-protocol::decode`, intel table validation, and URL canonicalization.
- `#![forbid(unsafe_code)]` everywhere except `rift-worker::lockdown` and FFI shims.
- No `unwrap()` or `expect()` on untrusted data paths. Errors are typed (`thiserror`).
- Commits are small, focused, and verified, with messages that explain *why*.
- Never commit secrets, signing keys, real malware, or user data.
- Every phase ends with `docs/reports/phase-N.md` containing three sections: **Verified**, **Unverified**, and **Could be improved**.

## 22. Roadmap and phase gates

| Phase | Deliverable | Exit gate |
|---|---|---|
| **0: Feasibility** | Proofs of concept A1–A7, L1–L3, X1–X3 (below) | Each is pass, fail, or narrowed, with evidence. Architecture is amended where needed. |
| **1: Foundations** | Workspace, CI, `rift-protocol`, `rift-core` (object, transfer, session, policy, url, intel, vault format) on the host | Unit, property, and fuzz tests; deny/clippy clean; report. |
| **2: Android vertical slice** | Compose shell, `:browser` session, captured download, isolated preview, reset and recovery | Security tests S1–S12 pass on the device matrix; report. |
| **3: Scanner and signed intel** | YARA-X job, verdict cache, TUF update and import, demo pack, `tools/` pack builder | Update-failure suite; offline operation; report. |
| **4: Vault** (removed in 2.3) | Keystore and passphrase key providers, lock/unlock, save and export UI | Crypto and lifecycle tests; plaintext-on-disk inventory clean; report. |
| **5: Linux** | Qt desktop app (decided 20 Oct 2026; it replaces the GTK4 + WebKitGTK plan), Flatpak, worker lockdown, shared core | Same functional contract plus Linux confinement tests; report. |
| **6: AI experiment** | Training notebook, model card, Rust inference | Ships only if it adds measured value within budget. |
| **7: Hardening** | Fuzz campaigns, fault injection, privacy captures, ProxyController study, dependency review | Release gates (§24). |

**Order (decided 20 Oct 2026).** Android comes first: Phases 4, 6 and 7 are completed for Android before Phase 5 starts, so Linux is the last step. The Linux app uses **Qt** instead of GTK4. The revision was made on 21 Oct 2026 (v2.2): §9, ADR-10 and the stack table, after PoCs Q1–Q4. It has not had an external review.

**Phase 0 proofs of concept:**

| ID | Question | Pass criterion |
|---|---|---|
| A1 | Is the WebView renderer sandboxed on our floor? | API 30/33/35/36: `isMultiProcessEnabled()` is true; the renderer runs as `isolated_app`; `Seccomp: 2`. |
| A2 | Is disposal complete? | After seeding cookies, localStorage, IndexedDB, a service worker, and the HTTP cache, then resetting: a JS probe and the filesystem inventory find nothing. Recovery after a kill mid-reset works. |
| A3 | Which downloads can be captured? | A matrix of GET, cookie-auth, redirect, Content-Disposition, POST, and `blob:`, measured. The product claim is set from the results. |
| A4 | Does PdfRenderer work in an isolated process? | It renders from a RAM-backed fd on API 30/34/35/36. |
| A5 | Does YARA-X with `pulley` build and run on Android? | It builds with cargo-ndk for arm64 and x86_64, is 16 KB aligned, and matches inside the isolated service. Size and throughput are recorded. |
| A6 | Are workers cut off from files and the network? | Inside the worker, a canary file in app storage gives `EACCES`; `socket(AF_INET)` and `connect` are denied. |
| A7 | Is the RAM-backed seekable fd handoff possible? | ashmem/SharedMemory fd → `ParcelFileDescriptor` → seek and read works in the worker. |
| A8 | Can the browser be isolated from Rift's data and the network beyond a process boundary? (v2.1) | From a separate browser APK: Rift's files unreachable, private services unbindable; a self-wipe leaves an empty data directory; behind the proxy and VPN, no request to a private or loopback address and no UDP leaves the device. |
| L1 | Is the WebKit sandbox actually active in Flatpak? | The WebProcess shows seccomp and namespaces on Fedora and Ubuntu. Rift's detector refuses when it is absent. |
| L2 | Does the worker lockdown hold? | Natively, inside Docker, and inside Flatpak: open, socket, execve, ptrace, and kill are denied. Allowed work succeeds. |
| L3 | Is the sealed-memfd output immutable? | After sealing, writes from the worker fail; the controller verifies the seals. |
| L4 | Can WebKitGTK run in a no-network Flatpak sub-sandbox behind a forwarding proxy? (v2.1) | Pages load through the controller's proxy; direct connections and DNS from the sandbox fail; the WebProcess sandbox is still active. |
| Q1–Q4 | The Qt redo of L1, L4 and L2 (v2.2): renderer sandbox, network lock, cxx-qt build, worker lockdown inside Flatpak | See [phase-5-qt-design.md](reports/phase-5-qt-design.md). All four pass in CI (20–21 Oct 2026). L1 and L4 as written apply to the superseded WebKitGTK design. |
| X1 | Does the sealed-object format (the vault's until 2.3, the quarantine's since) detect damage? | Round trip works; truncation, tampering, swapped objects, and a wrong key are each detected. |
| X2 | Can TUF be verified offline on Android targets? | A `tuftool` repository verifies through file transport. Tampering, rollback, expiry, and path traversal are rejected. Cross-compiles for Android. |
| X3 | Are URL lookups fast and correct? | Canonicalization passes the published Safe Browsing examples; p95 lookup ≤ 5 ms with 1 million entries. |

## 23. Acceptance test matrix

| ID | Test | Required result | Invariant |
|---|---|---|---|
| S1 | A page probes for native bridges | None exist (API inspection plus fixture) | INV-6 |
| S2 | A page requests camera, microphone, or geolocation | Denied; the manifest lacks the permissions | B4 |
| S3 | Worker opens a canary file | Denied by the OS (`EACCES`, Landlock, or seccomp) | INV-1/2 |
| S4 | Worker opens a socket or connects | Denied | INV-2 |
| S5 | Worker returns oversized or malformed output | Rejected without large allocation | INV-3 |
| S6 | Worker crashes or hangs | Job ends as failed or not fully scanned; UI stays responsive | INV-5 |
| S7 | Confinement unavailable (simulated) | Feature refused; no fallback | INV-1 |
| S8 | Oversized or lying `Content-Length` download | Stream stops at the limit | INV-13 |
| S9 | Redirect to a private or loopback address | Refused | INV-13 |
| S10 | Traversal or control characters in a filename | Display name normalized; storage unaffected | §11.1 |
| S11 | Bytes change after a scan | New object; old verdict not reused | INV-4 |
| S12 | Reset after browsing and downloads | Every session store gone, quarantine included | INV-8 |
| S13 | Kill during reset | Recovery runs before a fresh session is shown | INV-8 |
| S14 | Renderer crash | Session torn down; app alive | INV-7 |
| S15 | Unsupported WebView configuration (simulated) | Browsing refused | INV-7 |
| S16 | Update with a bad signature, hash, version, expiry, or path | Rejected; current snapshot retained | INV-10 |
| S17 | Interrupted update | Old snapshot active; no mixture of versions | INV-10 |
| S18 | Sealed-object truncation, tamper, swap, or wrong key | Detected; no partial plaintext released | §11.1, §14 |
| S19 | Plaintext-on-disk inventory after preview or kill | None found | INV-9 |
| S20 | Local mode traffic capture | No content-specific third-party requests from Rift | INV-11 |
| S21 | Demo rule and indicator match | Expected finding with versions | §12 |
| S22 | New pack adds or removes a rule | Cache invalidation is correct | §12.1 |
| S23 | Code in the browser's `:web` process reads Rift's files, binds its private services, calls the core with a stale generation | Files unreachable; binds refused; stale calls refused | B2 |
| S24 | Another app (different signer) binds the browser or the core, starts the browser, uses the proxy | Every attempt refused; the proxy answers 407 | B2, B7, INV-14 |
| S25 | A page fetches loopback and private addresses | The requests never reach their destination; the refusals are listed | INV-14 |
| S26 | A page uses WebRTC; browser-process code opens sockets and resolves DNS directly | No packet reaches a private or public address | INV-14 |
| S27 | Reset after a page set cookies and storage | The system wiped the browser app: new process, no files, no state in the next session | INV-8 |
| S28 | The network lock is lost mid-session (another VPN starts) | The session ends and the browser is wiped | INV-14 |
| S28c | The user switches the network lock off, then on (§8.8) | Off: the VPN is gone, the session ends, the next ones run reduced and labelled, pages still go through the proxy, and off is kept across a start. On: the lock runs again and the next session is locked | INV-14 |
| F1 | Content filters (§10.9): a page with an ad script, an ad element and a sign-in pop-up, under the user's own rules | Filters on: script blocked, element and pop-up hidden, article shown, bar counts it. Off: everything shown | INV-6, INV-11 |
| V3 | Link tools (§10.10): a wrapped tracking link; a link to a listed address; a link to loopback | Unwrapped and cleaned only on tap, rechecked, undone; the listed hop and loopback are not contacted; another app only after a warning | INV-11, INV-13 |
| Z1 | Extra isolation (§8.9): a page swaps what the user copies; with root, the browser UID connects to loopback | Off: the swap reaches the clipboard. On: the clipboard is unchanged and the reset's wipe goes through the helper; with root, only the session's proxy port answers | INV-14 |

Unit, property, and fuzz testing cover URL canonicalization, the table validator, protocol decoding, the policy decision table, session transitions, quota accounting, and the sealed-object format. Harmless fixtures only: no live malware in CI or demos.

## 24. Residual risk register

| Risk | Residual after mitigation | Owner response |
|---|---|---|
| Engine exploit chain reaches the browser app's `:web` process | It has the browser UID: this session's browsing state, the browser window, and loopback; not Rift's data, keys or the network beyond loopback (while the lock holds) | Two APKs (ADR-04); system wipe each reset; network lock (ADR-14); WebView minimum-version checks |
| Loopback services on the device | Escaped browser code can connect to other apps' local servers (pages cannot: the proxy refuses loopback) | Stated; no app-level Android mechanism closes loopback for one app. With root, extra isolation's firewall does (§8.9) |
| Only one VPN per device | Users of another VPN cannot have the network lock | Explicit reduced mode per session, labelled; never a silent fallback |
| The controller process dies while the browser runs | The lock goes with it. The browser exits when its binding to the core dies, but escaped code in the browser could stay running without the lock until the next launch wipes the app | The next launch wipes the browser before anything else (§15); Android's always-on VPN with "block connections without VPN" would close the gap, but it is a device setting Rift cannot set. With root, extra isolation's firewall rules stay in the kernel when Rift dies and keep the browser off the network (§8.9) |
| Sites that use HTTP authentication | The browser answers only the proxy's own challenge, so such sites cannot be signed in to | Stated; it keeps the proxy token from ever reaching a site |
| No site isolation within a session | A renderer compromise from one site can read other sites' data in the same session | One session at a time; encourage reset between unrelated sites |
| Network coverage gaps | With the lock, every connection is checked for destination class and against the threat database, but for HTTPS only by host; HTTPS content is not inspected | State coverage honestly |
| Download capture gaps | Some downloads are unsupported | Explicit UI message; no JS bridge |
| Parser or decoder vulnerabilities | Contained by B3; kernel exploits remain | Updates; fuzzing; worker retirement |
| Feed licensing | No real intelligence until rights are obtained | Demo packs; direct-adapter design |
| Signing-key compromise | Bounded by TUF thresholds and root rotation | Offline keys; documented response plan |
| Android developer verification (enforced from 30 Sep 2026 in BR/ID/SG/TH; global rollout planned for 2027) [R22] | Sideloaded builds need a registered identity | Register the package name before distribution |
| Same-user Linux processes | Can read an open session's files or memory | Out of scope; stated plainly |
| Page writes to the clipboard | A page can put text on the system clipboard after a user gesture (for example a command meant to be pasted elsewhere) | Stated in the live page watch's "not seen" list; no WebView control exists. Extra isolation (Shizuku or root) has Android ignore the browser app's clipboard (§8.9) |
| A browser process taken over after a renderer escape | Could suppress or forge the browser-reported half of the live page watch | The core's own events (proxy, lock, navigation, downloads) and the wipe at reset do not depend on it |

**Release gates:**

- Every invariant has a passing test on the declared device matrix.
- Dependency advisories have been reviewed.
- The licenses inventory is complete.
- The evidence reports are published.
- Every security-sensitive dependency has a named maintenance owner.

## 25. Licensing

- Project license: MIT OR Apache-2.0 (ADR-13).
- `cargo deny` enforces an allowlist of dependency licenses (MIT, Apache-2.0, BSD-2/3, ISC, MPL-2.0, Unicode-3.0, Zlib).
- Third-party rules and feeds are inventoried separately with their terms and attribution. A process boundary does not remove licensing obligations.
- PDFium binaries (BSD-3) carry their notices in the app's "Open-source licenses" screen.

## 26. Future expansion

These are considered only after V1. Each needs a definition of accepted input, maximum work, required capabilities, output format, tests, and its license impact.

- Bounded archive inspection, run in a worker.
- Reconstructed PDF export (render to pixels, then rebuild the document).
- OCR on sanitized pixels.
- A ClamAV adapter on Linux.
- An opt-in online reputation provider.
- The two-APK browser split.
- ProxyController-based host enforcement.
- Specific synthetic device APIs.

Executing arbitrary programs remains a different product with a different threat model.

## 27. Glossary

| Term | Meaning |
|---|---|
| Session | A disposable browsing workspace with its own generation, processes, data directory, and ephemeral quarantine key. |
| Quarantine | Session-scoped encrypted storage for untrusted objects. It is not a statement that content is harmless. |
| Worker | A confined process that parses one job's input and holds no other authority. |
| Controller | Trusted code (rift-core plus platform glue) that authorizes operations and validates results. |
| Snapshot | One immutable, verified set of intelligence data. |
| Not flagged | No finding from the completed configured checks. It is not a safety certificate. |
| Fail closed | Refuse the operation when its mandatory protection cannot be established. |
| Crypto-shredding | Making data unreadable by destroying its only key. |

## 28. References

Consulted on 17 Oct 2026. Verify again before release.

| ID | Source |
|---|---|
| R01 | [Chromium: WebView architecture](https://chromium.googlesource.com/chromium/src/+/main/android_webview/docs/architecture.md) — the browser side and network service run inside the app process |
| R02 | [Chromium: WebView renderer README](https://chromium.googlesource.com/chromium/src/+/main/android_webview/renderer/README.md) — out-of-process on all devices from API 30; one renderer per profile |
| R03 | [Android: `<service>` element and isolatedProcess](https://developer.android.com/guide/topics/manifest/service-element) |
| R04 | [GeckoView GeckoRuntimeSettings (160)](https://mozilla.github.io/geckoview/javadoc/mozilla-central/org/mozilla/geckoview/GeckoRuntimeSettings.html) · [Project Fission/Android](https://m.wiki.mozilla.org/Project_Fission/Android) |
| R05 | [Community report: Fission enabled then rolled back on Android (2026)](https://discuss.privacyguides.net/t/site-isolation-fission-now-appears-to-be-active-in-firefox-on-android/34899) |
| R06 | [YARA-X issue #344 (Android C-API)](https://github.com/VirusTotal/yara-x/issues/344) · [YARA-X `pulley` feature](https://github.com/VirusTotal/yara-x/blob/main/lib/Cargo.toml) |
| R07 | [Wasmtime platform support and Pulley](https://docs.wasmtime.dev/stability-platform-support.html) · [CVE-2026-34971](https://www.suse.com/security/cve/CVE-2026-34971.html) |
| R08 | [Android 15 PdfRenderer updatable module and PdfRendererPreV](https://android-developers.googleblog.com/2024/03/the-second-developer-preview-of-android-15.html) |
| R09 | [Android WebView native-bridge risks](https://developer.android.com/privacy-and-security/risks/insecure-webview-native-bridges) · [Unsafe file inclusion](https://developer.android.com/privacy-and-security/risks/webview-unsafe-file-inclusion) |
| R10 | [WebViewClient](https://developer.android.com/reference/android/webkit/WebViewClient) · [AndroidX WebKit](https://developer.android.com/reference/androidx/webkit/package-summary) |
| R11 | [Android 16 KB page sizes](https://developer.android.com/guide/practices/page-sizes) |
| R12 | [WebKit bug 278578: unsandboxed fallback without warning](https://bugs.webkit.org/show_bug.cgi?id=278578) |
| R13 | [Ubuntu: restricted unprivileged user namespaces](https://ubuntu.com/blog/ubuntu-23-10-restricted-unprivileged-user-namespaces) · [flatpak-spawn(1)](https://www.man7.org/linux/man-pages/man1/flatpak-spawn.1.html) |
| R14 | [Linux Landlock](https://docs.kernel.org/userspace-api/landlock.html) · [seccomp filter](https://docs.kernel.org/userspace-api/seccomp_filter.html) |
| R15 | [WebKitGTK 6.0 migration](https://webkitgtk.org/reference/webkit2gtk/2.39.90/migrating-to-webkitgtk-6.0.html) |
| R16 | [Safe Browsing: URLs and hashing](https://developers.google.com/safe-browsing/v4/urls-hashing) |
| R17 | [abuse.ch terms of use (effective 4 Nov 2025)](https://abuse.ch/terms-of-use/) |
| R18 | [tough advisories](https://github.com/awslabs/tough/security/advisories) · [TUF](https://theupdateframework.io/) |
| R19 | [age v1 specification](https://age-encryption.org/v1) · [rage / age crate](https://github.com/str4d/rage) |
| R20 | [Android Keystore](https://developer.android.com/privacy-and-security/keystore) |
| R21 | [pdfium-binaries](https://github.com/bblanchon/pdfium-binaries) · [pdfium-render](https://github.com/ajrcarey/pdfium-render) |
| R22 | [Android developer verification timeline](https://www.androidauthority.com/android-sideloading-changes-timeline-3679204/) |
| R23 | [Microsoft Edge: Super Duper Secure Mode (JIT disabled)](https://microsoftedge.github.io/edgevr/posts/Super-Duper-Secure-Mode/) |
| R24 | [Dangerzone](https://github.com/freedomofpress/dangerzone) |
| R25 | [VirusTotal API overview and terms](https://docs.virustotal.com/docs/api-overview) |

---

## Appendix A: changes from v1.1

| v1.1 | v2.0 | Reason |
|---|---|---|
| libyara (Android) and YARA-X (Linux) | YARA-X with `pulley` on both | One engine; no JIT; memory-safe (ADR-03) |
| Bubblewrap for Linux workers | seccomp + Landlock self-lockdown | Works inside Flatpak and on Ubuntu (ADR-05) |
| Poppler | PDFium | Licensing; one engine family (ADR-06) |
| libsodium with a custom versioned format | age | Don't design crypto formats (ADR-07) |
| SQLite with selected encrypted fields | Encrypted index file; memory-mapped hash tables for intel | Less leakage; simpler; safe update parsing (ADR-07/08) |
| Platform image decoding | Rust decoders in the worker | Memory safety (ADR-12) |
| Single app process hosting WebView | `:browser` process (v2.0); a separate browser APK with its own UID, wiped by the system (v2.1) | Reliable disposal; Rift's data and keys out of reach of an engine escape (ADR-02, ADR-04) |
| — | Network lock: deny-all VPN for the browser UID plus an authenticated egress proxy (v2.1) | Pages and escaped code cannot reach the LAN or loopback services through the browser (ADR-14) |
| ProfileStore lifecycle | Process kill plus per-generation data directory | Works on every provider |
| — | Per-session ephemeral quarantine key | Crypto-shredding makes disposal robust |
| — | WebKit sandbox *verification*; WebView multi-process precondition | Known silent-fallback bug; fail closed |
| — | Fullscreen, file chooser, renderer-crash, WebRTC rules | Hidden WebView gaps |
| Safe Browsing not addressed | Disclosed onboarding choice | Strong protection, but sends hash prefixes to Google |
| 11 conceptual interfaces | 3 traits plus concrete modules | YAGNI |
| AI in V1 (gated) | AI deferred to Phase 6 | Focus; uncertain marginal value |
| Online Enhanced mode in V1 architecture | Reserved, not built | No provider has suitable terms yet |
| Background update scheduling | Manual only in V1 | Battery; simplicity |
| Feed sources assumed packageable | Licensing blocks redistribution; demo packs plus a direct-adapter design | abuse.ch Nov 2025 terms |
| Distro packaging on Linux | Flatpak first | One tested, runtime-patched web engine (Qt WebEngine since v2.2) |

Content carried forward unchanged in substance: scope exclusions, the result vocabulary, immutable-object verdict binding, TUF update flow, fail-closed rules, the demonstration sequence (now Phase 2–5 evidence), the AI evaluation methodology, and the honesty rules about claims.
