# Simulation-Rift — Architecture and Specification

**Version:** 2.0 (supersedes the v1.1 "Project Specification", 17 Oct 2026)
**Date:** 17 October 2026
**Status:** Approved baseline architecture. Phase 0 feasibility tests are in progress; every claim marked **[PoC]** is unverified until its Phase 0 report says otherwise.
**Platforms:** Android (API 30+, arm64-v8a first, x86_64 for emulators) and Linux (Flatpak, x86_64 and aarch64)
**Languages:** Rust (shared core, workers, Linux UI), Kotlin (Android UI and platform glue), Python (offline model training only, never shipped)

> Simulation-Rift is a fully local, modular workspace for opening unfamiliar links, downloading and inspecting untrusted files, and keeping chosen files in encrypted storage. It does this by combining OS-enforced isolation, offline-first threat detection, and signed data updates. It never promises perfect isolation. It makes specific, tested claims about named boundaries.

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
14. [Rift Vault](#14-rift-vault)
15. [Sessions](#15-sessions)
16. [Rift AI (deferred, gated)](#16-rift-ai-deferred-gated)
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
| Import an attachment | Only the file the user picked (SAF / file portal) is copied into quarantine. Nothing else is indexed or enumerated. |
| Inspect a file | Scan status and coverage are shown. Supported formats get a confined preview. |
| Keep a file | The user saves it to the encrypted vault. It stays untrusted. |
| Update intelligence | The user fetches or imports a signed pack. After that, the device works offline. |
| Reset | All session state is destroyed. Saved vault files are preserved. |

### 2.2 V1 includes

- Browse, download, inspect, save, and reset, end to end.
- Local URL checks: indicator lookup plus explainable heuristics.
- File checks: SHA-256 indicators, magic-byte type identification, and YARA-X rules.
- Confined preview of PDF, PNG/JPEG/WebP, and plain text. Markdown, HTML, and SVG are shown as plain text.
- An encrypted vault, with one default vault.
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
- The AI phishing classifier, which is a gated later phase (§16).
- Multiple concurrent sessions and multiple vaults.

"Any link" means public `http`/`https` URLs subject to policy. It does not mean every authentication flow, DRM stream, app scheme, or download mechanism works.

## 3. Threat model

### 3.1 Assets

In priority order:

1. The user's personal files and other apps' data.
2. Vault contents and vault keys.
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
- Same-user non-sandboxed processes on Linux reading an *unlocked* vault.
- Most hardware and micro-architectural side channels. Spectre-class leaks between sites are reduced by giving each session its own renderer, but are not eliminated.
- Undiscovered browser-engine or kernel sandbox escapes. These are residual risk (§24).
- Forensic recovery of deleted flash blocks. Crypto-shredding mitigates this for Rift's own files (§15).

## 4. Trust boundaries

| # | Boundary | Enforced by | Strength | Notes |
|---|---|---|---|---|
| B1 | Web content → app | Android: Chromium renderer in an `isolated_app` SELinux domain with seccomp-bpf. Linux: the WebKitGTK WebProcess sandbox (bubblewrap + seccomp) | Strong; exploit chains exist | One renderer per WebView profile, so there is no site isolation within a session. |
| B2 | Browser host (`:browser`) → vault and core | Android: separate **process**, same UID | **Weak** | Raises cost (no key material in memory, no vault code loaded). It is not a security identity: same-UID code can read app files and use Keystore keys. See §8.3. |
| B3 | File content → app | Android: `isolatedProcess` service (random UID, `isolated_app` domain, no permissions). Linux: worker self-lockdown with seccomp-bpf allowlist, Landlock, rlimits, and no_new_privs | Strong for parse-only workers | Workers receive only file descriptors. |
| B4 | Website → sensors | Permissions are **absent from the manifest** (Android) or denied in WebKit permission callbacks (Linux) | Strong on Android (OS-enforced); policy-enforced on Linux | Callbacks deny as well, as defence in depth. |
| B5 | Offline attacker → vault | age encryption; the identity is wrapped by Android Keystore or a passphrase (scrypt) | Strong while locked | Leaks object count, ciphertext sizes, and timestamps. |
| B6 | Network or feed attacker → intelligence | TUF metadata (signatures, thresholds, expiry, rollback state), then strict bounded parsing | Strong while keys are protected | Signatures prove origin, not correctness. |
| B7 | Other apps → Rift's data | Android app sandbox (per-app UID). Flatpak's per-app home on Linux | Strong on Android; partial on Linux | Linux host processes of the same user can read `~/.var/app/<id>`. |

```text
                 ┌──────────────── TRUSTED ────────────────┐
  user ──UI──▶   │ main process: UI · rift-core · vault ·  │
                 │ intel · updater · policy                │
                 └───────┬───────────────────┬─────────────┘
                 B2 (weak, same UID)    B3 (strong)
                 ┌───────▼────────┐   ┌──────▼───────────────┐
                 │ :browser       │   │ rift-worker           │
                 │ WebView host   │   │ PDF · image · YARA-X  │
                 │ network service│   │ no net · no fs · no   │
                 └───────┬────────┘   │ keys                  │
                    B1 (strong)       └──────────────────────┘
                 ┌───────▼────────┐
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
| INV-6 | The browser exposes no JavaScript interface or message channel to web content. File and content access are disabled. `intent:`, `file:`, `content:`, and custom schemes are never forwarded automatically. Mixed content is never allowed. Multiple windows are disabled. A persistent trusted indicator survives fullscreen. The file chooser is denied unless the user enables it for the session. |
| INV-7 | Browsing is refused if the engine's renderer sandbox cannot be confirmed. On Android that means the renderer is not multi-process or WebView is below the minimum version. On Linux that means the WebKit sandbox is not active. If the renderer crashes, the session is torn down and the app does not crash. |
| INV-8 | Session reset terminates the session's processes, deletes session data, and verifies the deletion. Only then does it report success, and it advances the session generation. Results from older generations are rejected. A failed cleanup is shown as failed. |
| INV-9 | Vault and quarantine plaintext is written to persistent storage only in encrypted form. Preview plaintext lives in RAM-backed fds (memfd/ashmem) **[PoC A7/L3]**. |
| INV-10 | An intelligence snapshot is activated only after full TUF verification, staging, schema validation, and smoke tests, all followed by one atomic pointer swap. Expired network metadata and rollbacks are rejected. Recovery is done with a new, higher-versioned release, never by resetting anti-rollback state. |
| INV-11 | In Local Protection mode, Rift's own code sends no content-specific requests (URLs, hashes, files) to any third party. Engine features that do, such as Safe Browsing, are disclosed and controlled by the user. |
| INV-12 | The app opts out of backup and device-to-device transfer for all data. Vault screens set `FLAG_SECURE`. |
| INV-13 | Controller-owned network transfers (downloads, updates) re-check every redirect hop. They resolve DNS once per hop and refuse loopback, private, link-local, and multicast destinations unless the user explicitly allows them. They enforce byte limits on the stream, not on `Content-Length`. |

## 6. Architecture overview

```text
 ANDROID — one APK, one UID                                  LINUX — Flatpak
 ┌─ main process [TRUSTED] ─────────────────────┐   ┌─ rift (GTK4) [TRUSTED] ─────────┐
 │ Kotlin/Compose UI                            │   │ gtk4-rs + libadwaita UI          │
 │ rift-core via UniFFI (rift-ffi)              │   │ rift-core (direct Rust)          │
 └──┬──────────────────────┬────────────────────┘   └──┬───────────────┬──────────────┘
    │ Binder, non-exported │ Binder + ParcelFileDescriptor  │ WebKit IPC   │ socketpair + SCM_RIGHTS
 ┌──▼─ :browser ───────────┐ ┌▼─ isolatedProcess ─────┐ ┌──▼──────────┐ ┌▼─ rift-worker ──────┐
 │ WebView host + network  │ │ rift-worker-ffi (.so)  │ │ WebKit       │ │ seccomp + Landlock   │
 │ URL lookup (read-only)  │ │ PdfRenderer (platform) │ │ WebProcess   │ │ rlimits, NNP         │
 │ no vault, no keys       │ │ image · YARA-X(pulley) │ │ (sandboxed)  │ │ PDFium · image ·     │
 └──┬──────────────────────┘ └────────────────────────┘ └──────────────┘ │ YARA-X(pulley)       │
 ┌──▼─ WebView renderer ───┐                                             └──────────────────────┘
 │ isolated_app, seccomp   │
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
                                                                       │ user: save
                                                                       ▼
                            re-encrypt to vault identity ─▶ vault index update (atomic)
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
| `intel` | Snapshot store (memory-mapped sorted hash tables), lookups, and staging and atomic activation. |
| `update` | TUF client integration (`tough`) and offline import. |
| `scan` | Orchestration, cache keys, result vocabulary, coverage accounting. The engines themselves run in the worker. |
| `vault` | age-based object encryption, the encrypted index, lock/unlock, export authorization. |
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

- Permissions: `INTERNET` only, plus `POST_NOTIFICATIONS` if transfer progress notifications are adopted. **No** camera, microphone, location, contacts, SMS, storage, accessibility, device-admin, or install-packages permissions. Because the permissions are absent, the OS denies them regardless of WebView callbacks (B4).
- `android:allowBackup="false"` and `dataExtractionRules` that exclude everything (INV-12).
- `usesCleartextTraffic` is set only as required for user-initiated HTTP browsing. Rift's own traffic is HTTPS-only.
- Intent filters: `ACTION_VIEW` for http/https (Rift appears as a browser choice) and `ACTION_SEND` with `text/plain` (URLs) and `*/*` (file import).
- Components:
  - `MainActivity` (main process).
  - `BrowserActivity` with `android:process=":browser"`.
  - `PreviewService` with `android:isolatedProcess="true"`, `android:exported="false"`, and `android:useAppZygote="true"`. The zygote preload only loads the native libraries (`jnidispatch`, `rift_worker_ffi`): the zygote must stay single-threaded, so no JNA or UniFFI object is created there.
  - Debug builds add test workers from `src/debug` (probe, hanging, crashing, lying and unconfined services for S3–S7). The release manifest is checked to contain none of them.
  - A non-exported Binder service in the main process for the browser→core interface.

### 8.3 Processes and why

| Process | Holds | Why it exists |
|---|---|---|
| main | UI, rift-core, vault identity (when unlocked), intel, updater | Trusted controller. |
| `:browser` | WebView host and network service; a read-only intel snapshot handle | **Lifecycle:** killing this process plus deleting its data directory is the only disposal mechanism we expect to work on every WebView provider (§15). **Hygiene:** the process that hosts code reachable from a renderer escape never holds vault keys or loads vault code. |
| renderer | Web content | Provided and sandboxed by WebView (B1). |
| isolated worker | One job's input | B3. |

**Honest limit of B2.** Code running in `:browser` after an engine escape has the app's UID. It can read the app's private files, bind the app's non-exported services, and use Keystore keys that are not authentication-bound. Rift raises the cost in three ways:

- (a) Vault data is encrypted at rest and the identity is never in `:browser` memory.
- (b) The vault-wrapping key is authentication-bound by default, so each unlock needs a fresh BiometricPrompt or device credential.
- (c) The core's Binder interface offers `:browser` only `submit_download`, `lookup_url`, and `report_navigation`. It has no vault or export operations.

The only stronger option is a separate APK, which means a separate UID. That is recorded as a post-V1 option (ADR-04). The browser→core interface is designed so it could move across a UID boundary unchanged.

### 8.4 WebView configuration

- Preconditions (INV-7):
  - `WebViewCompat.getCurrentWebViewPackage()` is at or above the minimum supported version.
  - `WebViewCompat.isMultiProcessEnabled()` returns true **[PoC A1]**.
  - Otherwise browsing shows "unsupported device configuration".
- `setDataDirectorySuffix("s<generation>")` is called in `:browser` before any WebView use. A new generation gets a fresh directory even if deletion of the old one is still pending.
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
- `android.webkit.WebView.MetricsOptOut` is set in the manifest. The minimum WebView major version is 100, a release parameter reviewed against Chromium's security releases.
- **Safe Browsing** is a disclosed onboarding choice. It works by matching URL hash prefixes in Google Play services and can send prefixes to Google. If the user enables it, Local mode's claim (INV-11) states this explicitly.

### 8.5 Downloads **[PoC A3]**

`DownloadListener` supplies the URL, user agent, Content-Disposition, and MIME type. `:browser` sends `submit_download { url, cookie header for that URL only, user agent, referer }` to the core. The core performs the fetch under INV-13 and writes into session quarantine.

**Known unsupported in V1:** POST-generated responses, `blob:` and `data:` downloads, and single-use URLs already consumed by the engine. These show "this download cannot be captured safely". Rift adds no JavaScript bridge to support them.

PoC A3 (API 30 and 36) measured this. GET, Content-Disposition, redirect and cookie-gated downloads reach the listener, and the core's re-fetch returns the same bytes. A POST form response reaches the listener, but a re-fetch with GET gets HTTP 405, so the core must detect a failed or mismatched re-fetch and show the message above rather than store an error page. `blob:` and `data:` downloads **never call `DownloadListener`**: they fail silently in the engine, and Rift cannot show a message for an event it never sees. The product claim is therefore "Rift captures downloads that arrive at a URL; downloads generated inside the page are not supported." 

**Phase 2 implementation (`rift-core::download`).**
- HTTP client: `ureq` 3.4 without default features, with `rustls` (ring) and the bundled Mozilla roots (`webpki-roots`). It is blocking and small, and it lets Rift resolve names itself: a resolver wrapper runs the destination check (INV-13) on every address of every hop, so a redirect or DNS answer to a private address is refused before connecting. Redirects are followed by Rift (at most 10). The bundled roots mean Rift does not trust user-installed CAs for its own fetches; the cost is that root updates ship with Rift releases. `rustls-platform-verifier` remains the alternative if that proves wrong.
- The cookie header from `:browser` is sent only to the origin it was read for, never after a cross-origin redirect.
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
  - Not yet done: the per-thread seccomp filter described above (it needs a native shim).
- **Cold start:** `useAppZygote` with the native library preloaded in the app zygote is required. Without it the median cold start on the API 36 emulator was 304 ms (budget 300 ms); with it, 45 ms (157 ms for the first worker, which also starts the zygote).

### 8.7 Keys

- The vault-wrapping key is AES-256-GCM in Android Keystore:
  - Non-exportable; StrongBox if present, otherwise TEE.
  - `setUnlockedDeviceRequired(true)`.
  - By default `setUserAuthenticationParameters(0, BIOMETRIC_STRONG | DEVICE_CREDENTIAL)`, so every unwrap needs authentication through BiometricPrompt with a CryptoObject.
- Without a secure lock screen, auth-bound keys are impossible. The user must then choose a vault passphrase (age scrypt). Rift never silently stores an unprotected key.
- Key invalidation (for example, new biometrics enrolled) makes the vault unrecoverable without the optional recovery passphrase. This is stated when the vault is created.

## 9. Linux platform

### 9.1 Distribution

**Flatpak first**, on the GNOME runtime, which provides GTK4, libadwaita, and WebKitGTK 6.0 and is security-updated by runtime maintainers. The declared test baselines are current Fedora Workstation and Ubuntu LTS, both with Flathub. Native packages are post-V1.

Why: distribution WebKitGTK versions vary. Ubuntu 23.10+ restricts unprivileged user namespaces through AppArmor, which breaks unprofiled bubblewrap use [R13]. Flatpak gives one tested runtime.

### 9.2 Browser

- WebKitGTK 6.0 API (`webkit6` crate).
- Rift requires the WebProcess sandbox to be **actually active**, not just configured. WebKit has an open, reopened bug in which WebKitGTK runs processes unsandboxed with no warning when the Flatpak sandbox is unavailable [R12].
- After starting a session, Rift inspects the WebProcess (`/proc/<pid>/status` Seccomp/NoNewPrivs and namespace links under `/proc/<pid>/ns`) and refuses to browse if it is not confined (INV-7) **[PoC L1]**. Phase 0 refinements:
  - Web processes are identified by `/proc/<pid>/comm` (the executed binary), never by command line, because the `bwrap` launcher carries the web-process path among its arguments.
  - WebKit starts more web processes as tabs and sites change (process swap on navigation), so the check runs for every new web process before its page is shown, not once per session.
  - The check is necessary, not redundant: WebKitGTK 2.54.1 aborted when `bwrap` could not create namespaces, but an environment variable silently disables the sandbox, and R12 shows a fallback path has existed before.
  - The **network process is not sandboxed** by WebKitGTK (L1: no seccomp, no new namespaces). It parses HTTP, TLS and cookies for every site, so a bug there runs with the user's full privileges in a native package. This is a main reason for Flatpak first: there it is at least bounded by the Flatpak sandbox (to be verified in Phase 0 L1-Flatpak).
- Permission requests (`permission-request` signal): deny all, including camera, microphone, geolocation, notifications, and clipboard read.
- Downloads: the `decide-policy` and `download-started` handlers cancel the engine download and submit to the core transfer, as on Android. Engine downloads may be used later if they prove more compatible.
- Optional hardening for later evaluation: disable JavaScriptCore's JIT for untrusted sessions. There is precedent in Edge's enhanced security mode [R23]. The mechanism is unsupported and is not relied on in V1.

### 9.3 Workers **[PoC L2]**

The controller spawns `rift-worker` with a `SOCK_SEQPACKET` socketpair on fd 3. stdin, stdout, and stderr go to `/dev/null`, and the environment is empty. The worker runs the lockdown sequence (§7.3), and the controller verifies it before sending input. Pixels are returned in a **sealed memfd** (`F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK`). The controller checks the seals before mapping, so the kernel guarantees the content cannot change after validation.

If Landlock or seccomp is unavailable, preview and scanning are disabled. Rift never runs a parser unconfined and never asks users to weaken system security.

Bubblewrap is not used for workers. It needs user namespaces, which are blocked inside Flatpak and restricted on Ubuntu, and a seccomp allowlist is the stronger control for fd-only workers anyway. `flatpak-spawn --sandbox --no-network` may be added later as an extra layer.

## 10. Rift Browser

### 10.1 Features

- Address bar, back/forward, reload, the session indicator, Reset, a downloads list, and a protection status chip.
- Trusted controls live outside web content and cannot be covered (INV-6).
- No password manager, no autofill, no import from other browsers, and no extensions.

### 10.2 Navigation rules

| Input | Rule |
|---|---|
| `https:` | Allowed, subject to intel and policy. |
| `http:` | Allowed with a "connection not encrypted" warning. Rift's own endpoints never use it. |
| `file:`, `content:`, `javascript:` typed in the address bar | Rejected. |
| `intent:`, `market:`, custom schemes | Never auto-forwarded. V1 shows "external app links are blocked". |
| `blob:`, `data:` in-page | Engine-internal use is allowed. Downloads from these sources are unsupported in V1. |
| Certificate error | Cancelled. There is no click-through in V1. |

### 10.3 URL checks and the honest coverage claim

Rift checks user-entered URLs, main-frame navigations that the engine reports, and every download URL and redirect hop that the core fetches.

Rift **does not** claim to inspect subresources, WebSockets, WebRTC, service-worker fetches, or POST navigations. WebView's callbacks have documented gaps, and WebRTC data channels can reach local-network addresses without a permission prompt.

Host-level enforcement of all engine traffic through `androidx.webkit.ProxyController` is a Phase 7 investigation. It is not a V1 claim. The diagnostics screen states the actual coverage.

### 10.4 Verdict handling

- **Known malicious:** blocked. A per-navigation "Inspect anyway in restricted session" is offered after a warning. It changes no confinement and grants no permission.
- **Suspicious:** an interstitial in the trusted UI lists the specific heuristic facts.
- **Not flagged:** proceeds and shows the database age. There is never a green "safe" badge.

## 11. Rift Files: intake, quarantine, preview, export

### 11.1 Object lifecycle

```text
RECEIVING ─▶ COMMITTED(immutable, sha256) ─▶ SCANNING ─▶ SCANNED(verdict bound to versions)
    │ abort/limit                                   │
    ▼                                               ├─▶ PREVIEW (worker, on request)
 DISCARDED                                          ├─▶ SAVE TO VAULT (re-encrypt; still untrusted)
                                                    ├─▶ EXPORT (explicit, warned, original bytes)
                                                    └─▶ DELETE
```

- Storage names are app-generated `ObjectId`s. Server-supplied filenames are only display metadata, normalized to remove control characters, path separators, bidi overrides, and excessive length.
- Limits are enforced on the stream: 100 MiB per object and 500 MiB per session by default. Space is reserved before starting.
- The hash covers the final stored plaintext. Commit happens only after a complete transfer.
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

### 11.4 Export

Export is an explicit user action through SAF or the file portal, with a warning that the copy leaves Rift's protection and is **not sanitized**. Export is never automatic and never triggered by a website. Reconstructed "safe PDF" export, Dangerzone-style, is future work [R24].

## 12. Rift Scanner

### 12.1 Pipeline

1. **During transfer (core):** SHA-256 and magic-byte type. Extension mismatch is flagged.
2. **Hash lookup (core):** against the snapshot's file-hash table.
3. **Rules (worker):** YARA-X with the curated pack rules, bounded by deadline (15 s default) and match count.
4. **Result:** findings, coverage, and versions. The cache key is `(sha256, yara-x version, snapshot id, policy version)`.

A new snapshot invalidates cached conclusions as *current*. They remain visible as history. Rescans happen on access or on request, never as an automatic whole-vault sweep.

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

- Each snapshot is a directory `intel/snapshots/<id>/` with a pointer file `intel/current`. The pointer is replaced by write + fsync + rename.
- **URL table:** sorted array of `(sha256(expression)[..16], meta_idx: u32)`. Expressions follow the Safe Browsing canonicalization and host-suffix × path-prefix scheme [R16]. A host-only expression is a domain-scoped indicator; a host+path expression is a path-scoped one.
- **File table:** sorted array of `(sha256[32], meta_idx: u32)`.
- **Binary format:** a header with magic `RIFTIDX1`, version, record size, and count. On install the store validates that `len == header + count × size` and that records are strictly sorted, both in O(n). The table is memory-mapped and binary-searched. Malicious URLs are not stored in cleartext.
- **Metadata:** JSON of at most 1 MiB with a strict schema: sources, snapshot times, coverage window, and notices.
- **Rules:** YARA source text (bounded size), compiled inside the worker.
- No SQLite, executable content, native libraries, scripts, pickles, or serialized engine artifacts are accepted from packs.

### 13.2 TUF

- Client: `tough` ≥ 0.24.0. This is above the 2026 advisory floors of 0.22.0 [R18].
- The initial root is embedded in the app. Persisted state holds the trusted root and versions.
- Roles: root and targets keys offline; snapshot and timestamp keys on the maintainer machine.
- Expiry: timestamp 7 d, snapshot 14 d, targets 90 d, root 365 d.
- Offline import is a TUF repository directory or archive verified through a file transport, using exactly the same code path.
- **Staging paths are never derived from repository target names** (Phase 0 finding, X2). `tough::TargetName` normalizes `../../x` to `x` instead of rejecting it, and keeps absolute names absolute, so `dir.join(name.resolved())` can escape. Rift stages only names from a fixed allowlist of pack files, and only when the raw name is already in normal form.
- Metadata size limits are set far below tough's defaults: timestamp 16 KiB, snapshot 64 KiB, targets 1 MiB, root 64 KiB.
- Flow: fetch bounded metadata → verify signatures, thresholds, versions, expiry, hashes, and lengths → download targets into staging → validate the binary tables and JSON schema → compile rules in a worker (smoke test) → run fixture lookups → atomic pointer swap → retain the previous snapshot until no job references it.
- Scans already in progress stay pinned to their starting snapshot.
- If the installed data has expired and no update is possible, Rift keeps using it offline with a prominent **stale** warning. Clock problems are surfaced to the user; the expiry check is never bypassed.

### 13.3 Sources and licensing

| Source | Data | Status |
|---|---|---|
| First-party demo pack | Harmless test indicators and rules (EICAR-style fixtures) | V1. Labelled "DEMO — not real coverage". |
| abuse.ch URLhaus / MalwareBazaar | URL and hash indicators | **Blocked for redistribution.** The Nov 2025 terms grant free access for not-for-profit use, route commercial use through Spamhaus, and require consent for adaptation or derived works [R17]. Options: written permission, or a direct adapter using the user's own auth key. |
| OpenPhish community | Phishing URLs | The terms need review before any use. |
| Curated YARA rules (e.g. signature-base) | File patterns | Per-rule license review. Signature-base defaults to DRL 1.1. |
| Google Safe Browsing (via WebView) | Phishing and malware URLs | An engine feature the user can enable (§8.4). It is not part of Rift's packs. |

No shared upstream API secret ships in the app. Scraped data is never substituted for licensed feeds.

## 14. Rift Vault

### 14.1 Format

- **Objects:** each saved object is an age v1 file [R19] encrypted to the vault's X25519 recipient, stored as `vault/objects/<ObjectId>.age`. ObjectIds are random, so filenames do not reveal content hashes.
- **Index:** `vault/index.age`, a postcard-serialized `VaultIndex { format_version, generation, entries[] }`, encrypted to the same recipient. Each entry records the ObjectId, plaintext SHA-256, size, display name, detected type, source kind, an optional source URL, timestamps, and the last scan summary.
- **Writes:** write `index.age.tmp`, fsync it, rename it over the old index, and fsync the directory. `index.age.prev` is kept for crash recovery.
- After decrypting an object, the plaintext hash is checked against the index. This detects ciphertext swapped between objects.
- **The index is authenticated, not just encrypted** (Phase 0 finding, X1). age recipient encryption is not sender-authenticated: anyone who knows the public recipient can produce a well-formed age file. The index plaintext therefore ends with an HMAC-SHA256 keyed from the vault identity. The MAC is verified *before* the index is parsed. Objects are trusted only through the hash and size recorded in this authenticated index.
- If the current index is absent (a crash between the two renames), the previous index is used. If it is present but invalid, reading fails rather than silently falling back, which would amount to a rollback.
- **Why age:** a reviewed specification, chunked STREAM construction with truncation detection, and a maintained Rust implementation. It replaces a custom libsodium format (ADR-07). The crate is pre-1.0, so it is pinned and covered by format regression fixtures.

### 14.2 Keys

- **Android:** the vault identity (age X25519 secret) is wrapped by the Keystore key (§8.7).
- **Linux:** the identity is stored as an age **passphrase-encrypted** (scrypt) identity file. A Secret Service adapter is post-V1.
- The identity exists in memory only while unlocked. It is zeroized on lock on a best-effort basis; Rift does not claim every runtime copy is erased.
- Lock happens on user request, after an inactivity timeout (default 5 min), and when the app is backgrounded (configurable). On lock, preview jobs are stopped, fds are closed, displayed plaintext is cleared, and the identity is dropped.

### 14.3 Leakage and limits

- **Leaked:** object count, ciphertext sizes, file modification times, and the index size.
- **Not covered:** WebView and WebKit cookies and cache. These are session-scoped and destroyed on reset, but are not vault-encrypted.
- **Scale limit:** the single-file index is rewritten on each change. That is fine up to roughly 10,000 objects. Migrate (for example to SQLCipher) only if that limit is reached.
- Uninstalling the app or invalidating the key loses the vault unless a recovery passphrase was set. This is stated plainly to the user.

## 15. Sessions

```text
CREATING ─▶ ACTIVE ─▶ RESETTING ─▶ DESTROYED
               │           └────▶ CLEANUP_FAILED (shown; retried on next launch)
               └─▶ RECOVERY_PENDING (marker found at launch)
```

- One active session at a time in V1.
- **Generation:** a `u64` persisted in a recovery marker. It changes on every reset, and any result carrying an older generation is rejected.
- **Android reset:**
  1. Cancel transfers and retire workers.
  2. Drop the session key, which crypto-shreds quarantine.
  3. Ask `:browser` to finish, then `killProcess`. Wait for binder death.
  4. Delete `app_webview_s<gen>` and the WebView cache directories for that generation, **and every file in `shared_prefs/`**. PoC A2 found that WebView writes `AwOriginVisitLoggerPrefs.xml` (hashes of visited origins with a date) and `WebViewChromiumPrefs.xml` at the app level, outside the suffix. Rift therefore never stores its own state in SharedPreferences, so this directory can be deleted default-deny.
  5. Verify the inventory against an **allowlist** of Rift's own files: anything else is a leftover, so a new kind of engine state is detected even before it is understood. The Phase 2 allowlist is `files/rift/**` and `files/profileInstalled` (written by `androidx.profileinstaller`; it contains no browsing data).
  6. Increment the generation.
- **Linux reset:** the same steps, with WebKit's `WebKitNetworkSession` set to ephemeral (`webkit_network_session_new_ephemeral`), which keeps data in memory, and termination of the web process.
- **Recovery on launch:** if the marker says ACTIVE or RESETTING, cleanup completes *before* any new session is presented as fresh **[PoC A2]**.
- Inactivity reset: 15 min by default, configurable. This is best effort under platform scheduling.

## 16. Rift AI (deferred, gated)

The AI classifier is **not in V1**. It is Phase 6, and ships only if it adds measured value. These principles carry forward from v1.1:

- The AI is advisory only. It never grants permissions, changes confinement, overrides a known-malicious hit, or produces a "safe" label. Rift must work fully with the AI disabled, missing, or corrupt, in which case the UI shows "AI unavailable".
- Candidate model: logistic regression or small gradient-boosted trees over lexical URL features and hashed character n-grams. It is trained offline with Python and scikit-learn on licensed, provenance-tracked data, with domain-separated and time-separated holdouts. The report covers precision, recall, false-positive rate, calibration, and a comparison against heuristics alone **and** against Safe Browsing.
- Shipped as fixed-schema numeric data in a signed pack. Inference is direct Rust arithmetic with golden-vector tests. There is no ONNX runtime, Python, pickles, or downloaded code.
- Budgets: artifact ≤ 2 MiB, extra memory ≤ 8 MiB, p95 inference ≤ 15 ms on the reference phone.
- No training on user data and no URL telemetry.

## 17. Privacy and network behaviour

| Behaviour | Local Protection (default) |
|---|---|
| URL and file checks | On device |
| Content-specific queries by Rift | None |
| Intelligence updates | Manual. Contacts the configured update host, which sees connection metadata only. |
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
| New session to first paint (cold, including WebView init and `:browser` start) | ≤ 1.5 s |
| Local URL decision (canonicalize, lookups, heuristics) | p95 ≤ 5 ms |
| Hashing and encryption during transfer | Not the bottleneck at network speed; ≥ 200 MB/s on device |
| Worker cold start (Android, app zygote) | ≤ 300 ms |
| First PDF page (1–5 MB file), image preview | ≤ 1.5 s, ≤ 0.5 s |
| Idle CPU and wakeups | Zero: no services, polling, or schedulers in V1 |
| APK size added by Rift's native code (per ABI) | ≤ 25 MB |
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
| Linux UI | gtk4-rs, libadwaita, webkit6 (GNOME runtime) | runtime-provided |
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
| 02 | Browser in a dedicated `:browser` process | ProfileStore-only disposal | Process death plus deleting the directory works on every provider. It also keeps keys out of the escape-reachable process. | — |
| 03 | One rule engine: YARA-X (`pulley`) | libyara on Android plus YARA-X on Linux | One engine means one rule dialect, one test matrix, and a memory-safe implementation. `pulley` removes JIT; Cranelift on aarch64 had a 2026 sandbox-escape fix [R07]. YARA-X's C-API Android issue #344 is still open, so we use the Rust API [R06]. | PoC A5 fails (size or speed) → libyara on both platforms. |
| 04 | Single APK in V1 | Two APKs (separate browser UID); work profile | Two APKs are the only stronger Android boundary, but cost install friction and double the release work. The interface is kept narrow so the split remains possible. | The threat model needs vault protection against a full browser-host compromise. |
| 05 | Linux workers: seccomp + Landlock self-lockdown | Bubblewrap | Bubblewrap needs user namespaces, which Flatpak blocks and Ubuntu 23.10+ restricts [R13]. A syscall allowlist is the stronger control for fd-only workers. | — |
| 06 | Linux PDF: PDFium | Poppler (GPL), MuPDF (AGPL) | Permissive license, the same engine family as Android's PdfRenderer, and heavy fuzzing. | — |
| 07 | Vault: age format and an encrypted index file | libsodium plus a custom format; SQLite with encrypted fields; SQLCipher | Avoids designing our own crypto format. Encrypting all metadata leaks less than per-field encryption. `sodiumoxide` has been archived since 2021. | More than 10,000 objects → SQLCipher. |
| 08 | Intel: memory-mapped sorted hash tables plus Safe Browsing canonicalization | SQLite; cleartext lists | Trivially validated, fast, compact, atomic to swap, and no complex parser in the update path. | — |
| 09 | TUF via `tough` | A hand-rolled signed manifest; `rust-tuf` | Root rotation, thresholds, and freeze and rollback protection come from an established framework. | — |
| 10 | Linux distribution: Flatpak first | Distro packages | One tested WebKitGTK, patched by the runtime. | — |
| 11 | AI deferred to Phase 6, gated | AI in V1 | Uncertain marginal value over heuristics and Safe Browsing. Keeps V1 focused. | — |
| 12 | Images: Rust decoders | Platform BitmapFactory, ImageDecoder | Memory-safe decoders. The libwebp CVE-2023-4863 is a precedent for C codec risk. | — |
| 13 | License: MIT OR Apache-2.0 | GPL | Compatible with every chosen dependency (BSD, MIT, Apache, MPL). Can be revisited before outside contributions. | Maintainers choose otherwise. |

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
    rift-linux/      GTK4 application           (Phase 5)
  android/           Gradle project             (Phase 2)
  tools/             maintainer pack builder    (Phase 3)
  ml/                offline training           (Phase 6)
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
| **4: Vault** | Keystore and passphrase key providers, lock/unlock, save and export UI | Crypto and lifecycle tests; plaintext-on-disk inventory clean; report. |
| **5: Linux** | GTK4 + WebKitGTK Flatpak, worker lockdown, shared core | Same functional contract plus Linux confinement tests; report. |
| **6: AI experiment** | Training notebook, model card, Rust inference | Ships only if it adds measured value within budget. |
| **7: Hardening** | Fuzz campaigns, fault injection, privacy captures, ProxyController study, dependency review | Release gates (§24). |

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
| L1 | Is the WebKit sandbox actually active in Flatpak? | The WebProcess shows seccomp and namespaces on Fedora and Ubuntu. Rift's detector refuses when it is absent. |
| L2 | Does the worker lockdown hold? | Natively, inside Docker, and inside Flatpak: open, socket, execve, ptrace, and kill are denied. Allowed work succeeds. |
| L3 | Is the sealed-memfd output immutable? | After sealing, writes from the worker fail; the controller verifies the seals. |
| X1 | Does the vault format detect damage? | Round trip works; truncation, tampering, swapped objects, and a wrong key are each detected. |
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
| S12 | Reset with a saved vault object | Session state gone; vault object intact | INV-8 |
| S13 | Kill during reset | Recovery runs before a fresh session is shown | INV-8 |
| S14 | Renderer crash | Session torn down; app alive | INV-7 |
| S15 | Unsupported WebView configuration (simulated) | Browsing refused | INV-7 |
| S16 | Update with a bad signature, hash, version, expiry, or path | Rejected; current snapshot retained | INV-10 |
| S17 | Interrupted update | Old snapshot active; no mixture of versions | INV-10 |
| S18 | Vault truncation, tamper, swap, or wrong key | Detected; no partial plaintext released | §14 |
| S19 | Plaintext-on-disk inventory after preview, lock, or kill | None found | INV-9 |
| S20 | Local mode traffic capture | No content-specific third-party requests from Rift | INV-11 |
| S21 | Demo rule and indicator match | Expected finding with versions | §12 |
| S22 | New pack adds or removes a rule | Cache invalidation is correct | §12.1 |

Unit, property, and fuzz testing cover URL canonicalization, the table validator, protocol decoding, the policy decision table, session transitions, quota accounting, and the vault format. Harmless fixtures only: no live malware in CI or demos.

## 24. Residual risk register

| Risk | Residual after mitigation | Owner response |
|---|---|---|
| Engine exploit chain reaches `:browser` (same UID) | It can read app files and use non-auth-bound keys; the vault stays protected by auth-bound unwrap only | Document; keep the two-APK option (ADR-04); ship WebView minimum-version checks |
| No site isolation within a session | A renderer compromise from one site can read other sites' data in the same session | One session at a time; encourage reset between unrelated sites |
| Network coverage gaps (subresources, WebSocket, WebRTC) | Some traffic is unchecked | State coverage honestly; Phase 7 ProxyController study |
| Download capture gaps | Some downloads are unsupported | Explicit UI message; no JS bridge |
| Parser or decoder vulnerabilities | Contained by B3; kernel exploits remain | Updates; fuzzing; worker retirement |
| Feed licensing | No real intelligence until rights are obtained | Demo packs; direct-adapter design |
| Signing-key compromise | Bounded by TUF thresholds and root rotation | Offline keys; documented response plan |
| Android developer verification (enforced from 30 Sep 2026 in BR/ID/SG/TH; global rollout planned for 2027) [R22] | Sideloaded builds need a registered identity | Register the package name before distribution |
| Same-user Linux processes | Can read an unlocked vault's files or memory | Out of scope; stated plainly |

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
- Multiple vaults.
- Specific synthetic device APIs.

Executing arbitrary programs remains a different product with a different threat model.

## 27. Glossary

| Term | Meaning |
|---|---|
| Session | A disposable browsing workspace with its own generation, processes, data directory, and ephemeral quarantine key. |
| Quarantine | Session-scoped encrypted storage for untrusted objects. It is not a statement that content is harmless. |
| Vault | Persistent age-encrypted storage for objects the user chose to keep. They remain untrusted. |
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
| Single app process hosting WebView | `:browser` process | Reliable disposal; keys out of the escape-reachable process (ADR-02) |
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
| Distro packaging on Linux | Flatpak first | One tested, runtime-patched WebKitGTK |

Content carried forward unchanged in substance: scope exclusions, the result vocabulary, immutable-object verdict binding, TUF update flow, fail-closed rules, the demonstration sequence (now Phase 2–5 evidence), the AI evaluation methodology, and the honesty rules about claims.
