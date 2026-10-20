# Project status: Simulation-Rift

**As of 20 Oct 2026.** For a short current snapshot, see [`../../STATUS.md`](../../STATUS.md). This file summarizes everything done so far, what is finished, what is not, the known limitations and how to work around them, and what is left before the project is complete. Detail and raw evidence live in [`phase-0.md`](phase-0.md), [`phase-1.md`](phase-1.md), [`phase-2.md`](phase-2.md), [`phase-3.md`](phase-3.md), [`phase-4.md`](phase-4.md), [`phase-7.md`](phase-7.md), [`dependencies.md`](dependencies.md), [`browser-isolation.md`](browser-isolation.md), [`evidence/`](evidence/) and [`../architecture.md`](../architecture.md). Nothing here is an audited security product. No claim below means more than "tested in the stated environment".

## 1. Where the project stands

| Phase (architecture §22) | State |
|---|---|
| 0: Feasibility | **Mostly done.** All 13 PoCs pass or are measured in at least one environment. Open: X3 on a phone, L1 and L2 inside Flatpak, and A1–A7 on API 33/34 and a physical phone (the Phase 2 suite, which builds on them, passes on API 33/34). A1–A7 now also pass on a 16 KB page-size emulator (API 35). |
| 1: Foundations | **Gate met, with stated limits** ([report](phase-1.md)): unit, property and fuzz tests (6 targets, run in CI), `cargo deny` and `clippy` clean. Fuzzing found and fixed two bugs. Fuzz runs are minutes long, not a release-grade campaign. |
| 2: Android vertical slice | **Built; tested on emulators** ([report](phase-2.md)), and since 20 Oct on architecture 2.1: the browser is a separate app with its own UID behind a network lock, wiped by Android at every reset ([report](browser-isolation.md); S23–S28 and the whole earlier suite pass on API 36). Shell, browser sessions, captured downloads, isolated preview, reset and recovery. S1–S10, S12–S15, S19 and the image, PDF and text preview tests pass on API 36 and on API 35 with 16 KB pages (arm64), and on API 33 and 34 (x86_64, in CI). API 30 refuses browsing as designed. The R8 release build passes a smoke test. **Gate open:** a physical phone. |
| 3: Scanner and signed intel | **Built and tested on the host and on Android emulators** ([report](phase-3.md)). Pack validation, verdicts with a versioned cache, an atomic snapshot store, TUF updates (offline import of a user-chosen folder through the system picker, and online updates through the core's own checked fetcher), a clock warning, and `rift-pack` with a harmless demo pack. On Android every download is scanned (core hash and type checks, then the rules in a fresh isolated worker, two at a time) and the verdict is shown. Release builds verify against a production root given at build time (`RIFT_INTEL_ROOT`). **Open:** the production key policy (offline keys, thresholds, rotation) and licensed real feeds. |
| 4: Vault | **Built and tested on the host and the API 35 emulator** ([report](phase-4.md)): a Keystore key behind BiometricPrompt (or a passphrase), keep from quarantine, warned export, lock on request, in the background and when idle, and a no-plaintext-on-disk inventory. Kept files preview in an isolated worker until the vault locks; a recovery passphrase opens a vault whose key was lost. **Open:** a physical phone (the emulator's Keystore is software only). |
| 5: Linux app | Not started. **Moved to the last step** and **to Qt instead of GTK4** (decided 20 Oct 2026); the design will be revised before any code. |
| 6: AI experiment | Not started; deferred and gated by design. |
| 7: Hardening | **Started on Android** ([report](phase-7.md)): privacy measurements x1 (local work and updates move no byte on real networks; nothing scheduled) and x2 (browsing leaves only through the controller's proxy) pass on API 35; the dependency and licence inventory is written ([inventory](dependencies.md)). **Open:** fault injection, long fuzz campaigns, in-app licence notices, an Android advisory check, an external review, and release gates that need a phone. |

## 2. What was done

### 2.1 Architecture review (v2.0)

The original specification was reviewed and replaced by `docs/architecture.md`: threat model, trust boundaries, 13 security invariants, Android and Linux designs, decision record, roadmap with phase gates, acceptance tests, and a residual-risk register. Main decisions:

- Android browsing uses the system **WebView** in a separate `:browser` process (not GeckoView or a Chromium fork). Disposal is "kill the process and delete its generation directory".
- One shared **Rust** core (trusted logic) and one shared worker library (untrusted parsing) for both platforms.
- **YARA-X** with the `pulley` interpreter (no JIT) as the only rule engine.
- **age** for the vault and quarantine; ephemeral per-session keys crypto-shred quarantine.
- **TUF** (`tough`) for signed intelligence updates, verifiable offline.
- Linux ships as a **Flatpak** using WebKitGTK; workers lock themselves down with seccomp, Landlock and rlimits.

### 2.2 Phase 0 proofs of concept

| ID | Question | Result | Where |
|---|---|---|---|
| A1 | Is the Android WebView renderer sandboxed? | Pass on API 30 and 36 | [evidence](evidence/phase0-android.md) |
| A2 | Is session disposal complete, also after a crash? | Pass; found a WebView leak outside the session directory, now fixed | same |
| A3 | Which downloads can be captured? | URL downloads yes; POST, `blob:`, `data:` no | same |
| A4 | PdfRenderer in an isolated process? | Pass on API 30 and 36 | same |
| A5 | YARA-X on Android? | Pass on arm64; adds 14 MB to the APK for arm64 | same |
| A6 | Is the Android worker cut off from files and network? | Pass; `AF_UNIX` and exec memory still allowed | same |
| A7 | RAM-backed seekable fd handoff? | Pass (sealed memfd) | same |
| L1 | Is the WebKitGTK sandbox active, and can Rift detect it? | Pass for the native package in Docker; Flatpak open | [evidence](evidence/phase0-L1-docker.md) |
| L2 | Does the Linux worker lockdown hold? | Pass in Docker (aarch64) and GitHub CI (x86_64 Ubuntu); Flatpak open | [Docker](evidence/phase0-L2-L3-docker.md), [CI](evidence/phase0-L2-L3-ci-ubuntu.md) |
| L3 | Is the sealed-memfd output immutable? | Pass | same |
| X1 | Does the vault format detect damage? | Pass | `cargo test -p rift-core vault` |
| X2 | Can TUF be verified offline? | Pass on host and on Android (API 30, 36 emulators) | [host](evidence/phase0-X2-host.md), [Android](evidence/phase0-X2-android.md) |
| — | Android worker lifecycle: cold start, signals, timeout, stuck worker | Measured: app zygote required; kill denied; timeout fires; unbind retires a stuck worker | [evidence](evidence/phase0-android.md) |
| X3 | Are URL lookups fast and correct? | Pass on host and API 36 emulator (p95 11.6 µs); phone open | [host](evidence/phase0-X3-host.md), [Android](evidence/phase0-X3-android.md) |

### 2.3 Phase 1 code (Rust workspace)

| Crate / module | What it does |
|---|---|
| `rift-protocol` | Controller ⇄ worker messages. Frames are size-checked before allocation and every response is validated against the request (version, job, generation, bounds). `#![forbid(unsafe_code)]`. |
| `rift-core::urlcanon` | Safe Browsing-compatible URL canonicalization and lookup expressions; passes all published examples; idempotence property-tested. |
| `rift-core::intel` | Fully validated binary indicator tables with fast lookups. |
| `rift-core::heuristics` | Explainable URL flags (confusables and mixed scripts via UTS #39). Flags never produce "known malicious". |
| `rift-core::policy` | Pure navigation policy; refuses to browse when the engine sandbox is not verified. |
| `rift-core::transfer` | Download destination policy and display-name hygiene. |
| `rift-core::store` | Encrypted object store with atomic commit and crash cleanup. |
| `rift-core::session` | Session generations, ephemeral quarantine keys, recovery marker. |
| `rift-core::vault` | age-encrypted, HMAC-authenticated vault format. |
| `rift-worker` | Shared job logic: rule loading, YARA-X scans, bounded image decoding. Deadline mode chosen per platform. |

Tooling: pinned Rust toolchain (1.99.1), `clippy` with strict lints, `cargo deny` (licenses and RustSec advisories, with scoped and justified exceptions), and CI on Ubuntu and macOS plus a Linux lockdown job.

### 2.4 Findings that changed the design

These were all found by tests, not by reading:

1. age recipient encryption is not sender-authenticated, so the vault index is now HMAC-authenticated (X1).
2. `tough` normalizes hostile target names instead of rejecting them, so Rift stages only allowlisted flat names (X2).
3. Three idempotence bugs in URL canonicalization, found by property tests and fixed (X3).
4. YARA-X 1.21.0 pins a Wasmtime version with seven advisories. These were triaged: six cannot apply to Rift's configuration and one is contained by worker confinement.
5. YARA-X timeouts start a thread, which would escape the Linux worker's per-thread seccomp/Landlock. The Linux supervisor now enforces deadlines by killing the worker, and the lockdown refuses to start if more than one thread exists.
6. WebKitGTK's network process is not sandboxed in a native package, which supports shipping Flatpak first. The web-process check identifies processes by `comm`.
7. WebView writes a record of visited origins (`AwOriginVisitLoggerPrefs.xml`) outside the per-session directory. Reset now deletes all shared preferences and checks the inventory against an allowlist.
8. `blob:` and `data:` downloads never reach `DownloadListener`, so the product claim is limited to downloads served at a URL.
9. Android's `isolated_app` still allows `AF_UNIX` sockets and executable memory, so a per-thread seccomp filter is planned as defence in depth.
10. The YARA-X native library adds 14 MB (arm64) to 18 MB (x86_64) per ABI, stored uncompressed, against a 25 MB budget. Anything else native on Android (for example `tough` and `aws-lc-rs` for X2) must fit in what remains.
11. A worker forked from the system zygote misses the 300 ms cold-start budget on API 36 (median 304 ms); from the app zygote it takes 45 ms, so `useAppZygote` is required. The app cannot signal its worker, so the in-process YARA-X timeout is needed (and works), and unbinding is the kill switch.
12. The X2 test script let one tamper test pass for the wrong reason (a missing file). Every rejection is now checked for its expected reason.
13. Fuzzing (Phase 1): bracketed URL hosts were not canonicalized consistently, so the same URL could hash differently. Brackets are now accepted only as a whole IPv6 literal.
14. Fuzzing (Phase 1): shortening a long download name could hide its real extension (`invoice<padding>.pdf.exe` shown as `…pdf`). Long names now keep the final extension.
15. WebView 133 exposes a Media Integrity API (`window.android.webview`) to every page, whose token provider calls Play Integrity. It is now disabled, and S1 checks the refusal.
16. `androidx.profileinstaller` writes `files/profileInstalled`; the default-deny inventory caught it, and it is allowlisted (no browsing data).
17. `isMultiProcessEnabled()` loads the WebView provider, so the data-directory suffix must be set before the sandbox check.
18. Killing the main process while `:browser` is bound makes Android restart it immediately; recovery runs in that restart, before a session is shown (S13).
19. Isolated-service instance names may contain only letters, digits and `_` (`preview-1` is rejected).
20. Workers forked from the app zygote showed `NoNewPrivs: 1` on the API 36 image (Phase 0 saw 0 for system-zygote workers). Recorded, not relied on.
21. PdfRenderer loads PDFium lazily; with the parser-thread filter already installed the load fails, so the worker preloads it with a built-in PDF first.
22. Release builds also write `files/profileinstaller_profileWrittenFor_lastUpdateTime.dat`; the first release reset failed closed on it, as designed, and it is now allowlisted.
23. The app freezer can freeze a backgrounded `:browser`, so a synchronous shutdown call can fail; disposal kills and verifies regardless.
24. On a refused engine (API 30) and before any page loaded, the trusted bar read "Not flagged · threat database current". It now says only what the core actually decided, and N4 checks it.
25. WebView 91 starts a renderer process as soon as the provider loads, even with no WebView; it ends with `:browser` at reset.
26. A test that loaded WebView in the main process created an unsuffixed `app_webview/`; the next reset failed closed on it. The main process must never touch WebView, and the inventory catches it if it does.

### 2.5 Phase 2 code (Android vertical slice)

| Part | What it does |
|---|---|
| `rift-ffi` | UniFFI interface of the controller (main process only): navigation decisions with explained reasons, disposable sessions with recovery, downloads into encrypted quarantine, preview jobs whose worker replies it validates. |
| `rift-core::download` | The core's re-fetch of downloads under INV-13: destination check on every resolved address of every redirect hop, streamed size limit, cookies only to their origin, cancellation at reset. `ureq` + `rustls` + bundled Mozilla roots. |
| `rift-worker-ffi` | UniFFI interface of the worker, loaded only in the isolated process; no core code. |
| `android/` | Compose shell; `:browser` WebView host with the §8.4 configuration; disposal by process death, directory deletion and an allowlist inventory; `PreviewService` (isolated, app zygote) and the controller's `Previewer`. Debug-only misbehaving workers for S3–S7. |
| Tests | 20 instrumented tests plus host-driven S13 and S14 (`android/run-tests.sh`); fixtures in `android/fixtures`. |

Phase 2 findings, added to the list above: 15–26.

27. (Phase 3) A tampered TUF target that only grows is caught by tough's length check before its hash; the test now covers a same-length change too.
28. (Phase 3) The X2 PoC's staging allowlist (`meta.json`, `notices.txt`) did not match the product pack, which is four files (`rift_core::pack::FILES`) with notices inside `metadata.json`.
29. (Phase 3) `build.sh` first put the demo keys under `~/.config`, which is a git repository on the development machine; `rift-pack` refused, and the default moved to `~/.local/share`.
30. (Phase 3) tough and aws-lc-rs took `librift_ffi.so` from 3.15 to 7.45 MB (arm64) and from 3.52 to 8.32 MB (x86_64). Native code per ABI is now 19.3 MB (arm64) and 24.0 MB (x86_64) against the 25 MB budget.
31. (Phase 3) A scan worker that hangs outside YARA-X is stopped by the controller's 17 s deadline, not the engine's 15 s timeout; scans run one at a time, so the queue waits too.
32. (2.1) A `ResultReceiver` subclass cannot be unparcelled in another app; cross-app tests re-parcel it as a plain one.
33. (2.1) A VPN app must call `VpnService.prepare()` itself even with consent pre-granted, or its VPN never starts.
34. (2.1) Publishing a UI state update per packet the lock drops overloaded the emulator until system services stopped answering; counts are now published once a second at most.
35. (2.1) After the controller is killed, Android recreates its activity with the original `VIEW` intent; the home screen reopened the old link in the new session. Links are now taken only from fresh intents.
36. (2.1) androidx.core adds a signature permission of the app's own (`DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION`) to every app that uses it.
37. (2.1) A "System UI isn't responding" dialog left over from boot covered every window on the API 35 emulator; the six screen-reading tests and S13 failed. Test runs now close system dialogs and record every ANR and crash in `anr.txt`.
38. (2.1) On CI's API 34 emulator the first bind to the browser after Android cleared its data did not connect within 10 s, so the reset failed and so did every test after it. The bind is retried up to three times, and tests after a failed reset retry cleanup as a user would.
39. (Phase 3) tough reports a target's hash or length mismatch as the cause of a transport error. Rift's refusal reason therefore comes from the innermost tough error in the chain.
40. (Phase 3) `run-tests.sh`'s worker summary still matched process names from before workers were named `worker_N`, so `workers.txt` stayed empty. It is fixed, and API 35's summary was regenerated from its process samples.

41. (Phase 4) On the API 35 emulator, removing the screen lock deleted the vault's Keystore key outright instead of leaving an invalidated key; both cases now give the same message and the offer to delete the vault.
42. (Phase 4) A new Keystore key under the same alias replaces the old one, so creating a vault while one exists would destroy it. Creation refuses first, and the core asks the platform for nothing when a vault exists.
43. (Phase 4) Locking on `onStop` also locked the vault behind the export picker and the authentication prompt. While a system screen that Rift opened for the vault is in front, the background lock waits; the inactivity lock still applies.
44. (Phase 4) The emulator's Keystore reports "software only". The vault card shows the security level, and hardware backing stays unverified until a phone is tested.
45. (Phase 4) S16d's local failures: the address field had focus, and the keyboard covered the lower half where the script's swipes started, so the page never scrolled. The script now hides the keyboard first, only while Android reports it shown. Why the field had focus after a restart is not known.
46. (Phase 4) On a cold CI emulator (API 34), Android took over 10 s to confirm the browser app's first data clear (9.2 s on the retry, about 0.4 s afterwards), which failed the first session. The clear confirmation now has its own 30 s bound and logs its duration; running out still fails the reset.
47. (Phase 4, open) On CI (API 34, run 39379866862), s28 failed once: 50 ms after the test opened a new browser window (just after the wipe that followed losing the lock), Android removed the window's task ("remove task") and the window never showed. The outcome was safe (nothing loaded), but a user would have to open the window again. Rift's code removes no tasks; the cause is not confirmed (the force-stop of the clear and the new `singleTask` start may race). The test now opens the window up to three times and reports how many it needed.
48. (Phase 4) age chose the scrypt work factor by timing the device, and accepted at most its current measurement + 4 when unlocking. In a full run the right passphrase was refused in 0.2 s, without scrypt running, right after the launcher came to the front; Rift called it a wrong passphrase. Every passphrase wrapping now uses N = 2^17 and unlocking accepts exactly that; a heavier file is reported as data Rift did not write. The cause is inferred from the timing and the error type; the factors were not logged.
49. (Phase 7) The local emulator's DNS proxy stopped answering after a long uptime (the shell could not resolve names either, with Rift stopped). The privacy test's control therefore uses an IP address, not a name; a restart of the emulator fixed DNS.
50. (Phase 7) The core refused all of `64:ff9b::/32`, and the proxy and the downloader refuse a name if any of its addresses is refused. On a DNS64 network (common on IPv6-only mobile networks) every IPv4-only host also resolves to `64:ff9b::<IPv4>`, so all of them were refused; the host network test found it on the development network. Addresses in the well-known `64:ff9b::/96` are now judged by the IPv4 address they carry; the rest of the /32 (including local-use `64:ff9b:1::/48`) stays refused.
51. (Phase 7) Two crypto libraries shipped: `ureq`'s TLS used `ring`, `tough` uses `aws-lc-rs`. The core's TLS now uses rustls' aws-lc-rs provider and `ring` is in no build. `librift_ffi.so` went from 7.76 to 7.50 MB (arm64) and from 8.66 to 8.99 MB (x86_64, since aws-lc's x86_64 cipher code is now linked). Native code per ABI is now 19.2 MB (arm64) and 24.5 MB (x86_64); x86_64 has 0.5 MB of the 25 MB budget left. TLS was rechecked on the host and on the device (x2).

### 2.8 Phase 4 code (vault)

| Part | What it does |
|---|---|
| `rift-core::locker` | The vault directory: a wrapped identity (passphrase or platform), the authenticated index, sealed objects; unlock sweeps unlisted files; saves are crash-safe. |
| `rift-ffi::vault` | `VaultHandle`, the `PlatformKey` foreign trait, and `Sessions::save_to_vault` (quarantine to vault without plaintext on disk). |
| Android `VaultKeystore`, `Locker` | The AES-GCM Keystore key (StrongBox, else TEE; unlocked device; per-use authentication), BiometricPrompt with a CryptoObject, the lock policy, keep, export and delete; the vault card and "Keep in the vault". |

### 2.7 Architecture 2.1 code (browser app and network lock)

| Part | What it does |
|---|---|
| `rift-core::egress` | The browser's only way out: an HTTP proxy on 127.0.0.1 with a per-session port, token and realm; `CONNECT` and absolute `http://` only, bounded heads, one resolution per hop with INV-13's destination rule, no TLS inspection. Fuzzed (`egress_head`). |
| `rift-ffi::egress` | One proxy per session, started when the browser registers, following the session's host exceptions, stopped before the browser is wiped. |
| `android/bridge` | Shared Binder interfaces and codecs, package identities, and the per-call UID and signer check. |
| `android/browser` | The browser app: `BrowserActivity` in `:web` (proxy override with implicit rules removed, VPN check, proxy-only credential answer) and `SessionService` (pid, inventory, system wipe). |
| `android/app` | `NetworkLockService` (a VPN for the browser only that drops everything), the exported, signature-checked `CoreService`, wipe-based disposal, the lock and reduced-isolation UI. No WebView. |
| `android/outsider`, escape probe | Test apps for S23, S24, S26 and S28. |

### 2.6 Phase 3 code (scanner and signed intel)

| Part | What it does |
|---|---|
| `rift-core::pack` | Validates a pack: the four fixed files within their limits, strict metadata, tables pointing into the metadata, a digest over every file. |
| `rift-core::scan` | Evidence to status (§12.3, never "safe"); verdict cache keyed by object, engine, pack digest and policy. |
| `rift-core::snapshot` | Digest-named snapshots made current by an fsynced pointer swap; interrupted installs leave the old one. |
| `rift-update` | Offline TUF verification with tough (no HTTP), then install through the snapshot store. |
| `tools/rift-pack` | Role keys (outside git), signed root, the demo pack, signed releases. |
| `rift-ffi::scan` | The controller API for Android: the threat database, verified updates that a worker must compile before install, and scan jobs whose replies the core validates. |
| Android `IsolatedWorker`, `Scanner` | One fresh isolated worker per scan (seccomp required, deadlines, unbound after); the verdict under each download; a database card; the signed demo database in debug builds. |

## 3. Finished vs. not finished

**Finished (tested, with evidence):**

- The architecture and the decision record.
- PoCs A1–A7 and the worker lifecycle test on Android emulators (API 30, 36); X2 on the host and on Android; L1 (native), L2, L3, X1; X3 on the host.
- The Phase 1 crates listed above, and the Phase 2 and 3 additions: 132 host tests pass on macOS (92 `rift-core`, 8 `rift-ffi`, 11 `rift-protocol`, 7 `rift-update`, 10 `rift-worker`, 4 `rift-worker-ffi`), plus the Linux-only `no_threads` test in CI; six fuzz targets run in CI; `clippy` and `cargo deny` are clean. The Linux lockdown PoC passes in CI on x86_64 Ubuntu.
- The Phase 2 Android slice: all 20 instrumented tests and S13/S14 pass on the API 36 emulator ([evidence](evidence/phase2-android-api36/)) and on API 33 and 34 x86_64 in CI ([33](evidence/phase2-android-api33-x86_64/), [34](evidence/phase2-android-api34-x86_64/)), and the 19 that existed then pass on the API 35 16 KB page-size emulator ([evidence](evidence/phase2-android-api35-16k/)).
- Phase 3: S11, S16, S17, S21 and S22 on the host, and the Android scan path: S16 (tampered update refused on the device), S21 (demo database installs; the demo file is known malicious by hash and rule), no-database scans that name their gaps, and a hung scan worker that costs only rule coverage. The full 24-test suite and S13/S14 pass on API 33 and 34 x86_64 in CI ([33](evidence/phase3-android-api33-x86_64/), [34](evidence/phase3-android-api34-x86_64/)) and on the API 35 16 KB page-size arm64 emulator ([evidence](evidence/phase3-android-api35-16k/), [report](phase-3.md)). The R8 release build passed a UI smoke test on API 36. On API 30 (WebView 91, below the minimum) browsing is refused as designed, so 17 tests that need a page fail; S3, S15 and S13 pass ([evidence](evidence/phase2-android-api30/)).

**Not finished:**

| Item | What is missing |
|---|---|
| X3 on a phone | Run the lookup benchmark on a real arm64 phone. |
| L1 in Flatpak | Run the probe inside a Flatpak on Fedora and Ubuntu; check whether Flatpak also bounds the network process. |
| Android device matrix | Physical phones, OEM WebView builds, a 16 KB page-size device. All emulator levels (30, 33–36, both ABIs, 16 KB pages) have run. |
| Deeper fuzzing | Fuzz targets for the worker's decoders; long scheduled campaigns and coverage measurement (Phase 7). |
| Phase 2 gate | The same suite on a physical phone; the instrumented suite against a release-like build. |
| Phase 3 on Android | Built and passing on API 33–36 (both ABIs, 16 KB pages) on architecture 2.1. Open: a phone, and an import screen for user-chosen updates with a production root (release builds have none; being built). Done since: concurrent scan workers (two), short refusal messages, and a test that running scans keep their snapshot. |
| Online updates | An HTTP transport for tough over the core's own fetcher (INV-13). |
| Phases 4–7 | Everything in §5. |

## 4. Limitations and how to work around them

### 4.1 Limitations of the development environment

| Limitation | Effect | Workaround |
|---|---|---|
| The Docker VM has ~6 GB with ~1.4 GB free; building YARA-X/Cranelift for Linux in Docker is killed (OOM) | Linux-only Rust tests (`no_threads`) cannot be run locally; they run only in CI | Give Docker Desktop ≥ 8 GB (Settings → Resources) or stop unrelated containers; meanwhile rely on GitHub CI, which runs them on Ubuntu. |
| No physical Android device | All Android evidence is from emulators with software GPU | Connect a phone with USB debugging and run `poc/android-feasibility/run-poc.sh <dir>` (not yet tried on a phone). Without `adb root`, everything except the A1 renderer `/proc` check should still run. |
| Apple Silicon cannot run x86_64 emulator images, and large image downloads over this connection are slow | x86_64 and API 33/34 could not run locally | The `android-emulator` CI job runs the suite on x86_64 API 33 and 34 with KVM and uploads the evidence. Local arm64 images: `sdkmanager --sdk_root=$HOME/Library/Android/sdk "system-images;android-NN;google_apis;arm64-v8a"`, create an AVD, then `android/run-tests.sh <dir>`. |
| API 30 image has WebView 91 | Old engine; not representative of updated devices | Update WebView from Play on a `google_apis_playstore` image, or use a phone. |
| No Flatpak host | L1 and L2 unverified in the shipping configuration | Run on a Fedora or Ubuntu VM/desktop with `flatpak-builder`. |
| `cargo` is not on PATH in non-login shells | Commands fail with "not found" | `export PATH="$HOME/.cargo/bin:$PATH"`. |
| Slow network: the Gradle wrapper re-downloads its Gradle distribution and stalls | `build.sh` hangs in the Gradle step | Unpack Gradle 9.8.1 once and run `GRADLE=/path/to/gradle-9.8.1/bin/gradle ./build.sh`. |

### 4.2 Limitations of the design (not bugs; stated so they are not over-claimed)

| Limitation | Why | Mitigation or way forward |
|---|---|---|
| A WebView escape lands in the browser app's `:web` process | The engine's own sandbox can fail | Since 2.1 that process has its own UID (no access to Rift's data), a network route only to Rift's proxy, and is wiped by Android at every reset (S23–S28). It still has the current session's own browsing data and the window. |
| Escaped browser code can reach loopback | No VPN covers loopback, and Android has no per-app loopback control | Pages cannot (the proxy refuses loopback). Stated; the Linux design closes it with a network namespace. |
| One VPN per device | Android runs one VPN at a time | Without the lock the browser refuses to browse; reduced isolation is an explicit, labelled per-session choice. |
| The lock ends with the controller process | The VPN belongs to the controller | The browser exits when the core dies and is wiped at the next launch; escaped code could outlive the controller until then. |
| `blob:`, `data:` and POST downloads cannot be captured | WebView does not report them or they cannot be re-fetched | Stated as unsupported. For `blob:` and `data:` Rift is never told, so it cannot even show a message. A JavaScript bridge could capture them but would add attack surface, so it is rejected for V1. |
| Android worker is weaker than the Linux worker (exec memory, `AF_UNIX`; NoNewPrivs varies by image) | `isolated_app` policy is set by the OS; ART needs exec memory | A seccomp filter on the parser thread now denies sockets, exec mappings, exec and ptrace there (measured on API 36). Other threads share the address space, so it is defence in depth, not a boundary. |
| Rift's own downloads trust only the bundled Mozilla roots | Chosen so user-installed CAs cannot intercept the core's fetches | Downloads behind a TLS-inspecting proxy fail. Switching to `rustls-platform-verifier` is the documented alternative if that proves unacceptable. |
| Preview input is held in the controller's memory (≤ 32 MiB) | The decrypted copy passes through Kotlin into the memfd | Larger files are not previewed; writing from Rust into the memfd would remove the copy. |
| An Android app cannot inspect the renderer's sandbox at runtime (A1 needed `adb root`) | Other apps' `/proc` entries are hidden | Rift relies on the API ≥ 30 floor and `isMultiProcessEnabled()`, which A1 showed imply an `isolated_app` renderer on the tested builds. |
| The WebView version on a device is outside Rift's control | Updated by Google Play, or not at all on some devices | Minimum-version precondition before browsing (§8.4); the version is recorded in compatibility reports. |
| URL heuristics and YARA rules are not a malware verdict | Offline indicators have limited coverage | Results always state coverage; never "100% safe". |
| The only threat database is the demo one | Real feeds need licensing review (§13.3); no real malware is kept in the repository | Every verdict and the database card carry the demo label. Real coverage needs licensed feeds and a production root in release builds. |
| Update expiry trusts the device clock | TUF checks expiry against the system time | A wrong clock shows as "expired", or as current when it is not. The database card warns when the clock reads more than an hour before the database was made (S16f); a clock that is merely fast cannot be detected offline. |
| Demo signing keys are one key per role on one machine | `rift-pack` is a development tool | The §13.2 policy (offline root and targets keys, thresholds, rotation) is needed before any real release. |
| Two scan workers at a time | Each holds its file (≤ 32 MiB) and the rules in memory | A hung worker costs only its own file (S21b: the next file finished at 1.5 s). Two hung workers at once still hold the queue for up to 17 s. |
| WebKitGTK network process unsandboxed in native packages | Upstream design | Ship Flatpak first. The Linux app is moving to Qt (§22), so this is reviewed again for Qt's web engine. |
| The vault key may be software-backed | Devices without a TEE (emulators) have only a software Keystore | The vault card shows the key's security level. On a device with only a software Keystore, the passphrase gives the same protection with no hardware claim. |
| Removing the screen lock deletes the vault's key | Android's rule for auth-bound keys | The optional recovery passphrase opens the vault and a new key protects it again (v3). Without one the vault is lost; the card says so and offers deletion. |
| Quarantine does not survive a process kill | Keys are ephemeral by design (crypto-shredding) | Intended. Users save to the vault to keep files. |
| Upstream dependencies carry advisories (Wasmtime via YARA-X) | Rift cannot patch them | Scoped `cargo deny` exceptions with an exit condition: remove when YARA-X depends on Wasmtime ≥ 48.0.6. |

## 5. What is left to finish the project

**Phase 0 close-out**
1. X3 on a phone; L1 and L2 inside Flatpak on Fedora and Ubuntu.
2. Run A1–A7 on API 33/34 and a physical phone. (Done on the API 35 16 KB page-size image.)

**Phase 2: Android vertical slice** (items 3–5 built and tested on API 36; see [phase-2.md](phase-2.md))
3. ~~Compose UI shell; the `:browser` session with the WebView configuration from §8.4; navigation policy wired through the core.~~ Done.
4. ~~Download capture → core re-fetch → encrypted quarantine, with the unsupported cases shown as such.~~ Done.
5. ~~Previews (images and PDF in the isolated worker, text as escaped plain text); reset and recovery.~~ Done (P1, P2, S3–S7, S12, S13, S19).
6. Security tests on the device matrix: **API 36, API 35 (16 KB pages), API 33 and 34 x86_64 (CI) done on 2.0; on 2.1 (browser app and network lock) API 36, API 35 (16 KB pages) and API 33/34 x86_64 (CI run 39363201440) done; a physical phone open.** Release build: R8 configured and smoke-tested. The parser-thread seccomp filter is done.

**Phase 3: Scanner and signed intel**
7. ~~Verdict assembly and a cache bound to rule and engine versions; the snapshot store; scan jobs on Android after each download.~~ Done (host: S11, S17, S22; Android API 33–36: S21, hung worker). Running scans keep their starting snapshot (rift-ffi test), and two scan workers run at a time (S21b).
8. ~~TUF offline import; a demo intel pack; `tools/` pack builder.~~ Done (host and Android API 33–35: S16, S21). Open: the Android import screen with a production root, online updates, the production key policy. No real malware samples are in the repository.

**Phase 4: Vault**
9. ~~Keystore and passphrase key providers, lock/unlock, save and export with warnings; plaintext-on-disk inventory test.~~ Done on the API 35 emulator (v1–v7), with previews of kept files, a recovery passphrase, the verdict each file had when kept, scanning kept files again, and lock settings. Open: a phone.

**Phase 6 and 7 (Android)**
10. Optional AI experiment, shipped only if it adds measured value.
11. Hardening: ~~privacy network checks~~ (x1, x2 on API 35; [phase-7.md](phase-7.md)) and ~~the dependency and licence inventory~~ ([dependencies.md](dependencies.md)); open: fuzz campaigns, fault injection, in-app licence notices, an Android advisory check, release gates (§24), and an external security review before any release claim.

**Phase 5: Linux (last, decided 20 Oct 2026)**
12. A Qt desktop app on the shared core (not GTK4), with the worker lockdown and a fail-closed engine-sandbox check. The §9 design is revised for Qt and its PoCs redone first.

## 6. Reproducing the evidence

| What | Command |
|---|---|
| Host tests | `cargo test --workspace` |
| Fuzzing | `cargo +nightly fuzz run <target> -- -max_total_time=60` (needs cargo-fuzz; `cargo +nightly fuzz list` shows the targets) |
| Lints and policy | `cargo clippy --workspace --all-targets -- -D warnings` and `cargo deny check` |
| Linux lockdown (L2/L3) | `poc/linux-worker-lockdown` in Docker or the `linux-worker-lockdown` CI job |
| WebKitGTK check (L1) | `poc/linux-webkit-sandbox/run-in-docker.sh` |
| TUF offline (X2) | `poc/tuf-offline/run-scenarios.sh poc/target/release/tuf-offline` (needs `tuftool`); on Android: build with `cargo ndk -t arm64-v8a -P 30 build --release -p tuf-offline`, then pass `poc/tuf-offline/adb-client.sh` as the client with `RIFT_X2_BINARY` set |
| Android A1–A7 | `poc/android-feasibility/build.sh`, then `run-poc.sh <out-dir>` with one emulator or phone attached |
| Android Phase 2 suite | `android/build.sh`, then `android/run-tests.sh <out-dir>` with one emulator attached (S13/S14 need `adb root`); x86_64 API 33/34 run in the `android-emulator` CI job |
| Signed demo pack (Phase 3) | `cargo run -p rift-pack -- keys <dir outside git>`, then `root <keys> <root.json>`, `demo <pack-dir>`, `publish <root.json> <keys> <pack-dir> <repo-dir> 1`; check with `cargo run -p rift-update --example verify -- <root.json> <repo-dir> <datastore>` |
