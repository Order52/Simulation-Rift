# Project status: Simulation-Rift

**As of 18 Oct 2026.** This file summarizes everything done so far, what is finished, what is not, the known limitations and how to work around them, and what is left before the project is complete. Detail and raw evidence live in [`phase-0.md`](phase-0.md), [`phase-1.md`](phase-1.md), [`phase-2.md`](phase-2.md), [`evidence/`](evidence/) and [`../architecture.md`](../architecture.md). Nothing here is an audited security product. No claim below means more than "tested in the stated environment".

## 1. Where the project stands

| Phase (architecture §22) | State |
|---|---|
| 0: Feasibility | **Mostly done.** All 13 PoCs pass or are measured in at least one environment. Open: X3 on a phone, L1 and L2 inside Flatpak, and the wider Android device matrix (physical phones, API 33–35, 16 KB pages). |
| 1: Foundations | **Gate met, with stated limits** ([report](phase-1.md)): unit, property and fuzz tests (6 targets, run in CI), `cargo deny` and `clippy` clean. Fuzzing found and fixed two bugs. Fuzz runs are minutes long, not a release-grade campaign. |
| 2: Android vertical slice | **Built; tested on one device** ([report](phase-2.md)). Shell, `:browser` sessions, captured downloads, isolated preview, reset and recovery; S1–S10, S12–S15, S19 and the image, PDF and text preview tests pass on the API 36 emulator. **Gate open:** the device matrix (API 30/33/34/35, 16 KB pages, a phone) has not run. |
| 3: Scanner and signed intel | Not started (engine and TUF verification proven in PoCs only). |
| 4: Vault | Format done (Phase 1); key providers and UI not started. |
| 5: Linux app | Not started (worker lockdown and WebKit check proven in PoCs). |
| 6: AI experiment | Not started; deferred and gated by design. |
| 7: Hardening | Not started. |

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

### 2.5 Phase 2 code (Android vertical slice)

| Part | What it does |
|---|---|
| `rift-ffi` | UniFFI interface of the controller (main process only): navigation decisions with explained reasons, disposable sessions with recovery, downloads into encrypted quarantine, preview jobs whose worker replies it validates. |
| `rift-core::download` | The core's re-fetch of downloads under INV-13: destination check on every resolved address of every redirect hop, streamed size limit, cookies only to their origin, cancellation at reset. `ureq` + `rustls` + bundled Mozilla roots. |
| `rift-worker-ffi` | UniFFI interface of the worker, loaded only in the isolated process; no core code. |
| `android/` | Compose shell; `:browser` WebView host with the §8.4 configuration; disposal by process death, directory deletion and an allowlist inventory; `PreviewService` (isolated, app zygote) and the controller's `Previewer`. Debug-only misbehaving workers for S3–S7. |
| Tests | 19 instrumented tests plus host-driven S13 and S14 (`android/run-tests.sh`); fixtures in `android/fixtures`. |

Phase 2 findings, added to the list below: 15–20.

## 3. Finished vs. not finished

**Finished (tested, with evidence):**

- The architecture and the decision record.
- PoCs A1–A7 and the worker lifecycle test on Android emulators (API 30, 36); X2 on the host and on Android; L1 (native), L2, L3, X1; X3 on the host.
- The Phase 1 crates listed above, and the Phase 2 additions: 105 host tests pass on macOS (75 `rift-core`, 7 `rift-ffi`, 11 `rift-protocol`, 8 `rift-worker`, 4 `rift-worker-ffi`), plus the Linux-only `no_threads` test in CI; six fuzz targets run in CI; `clippy` and `cargo deny` are clean. The Linux lockdown PoC passes in CI on x86_64 Ubuntu.
- The Phase 2 Android slice on the API 36 emulator: all 19 instrumented tests and S13/S14 pass ([evidence](evidence/phase2-android-api36/)).

**Not finished:**

| Item | What is missing |
|---|---|
| X2 size in the product | The standalone Android binary is 4.8 MB (upper bound); measure tough + aws-lc-rs inside Rift's shared library. |
| X3 on a phone | Run the lookup benchmark on a real arm64 phone. |
| L1 in Flatpak | Run the probe inside a Flatpak on Fedora and Ubuntu; check whether Flatpak also bounds the network process. |
| Android device matrix | API 33/34/35, physical phones, OEM WebView builds, x86_64, a 16 KB page-size device. |
| Deeper fuzzing | Fuzz targets for the worker's decoders; long scheduled campaigns and coverage measurement (Phase 7). |
| Phase 2 gate | The same suite on API 30/33/34/35, a 16 KB page-size image and a physical phone; a release build. |
| Phases 3–7 | Everything in §5. |

## 4. Limitations and how to work around them

### 4.1 Limitations of the development environment

| Limitation | Effect | Workaround |
|---|---|---|
| The Docker VM has ~6 GB with ~1.4 GB free; building YARA-X/Cranelift for Linux in Docker is killed (OOM) | Linux-only Rust tests (`no_threads`) cannot be run locally; they run only in CI | Give Docker Desktop ≥ 8 GB (Settings → Resources) or stop unrelated containers; meanwhile rely on GitHub CI, which runs them on Ubuntu. |
| No physical Android device | All Android evidence is from emulators with software GPU | Connect a phone with USB debugging and run `poc/android-feasibility/run-poc.sh <dir>` (not yet tried on a phone). Without `adb root`, everything except the A1 renderer `/proc` check should still run. |
| Emulator images: only API 30 and 36 installed, no 16 KB page-size image (downloads over this connection stalled) | A1/A4 criteria name 33/34/35; the Phase 2 gate needs the matrix; 16 KB alignment checked only statically | `sdkmanager "system-images;android-35;google_apis_ps16k;arm64-v8a"` (and 33, 34), create an AVD, then `android/run-tests.sh <dir>`. |
| API 30 image has WebView 91 | Old engine; not representative of updated devices | Update WebView from Play on a `google_apis_playstore` image, or use a phone. |
| No Flatpak host | L1 and L2 unverified in the shipping configuration | Run on a Fedora or Ubuntu VM/desktop with `flatpak-builder`. |
| `cargo` is not on PATH in non-login shells | Commands fail with "not found" | `export PATH="$HOME/.cargo/bin:$PATH"`. |
| Slow network: the Gradle wrapper re-downloads its Gradle distribution and stalls | `build.sh` hangs in the Gradle step | Unpack Gradle 9.8.1 once and run `GRADLE=/path/to/gradle-9.8.1/bin/gradle ./build.sh`. |

### 4.2 Limitations of the design (not bugs; stated so they are not over-claimed)

| Limitation | Why | Mitigation or way forward |
|---|---|---|
| A WebView escape lands in `:browser` with the app's UID | Android gives one UID per APK | Vault keys never enter `:browser`; auth-bound Keystore key; minimal Binder interface. Stronger: a separate browser APK (ADR-04, post-V1). |
| `blob:`, `data:` and POST downloads cannot be captured | WebView does not report them or they cannot be re-fetched | Stated as unsupported. For `blob:` and `data:` Rift is never told, so it cannot even show a message. A JavaScript bridge could capture them but would add attack surface, so it is rejected for V1. |
| Android worker is weaker than the Linux worker (exec memory, `AF_UNIX`; NoNewPrivs varies by image) | `isolated_app` policy is set by the OS; ART needs exec memory | Per-thread seccomp filter in the native library, as defence in depth, if it does not break ART (not done yet). |
| Rift's own downloads trust only the bundled Mozilla roots | Chosen so user-installed CAs cannot intercept the core's fetches | Downloads behind a TLS-inspecting proxy fail. Switching to `rustls-platform-verifier` is the documented alternative if that proves unacceptable. |
| Preview input is held in the controller's memory (≤ 32 MiB) | The decrypted copy passes through Kotlin into the memfd | Larger files are not previewed; writing from Rust into the memfd would remove the copy. |
| An Android app cannot inspect the renderer's sandbox at runtime (A1 needed `adb root`) | Other apps' `/proc` entries are hidden | Rift relies on the API ≥ 30 floor and `isMultiProcessEnabled()`, which A1 showed imply an `isolated_app` renderer on the tested builds. |
| The WebView version on a device is outside Rift's control | Updated by Google Play, or not at all on some devices | Minimum-version precondition before browsing (§8.4); the version is recorded in compatibility reports. |
| URL heuristics and YARA rules are not a malware verdict | Offline indicators have limited coverage | Results always state coverage; never "100% safe". |
| WebKitGTK network process unsandboxed in native packages | Upstream design | Ship Flatpak first; native packages only with a stated reduced boundary. |
| Quarantine does not survive a process kill | Keys are ephemeral by design (crypto-shredding) | Intended. Users save to the vault to keep files. |
| Upstream dependencies carry advisories (Wasmtime via YARA-X) | Rift cannot patch them | Scoped `cargo deny` exceptions with an exit condition: remove when YARA-X depends on Wasmtime ≥ 48.0.6. |

## 5. What is left to finish the project

**Phase 0 close-out**
1. X3 on a phone; L1 and L2 inside Flatpak on Fedora and Ubuntu.
2. Run A1–A7 on API 33/34/35, a physical phone and a 16 KB page-size image.

**Phase 2: Android vertical slice** (items 3–5 built and tested on API 36; see [phase-2.md](phase-2.md))
3. ~~Compose UI shell; the `:browser` session with the WebView configuration from §8.4; navigation policy wired through the core.~~ Done.
4. ~~Download capture → core re-fetch → encrypted quarantine, with the unsupported cases shown as such.~~ Done.
5. ~~Previews (images and PDF in the isolated worker, text as escaped plain text); reset and recovery.~~ Done (P1, P2, S3–S7, S12, S13, S19).
6. Security tests on the device matrix: **API 36 done; API 30/33/34/35, 16 KB pages and a phone open.** Also open: the per-thread seccomp filter, a release build.

**Phase 3: Scanner and signed intel**
7. YARA-X scan jobs, verdict cache bound to rule and engine versions.
8. TUF update and offline import; a demo intel pack; `tools/` pack builder. No real malware samples in the repository.

**Phase 4: Vault**
9. Keystore and passphrase key providers, lock/unlock, save and export with warnings; plaintext-on-disk inventory test.

**Phase 5: Linux**
10. GTK4 + WebKitGTK Flatpak app on the shared core, with the worker lockdown and the fail-closed sandbox check.

**Phase 6 and 7**
11. Optional AI experiment, shipped only if it adds measured value.
12. Hardening: fuzz campaigns, fault injection, privacy network captures, dependency review, release gates (§24), and an external security review before any release claim.

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
| Android Phase 2 suite | `android/build.sh`, then `android/run-tests.sh <out-dir>` with one emulator attached (S13/S14 need `adb root`) |
