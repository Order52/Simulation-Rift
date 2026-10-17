# Project status: Simulation-Rift

**As of 17 Oct 2026.** This file summarizes everything done so far, what is finished, what is not, the known limitations and how to work around them, and what is left before the project is complete. Detail and raw evidence live in [`phase-0.md`](phase-0.md), [`evidence/`](evidence/) and [`../architecture.md`](../architecture.md). Nothing here is an audited security product. No claim below means more than "tested in the stated environment".

## 1. Where the project stands

| Phase (architecture §22) | State |
|---|---|
| 0: Feasibility | **Mostly done.** All 13 PoCs pass or are measured in at least one environment. Open: X3 on a phone, L1 and L2 inside Flatpak, and the wider Android device matrix (physical phones, API 33–35, 16 KB pages). |
| 1: Foundations | **Gate met, with stated limits** ([report](phase-1.md)): unit, property and fuzz tests (6 targets, run in CI), `cargo deny` and `clippy` clean. Fuzzing found and fixed two bugs. Fuzz runs are minutes long, not a release-grade campaign. |
| 2: Android vertical slice | Not started (the Phase 0 PoC app is a test harness, not product code). |
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

## 3. Finished vs. not finished

**Finished (tested, with evidence):**

- The architecture and the decision record.
- PoCs A1–A7 and the worker lifecycle test on Android emulators (API 30, 36); X2 on the host and on Android; L1 (native), L2, L3, X1; X3 on the host.
- The Phase 1 crates listed above: 81 unit and property tests pass on macOS (62 `rift-core`, 11 `rift-protocol`, 8 `rift-worker`), plus the Linux-only `no_threads` test in CI; six fuzz targets run in CI; `clippy -D warnings` and `cargo deny` are clean. The Linux lockdown PoC passes in CI on x86_64 Ubuntu.

**Not finished:**

| Item | What is missing |
|---|---|
| X2 size in the product | The standalone Android binary is 4.8 MB (upper bound); measure tough + aws-lc-rs inside Rift's shared library. |
| X3 on a phone | Run the lookup benchmark on a real arm64 phone. |
| L1 in Flatpak | Run the probe inside a Flatpak on Fedora and Ubuntu; check whether Flatpak also bounds the network process. |
| Android device matrix | API 33/34/35, physical phones, OEM WebView builds, x86_64, a 16 KB page-size device. |
| Deeper fuzzing | Fuzz targets for the worker's decoders; long scheduled campaigns and coverage measurement (Phase 7). |
| Phases 2–7 | Everything in §5. |

## 4. Limitations and how to work around them

### 4.1 Limitations of the development environment

| Limitation | Effect | Workaround |
|---|---|---|
| The Docker VM has ~6 GB with ~1.4 GB free; building YARA-X/Cranelift for Linux in Docker is killed (OOM) | Linux-only Rust tests (`no_threads`) cannot be run locally; they run only in CI | Give Docker Desktop ≥ 8 GB (Settings → Resources) or stop unrelated containers; meanwhile rely on GitHub CI, which runs them on Ubuntu. |
| No physical Android device | All Android evidence is from emulators with software GPU | Connect a phone with USB debugging and run `poc/android-feasibility/run-poc.sh <dir>` (not yet tried on a phone). Without `adb root`, everything except the A1 renderer `/proc` check should still run. |
| Emulator images: only API 30 and 36 installed, no 16 KB page-size image | A1/A4 criteria name 33/34/35; 16 KB alignment checked only statically | `sdkmanager "system-images;android-35;google_apis;arm64-v8a"` and the `..._ps16k` variants, then rerun. |
| API 30 image has WebView 91 | Old engine; not representative of updated devices | Update WebView from Play on a `google_apis_playstore` image, or use a phone. |
| No Flatpak host | L1 and L2 unverified in the shipping configuration | Run on a Fedora or Ubuntu VM/desktop with `flatpak-builder`. |
| `cargo` is not on PATH in non-login shells | Commands fail with "not found" | `export PATH="$HOME/.cargo/bin:$PATH"`. |
| Slow network: the Gradle wrapper re-downloads its Gradle distribution and stalls | `build.sh` hangs in the Gradle step | Unpack Gradle 9.8.1 once and run `GRADLE=/path/to/gradle-9.8.1/bin/gradle ./build.sh`. |

### 4.2 Limitations of the design (not bugs; stated so they are not over-claimed)

| Limitation | Why | Mitigation or way forward |
|---|---|---|
| A WebView escape lands in `:browser` with the app's UID | Android gives one UID per APK | Vault keys never enter `:browser`; auth-bound Keystore key; minimal Binder interface. Stronger: a separate browser APK (ADR-04, post-V1). |
| `blob:`, `data:` and POST downloads cannot be captured | WebView does not report them or they cannot be re-fetched | Stated as unsupported. For `blob:` and `data:` Rift is never told, so it cannot even show a message. A JavaScript bridge could capture them but would add attack surface, so it is rejected for V1. |
| Android worker is weaker than the Linux worker (exec memory, `AF_UNIX`, NoNewPrivs=0) | `isolated_app` policy is set by the OS; ART needs exec memory | Per-thread seccomp filter in the native library, as defence in depth, if it does not break ART. |
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

**Phase 2: Android vertical slice**
3. Compose UI shell; the `:browser` session with the WebView configuration from §8.4; navigation policy wired through the core.
4. Download capture → core re-fetch → encrypted quarantine, with the unsupported cases shown as such.
5. Isolated worker preview (PDF, images, text) with validated output; reset and recovery as proven in A2.
6. Security tests S1–S12 on the device matrix; Phase 2 report.

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
