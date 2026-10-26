# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Rift is a local Android app (Linux is future work) that checks links before they open, opens them in a sealed disposable browser, and quarantines, scans and previews files in isolated workers. It is a security product in development and not audited: every claim in the docs is "tested in the stated environment", and each one names its boundary and the test that shows it. `docs/architecture.md` is the spec (threat model §3, trust boundaries §4, invariants INV-1…INV-14 §5, acceptance tests §23, residual risks §24). `STATUS.md` says what works now; `docs/reports/` holds the evidence for each claim.

## Commands

Rust (the product workspace: `crates/*` and `tools/*`; toolchain pinned in `rust-toolchain.toml`, MSRV 1.98 checked separately in CI):

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo test -p rift-core filters::            # one crate / one module or test name
cargo deny check                             # licences, advisories, bans, sources
cargo +nightly fuzz run <target> -- -max_total_time=60   # targets in fuzz/fuzz_targets (CI pins a nightly)
```

`poc/` (Phase 0 harnesses, not product code) and `linux/` (needs Qt; its own workspace, built via Flatpak in `linux/flatpak/`) are separate workspaces excluded from the root one.

Android (`android/`, modules `:bridge`, `:app`, `:browser`, `:outsider`; needs the NDK, `cargo-ndk`, the Android Rust targets and JDK 21):

```sh
sh android/build.sh            # Rust libs for arm64+x86_64, UniFFI Kotlin bindings, signed demo intel, debug APKs, JVM unit tests
sh android/run-tests.sh <out>  # full device suite on the one attached emulator/device; writes evidence to <out>
sh android/release.sh          # signed arm64 release APK (key kept outside the repo)
cd android && ./gradlew :app:testDebugUnitTest --tests '*IntelImportTest'   # one JVM unit test
```

Releases are automatic (`.github/workflows/release.yml`, weekly, from a tree CI passed; version from the last tag, signing key in the `release` environment); `release.sh` by hand still works. Dependabot, `kev.yml` and `retrain.yml` open pull requests that merge themselves when the required CI checks pass.

`build.sh` must run before Gradle on a fresh checkout: the Kotlin bindings (`app/build/generated-rift`) and the demo threat database (`app/build/generated-intel`) are generated there, not checked in. `run-tests.sh` starts the fixture web server (`android/fixtures/server.py`, pages in `fixtures/web/`), installs all APKs, runs `SecurityTest` by instrumentation, then host-driven tests that need `adb root` (a debuggable emulator image). `RIFT_HOST_ONLY=1` skips the instrumented tests; `RIFT_FAULT_ONLY=1` runs only the fault rounds. To run one instrumented test after installing: `adb shell am instrument -w -e class org.simulationrift.app.SecurityTest#<method> org.simulationrift.app.test/androidx.test.runner.AndroidJUnitRunner`. Instrumented test names carry the §23 test ID (`s01_…`, `n1_…`). x86_64 emulators (CI: API 33, 34) can't run on Apple Silicon.

## Architecture

**Crates and dependency direction:** `rift-protocol` ← `rift-worker` ← `rift-worker-ffi`, and `rift-protocol` ← `rift-core` ← `rift-ffi`. `rift-core` (trusted logic: URL canonicalisation, policy, heuristics, intel, egress proxy, downloads/transfer, sessions, quarantine sealing, content filters) never depends on parser crates. `rift-worker` holds the untrusted-input parsers (image, PDF, YARA-X). `rift-update` does TUF verification of signed threat-intel packs; `tools/rift-pack` builds and signs them; `tools/rift-train` trains Rift AI (model in `models/`). `rift-channel` is the Linux worker transport.

**Android is two APKs with two UIDs, plus isolated workers:**
- **Controller** (`android/app`, `org.simulationrift.app`, trusted): Compose UI, `rift_ffi` loaded only in its main process, the loopback egress proxy, and a VPN that applies only to the browser's UID and drops everything, so the browser's only route out is the proxy (INV-14). It holds no WebView.
- **Browser** (`android/browser`, `org.simulationrift.browser`): WebView host with no permissions and no Rift data. It reaches the controller only through Binder interfaces in `android/bridge` (AIDL `ICore`/`ISession`/`IBrowser`), guarded by a `signature` permission and per-call UID/signer checks. Android wipes it (`clearApplicationUserData`) at every reset (INV-8). `assets/decoys.js` answers device-feature requests with made-up data, through the one string-only message channel (INV-6).
- **Isolated workers**: `isolatedProcess` services in the controller APK that load only `rift_worker_ffi` and receive only file descriptors (INV-1/2). Worker output is untrusted and validated (INV-3).
- `android/outsider` is a test-only app, signed with its own throwaway key, that plays a hostile app on the same device.
- The release APK embeds the signed browser APK and installs it on first launch (§8.10); both must carry the same certificate.

**Data flow:** link → `urlcanon` → intel lookup + heuristics (+ Rift AI, advisory) → `policy` → browser session of generation N. A download is re-fetched by the core (per-hop destination checks, stream byte limits), hashed, encrypted to a session key held only in memory, scanned in a worker, and its verdict bound to hash + engine/intel/policy versions. Reset drops the key (crypto-shred), deletes and verifies, then advances the generation; results from older generations are rejected.

## Conventions

- Workspace lints: `unsafe_code = "forbid"` (the Linux workspace uses `deny` only for cxx bridge blocks); clippy denies `unwrap_used` and warns on `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects`. Tests may unwrap/panic/index (`clippy.toml`). No unwrap/expect on untrusted data; errors are typed.
- A failed, timed-out or unsupported check gives **Not fully scanned**, never a clean verdict (INV-5). User-facing text never calls anything "safe".
- Fuzz findings are fixed in the crate and kept as unit tests, not corpus files. Proptest regressions are checked in (`crates/rift-core/proptest-regressions/`).
- Changing a security property means updating the invariant/test ID in `docs/architecture.md`, `STATUS.md`, and evidence under `docs/reports/`. Phase reports use the sections **Verified**, **Unverified**, **Could be improved**.
- Never commit signing keys (demo keys live in `~/.local/share/simulation-rift/demo-keys`, release keys in `…/release-keys`), real malware or user data.
- Commit subjects are lowercase, prefixed by area (`core:`, `android:`, `android test:`, `filters:`, `docs:`, `tests:`), and say what changed in plain words.

## How to work here

From the Karpathy guidelines. They favour caution over speed; use judgment on trivial tasks.

- **Think before coding.** State your assumptions. If a request can be read more than one way, lay out the readings instead of picking one silently. If something is unclear, or a simpler approach exists, say so and ask.
- **Simplicity first.** Write the minimum code that solves the problem: no features, abstractions, configurability or error handling for impossible cases that nobody asked for. If 200 lines could be 50, rewrite them.
- **Surgical changes.** Touch only what the task needs. Match the existing style, and don't reformat, refactor or "improve" nearby code. Remove only what your own change left unused; mention other dead code rather than deleting it. Every changed line should trace back to the request.
- **Goal-driven execution.** Turn the task into checks you can verify: to fix a bug, first write a test that reproduces it; to refactor, have tests pass before and after. For multi-step work, state a short plan with a check for each step, and keep going until the checks pass.
