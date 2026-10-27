# Developing Rift

How to set up, build, test and change Rift. The design itself is in [architecture.md](architecture.md); this guide is about working on the code.

## Contents

1. [Set up](#1-set-up)
2. [Repository map](#2-repository-map)
3. [How the pieces fit](#3-how-the-pieces-fit)
4. [Build](#4-build)
5. [Test](#5-test)
6. [CI](#6-ci)
7. [Rules for changes](#7-rules-for-changes)
8. [Common tasks](#8-common-tasks)

## 1. Set up

| Tool | Version |
|---|---|
| Rust | pinned in `rust-toolchain.toml` (MSRV 1.98 is checked separately in CI) |
| Android SDK, NDK | the NDK version (and cargo-ndk's, the fuzzing nightly's) is pinned in `.github/toolchains.env` |
| `cargo-ndk` | `cargo install cargo-ndk` |
| Rust Android targets | `rustup target add aarch64-linux-android x86_64-linux-android` |
| JDK | 21 |
| Python | 3, for the fixture server and the training scripts |
| Nightly Rust | only for fuzzing; CI pins the version |

`android/build.sh` defaults `ANDROID_HOME` to `~/Library/Android/sdk` and `JAVA_HOME` to Homebrew's `openjdk@21`; set both elsewhere.

The first build makes a set of **demo signing keys** for the demo threat database in `~/.local/share/simulation-rift/demo-keys` (override with `RIFT_DEMO_KEYS`). They are outside the repository on purpose: never commit keys.

## 2. Repository map

| Path | What it is |
|---|---|
| `crates/rift-protocol` | The controller/worker message contract and its validation |
| `crates/rift-core` | Trusted logic: URL canonicalisation (`urlcanon`), policy, heuristics, threat data (`intel`, `hostlists`), Rift AI (`urlmodel`, `pagemodel`), the egress proxy (`egress`), downloads and transfer, sessions, quarantine sealing (`seal`), content filters, link cleaning, trackers, app links, self-update (`appupdate`) |
| `crates/rift-ffi` | UniFFI interface from the Android controller to `rift-core` |
| `crates/rift-worker` | Parsers of untrusted input: images, PDFs, YARA-X scanning |
| `crates/rift-worker-ffi` | `rift-worker` inside Android's isolated service |
| `crates/rift-update` | TUF verification of signed threat-database packs, online and offline |
| `crates/rift-channel` | The Linux controller-to-browser channel (Linux is on hold) |
| `tools/rift-pack` | Maintainer tool: builds threat-database packs and signs them as TUF repositories |
| `tools/rift-train` | Maintainer tool: trains, gates and compares Rift AI's models and the brand list |
| `android/app` | The controller app, `org.simulationrift.app` (Compose UI, proxy, VPN, workers) |
| `android/browser` | The sealed browser, `org.simulationrift.browser` (WebView, decoys) |
| `android/bridge` | AIDL interfaces between the two apps (`ICore`, `ISession`, `IBrowser`) |
| `android/outsider` | A test-only hostile app with its own key |
| `android/fixtures` | The local web server and pages the device tests use |
| `models/` | Shipped models: `url-model.bin`, `page-model.txt`, `brands.txt`, with data notices |
| `fuzz/` | `cargo-fuzz` targets for every parser of untrusted input |
| `linux/` | Linux app (Qt, Flatpak), its own workspace, on hold |
| `poc/` | Phase 0 feasibility harnesses, not product code |
| `docs/` | Spec, reports, evidence and guides |

The root Cargo workspace is `crates/*` and `tools/*`; `poc/` and `linux/` are excluded.

## 3. How the pieces fit

Dependencies only point one way:

```
rift-protocol ← rift-worker ← rift-worker-ffi
rift-protocol ← rift-core   ← rift-ffi
```

`rift-core` never depends on a parser crate: everything that reads untrusted bytes in depth lives in `rift-worker` and runs in a separate, isolated process.

On Android there are three kinds of process:

- **The controller** (`android/app`, trusted) loads `rift_ffi` in its main process only. It runs the loopback egress proxy and a VPN that applies only to the browser's UID and drops every packet (INV-14). It holds no WebView.
- **The browser** (`android/browser`) has no permissions and no Rift data. It reaches the controller only through the Binder interfaces in `android/bridge`, guarded by a `signature` permission and a UID and signer check on every call. Android wipes it with `clearApplicationUserData` at each reset (INV-8). `assets/decoys.js` answers device-feature requests with made-up data through one string-only message channel (INV-6).
- **Isolated workers** are `isolatedProcess` services in the controller APK. They load only `rift_worker_ffi`, receive only file descriptors, and their answers are validated as untrusted (INV-1 to INV-3).

A link goes `urlcanon` → threat data and heuristics (+ Rift AI, advisory) → `policy` → a browser session of generation N. A download is fetched again by the core (with destination checks on every redirect and byte limits), hashed, encrypted to a session key held only in memory, scanned in a worker, and its verdict bound to the hash and the engine, database and policy versions. A reset drops the key, deletes and verifies, then moves to the next generation; results from older generations are rejected.

The invariants (INV-1…INV-14) are in [architecture §5](architecture.md#5-security-invariants), the trust boundaries in §4.

## 4. Build

```sh
cargo build --workspace --locked        # Rust only
sh android/build.sh                     # everything Android needs, then debug APKs and JVM unit tests
sh android/release.sh                   # signed arm64 release APK
```

`android/build.sh` must run before Gradle on a fresh checkout. It:

1. builds the Rust libraries for arm64 and x86_64 with `cargo-ndk`;
2. generates the Kotlin bindings into `android/app/build/generated-rift`;
3. builds and signs the demo threat database into `android/app/build/generated-intel`;
4. builds the debug APKs and runs the JVM unit tests.

After that, Gradle works on its own:

```sh
cd android && ./gradlew :app:assembleDebug
cd android && ./gradlew :app:testDebugUnitTest --tests '*IntelImportTest'
```

`release.sh` builds and signs the browser, embeds it in Rift's APK and signs Rift with the same key (both must carry the same certificate, §8.10). It makes a key in `~/.local/share/simulation-rift/release-keys` the first time (override with `RIFT_RELEASE_KEYS`). That key is for your own devices only: the published releases are signed by the release workflow, see [maintenance.md](maintenance.md#releases). Set `RIFT_INTEL_ROOT` (a root file) and `RIFT_INTEL_URL` (an https address) when running `build.sh` to give the build a trusted root and an update address for threat-database packs; without them a release build cannot install database updates and says so.

## 5. Test

### Rust

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo test -p rift-core filters::        # one crate, one module or test name
cargo deny check                         # licences, advisories, bans, sources
cargo +nightly fuzz run <target> -- -max_total_time=60
```

Fuzz targets are in `fuzz/fuzz_targets` (`url_canonicalize`, `egress_head`, `filters`, `worker_image`, `worker_scan` and others).

### On a device

```sh
sh android/run-tests.sh <out-dir>
```

This needs exactly one attached emulator or device. It starts the fixture server (`android/fixtures/server.py`, pages in `fixtures/web/`), installs all APKs (including the outsider app), runs `SecurityTest` by instrumentation, then host-driven tests that need `adb root` (a debuggable emulator image), and writes the evidence to `<out-dir>`.

| Variable | Effect |
|---|---|
| `RIFT_HOST_ONLY=1` | Skip the instrumented tests; run only the host-driven steps |
| `RIFT_FAULT_ONLY=1` | Run only the fault rounds (killing the controller, a full disk) |
| `RIFT_FAULT_ROUNDS=N` | Number of fault rounds (default 8) |

One instrumented test, after installing:

```sh
adb shell am instrument -w -e class org.simulationrift.app.SecurityTest#<method> \
  org.simulationrift.app.test/androidx.test.runner.AndroidJUnitRunner
```

Instrumented test names start with their acceptance-test ID from [architecture §23](architecture.md#23-acceptance-test-matrix) (`s01_…`, `n1_…`, `n11_…`), so a claim in the docs can be traced to its test.

x86_64 emulator images (what CI uses, API 33 and 34) cannot run on Apple Silicon; use an arm64 image locally.

## 6. CI

`.github/workflows/ci.yml` runs on every pull request and on pushes to `main` that touch code. Pushes that change only documentation, `poc/`, `linux/` or other workflows are skipped (`paths-ignore`; `release.yml` keeps the same list, keep both in step).

| Job | What it checks |
|---|---|
| `rust` | fmt, clippy with `-D warnings`, the workspace tests |
| `msrv` | builds with the minimum supported Rust |
| `dependencies` | `cargo deny` and OSV-Scanner over the Android libraries |
| `linux-worker-lockdown` | the Linux worker's Landlock and seccomp confinement |
| `fuzz` | every fuzz target for a short run |
| `android-emulator` | `build.sh` and the full `run-tests.sh` suite on API 33 and 34 emulators |

Branch protection requires these checks; the bot pull requests merge themselves only when they pass. A failed run is re-run once automatically by `caretaker.yml`.

The other workflows (releases, retraining, dependency updates) are described in [maintenance.md](maintenance.md).

## 7. Rules for changes

- **Lints.** `unsafe_code = "forbid"` across the workspace. Clippy denies `unwrap_used` and warns on `expect_used`, `panic`, `indexing_slicing` and `arithmetic_side_effects`; tests may unwrap, panic and index (`clippy.toml`). Never unwrap or expect on untrusted data: errors are typed.
- **Never "safe".** A failed, timed-out or unsupported check gives **Not fully scanned**, never a clean verdict (INV-5). No user-facing text calls anything safe.
- **Fuzz findings** are fixed in the crate and kept as unit tests, not as corpus files. Proptest regressions are checked in (`crates/rift-core/proptest-regressions/`).
- **Security changes** update the invariant or test ID in `docs/architecture.md`, `STATUS.md`, and the evidence under `docs/reports/`. Reports use the sections **Verified**, **Unverified** and **Could be improved**.
- **Never commit** signing keys, real malware, downloaded feeds or datasets, or user data. Training scripts read downloaded data from a directory outside the repository, with `python3 -I`.
- **Commit subjects** are lowercase, prefixed by area (`core:`, `android:`, `android test:`, `filters:`, `docs:`, `tests:`, `tools:`), and say what changed in plain words.
- **Keep changes small.** Touch only what the change needs and match the surrounding style.

## 8. Common tasks

### Add a check to Check

Address checks live in `crates/rift-core/src/heuristics.rs`; their results are combined in `policy.rs`. Add a unit test with addresses that should and should not trip it, and run the accuracy comparison (`tools/rift-train`'s `compare` binary, [check-accuracy.md](reports/check-accuracy.md)) to see what it does to false alarms.

### Add a device-test

Add a method to `android/app/src/androidTest/.../SecurityTest.kt` named after a new ID, add the row to architecture §23, and run it alone with `am instrument` (above) before the full suite.

### Change something the browser can reach

Anything crossing the browser/controller boundary goes through the AIDL interfaces in `android/bridge` and the UID and signer checks in `CoreService.kt`. Treat every value from the browser as untrusted, and add the case to the outsider app's tests (S24).

### Change a model

See [maintenance.md](maintenance.md#rift-ai) for retraining, and the reports [rift-ai.md](reports/rift-ai.md) and [page-model.md](reports/page-model.md) for the models themselves.
