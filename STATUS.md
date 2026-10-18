# Simulation-Rift: current status

**As of 18 Oct 2026** (`main` at the commit that added this file). Simulation-Rift is in development, in Phase 3 of the roadmap (Phases 0–7, [architecture §22](docs/architecture.md)). It is **not** a usable or audited security product. Every claim below means "tested in the stated environment", nothing more. The full history of the work, all 31 findings and the per-phase evidence are in [`docs/reports/project-status.md`](docs/reports/project-status.md) and the phase reports next to it.

## In one paragraph

The Android debug build works end to end on emulators. You can open a link in a disposable, sandboxed browser session. Downloads are captured into encrypted, per-session quarantine and previewed in an isolated worker process. Every download is scanned against a signed threat database, and reset destroys the whole session. The only threat database is a harmless demo one, so the scanner has no real-world coverage yet. Nothing has run on a physical phone. The Linux app, the vault and the hardening phase have not started.

## Phases

| Phase | State |
|---|---|
| 0: Feasibility (13 proofs of concept) | **Mostly done.** All pass in at least one environment. Open: the lookup benchmark on a phone, and the Linux checks inside Flatpak. |
| 1: Foundations (Rust core, protocol, formats) | **Done.** Unit, property and fuzz tests, strict lints, dependency policy. |
| 2: Android vertical slice | **Done on emulators.** Gate still open: a physical phone. |
| 3: Scanner and signed intelligence | **Mostly done.** Scanning and offline signed updates work on the host and on Android emulators. Open: the import screen, online updates, the production key policy and the items in "What is left". |
| 4: Vault | Format done and tested; key providers, lock/unlock and UI not started. |
| 5: Linux app | Not started (the worker lockdown and the WebKitGTK sandbox check are proven in PoCs). |
| 6: AI experiment | Not started; optional and gated by design. |
| 7: Hardening and release | Not started. |

## What works today (Android debug build)

| Feature | What it does | Tests |
|---|---|---|
| Disposable browser | System WebView in its own `:browser` process, no native bridges or device permissions; refuses to browse if the engine sandbox cannot be verified or WebView is too old. | S1, S2, S15, N1–N4 |
| Navigation policy | Blocks automatic external-app links, asks before lookalike addresses, marks unencrypted pages, explains every decision. | N1–N4 |
| Download capture | Downloads served at a URL are re-fetched by the Rust core (destination checks on every redirect, size limit, cookies only to their origin) into encrypted quarantine. Hostile names are display-only. | S8–S10 |
| Previews | Images and PDFs render in an isolated worker (no files, no network, seccomp on the parser thread, deadlines, unbound after each job). Text is shown as escaped plain text. | P1, P2, S3–S7, S19 |
| Scanning | Each download is checked by file hash and type in the core, then by YARA-X rules in a fresh isolated worker. The result names each check and each gap. The best status is "Not flagged", never "safe". | S16a, S21a, S21b |
| Signed threat database | Offline TUF install. A fresh worker must compile the rules before an update is accepted. Tampered, rolled-back, expired or wrongly signed updates are refused and the old database stays. Debug builds embed a signed demo database. | S16, S17, S21, S22 |
| Reset and recovery | Reset kills `:browser`, deletes the session and checks what is left on disk against an allowlist. A kill in the middle of a reset is recovered on the next start. | S12, S13, S14 |

## Where it has been tested

| Environment | Result |
|---|---|
| Host: macOS arm64, and CI on Ubuntu and macOS | 132 Rust tests, `clippy -D warnings`, `fmt`, `cargo deny`, 6 fuzz targets (short runs) and the Linux worker lockdown all pass. |
| Android API 35, 16 KB pages, arm64 (local emulator) | Full suite: 24 instrumented tests plus S13/S14 pass. App installed at 11:46 on 18 Oct. |
| Android API 33 and 34, x86_64 (CI emulators) | Full suite: 24 tests plus S13/S14 pass (CI run 39111591453). |
| Android API 36, arm64 (local emulator) | Phase 2 suite (20 tests plus S13/S14) passes; **the 4 Phase 3 tests have not run here yet.** |
| Android API 30 | Browsing is refused as designed (WebView 91 is below the minimum). |
| Physical Android phone | **Not tested.** |
| Linux desktop app, Flatpak | **Not built.** |

## What is left

In order of priority:

1. **Finish Phase 3**
   1. Short refusal messages in the UI (they currently show tough's full error, including internal paths).
   2. A bounded pool of scan workers, so one hung worker does not delay the queue by 17 s.
   3. Pin running scans to the database snapshot they started with.
   4. An import screen for a user-chosen update, and a production root in release builds (they have none today).
   5. Online updates over the core's own fetcher, without adding a second TLS stack (size budget).
   6. Show clock problems in the UI, the production key policy (offline keys, thresholds, rotation), and licensed real feeds.
   7. Run the suite on API 36 and on a phone.
2. **Close Phases 0 and 2:** the suite and the PoCs on physical phones (including a 16 KB page-size device); the lookup benchmark on a phone; the Linux checks inside Flatpak.
3. **Phase 4, vault:** Keystore and passphrase key providers, lock/unlock, save and export with warnings, a test that no plaintext is left on disk.
4. **Phase 5, Linux:** the GTK4 + WebKitGTK Flatpak app on the same Rust core, with the worker lockdown and the fail-closed sandbox check.
5. **Phase 6 (optional):** the AI experiment, only if it adds measured value.
6. **Phase 7, hardening:** long fuzz campaigns, fault injection, privacy network captures, a dependency review, release gates, and an external security review before any release claim.

## Main limitations

| Limitation | Workaround or way forward |
|---|---|
| No real threat coverage: only the demo database exists. | Real feeds need a licensing review; the demo label is shown on every verdict. |
| Emulators only; no physical phone. | Connect a phone with USB debugging and run `android/run-tests.sh <dir>` (S13/S14 need `adb root`). |
| A WebView escape lands in `:browser`, which has the app's user ID. | Vault keys never enter `:browser`. A separate browser APK is the stronger option (post-V1). |
| `blob:`, `data:` and POST downloads cannot be captured. | Stated as unsupported. |
| The Android worker is weaker than the Linux one (Android allows exec memory and `AF_UNIX`). | A seccomp filter on the parser thread; defence in depth, not a boundary. |
| The native code budget is tight: 19.3 MB (arm64) and 24.0 MB (x86_64) per ABI, against 25 MB. | No second TLS stack for online updates; measure every native addition. |
| Update expiry trusts the device clock. | Surfacing clock problems in the UI is on the list. |
| Demo signing keys are one per role, on one machine. | The production key policy is needed before any release. |
| Wasmtime advisories, pulled in through YARA-X. | Scoped exceptions in `cargo deny`, removed once YARA-X depends on Wasmtime ≥ 48.0.6. |
| Dev machine: Docker cannot build the Linux-only tests (out of memory); Apple silicon cannot run x86_64 emulators. | CI runs both. |

## Build and test

| What | Command |
|---|---|
| Rust tests and lints | `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo deny check` |
| Android app (debug, with the demo database) | `sh android/build.sh` (signing keys go to `~/.local/share/simulation-rift/demo-keys`, outside the repository) |
| Android suite on one attached emulator | `sh android/run-tests.sh <evidence-dir>` |
| Install only | `adb install -r android/app/build/outputs/apk/debug/app-debug.apk` |

Further reading: [architecture](docs/architecture.md); the detailed status and history in [project-status.md](docs/reports/project-status.md); the phase reports [0](docs/reports/phase-0.md), [1](docs/reports/phase-1.md), [2](docs/reports/phase-2.md), [3](docs/reports/phase-3.md); the raw evidence in [`docs/reports/evidence/`](docs/reports/evidence/).
