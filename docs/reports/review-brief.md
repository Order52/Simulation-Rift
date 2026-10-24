# Brief for an external security review

**Date:** 24 October 2026. **Architecture:** 2.9. **Build under review:** Android 0.9.0 (`main`). Linux is out of scope for this review: it is on hold ([TODO.md](../../TODO.md)).

Rift opens untrusted links and files on an Android phone. It checks a link before opening it, opens it in a sealed, disposable browser, and quarantines, scans and previews files in isolated workers. It has not been audited. This brief says what to look at first and where it is. [architecture.md](../architecture.md) is the spec: the threat model is in §3, the trust boundaries in §4, the invariants INV-1 to INV-14 in §5, the acceptance tests in §23 and the known residual risks in §24. [STATUS.md](../../STATUS.md) says what has been tested where.

## What we want to know

1. **Can web content or an escaped renderer reach Rift's data, keys or the network other than through the proxy?** Boundaries B1, B2 and B8, and invariants INV-6, INV-8 and INV-14.
2. **Can a crafted file break out of a worker, or make a failed scan look clean?** B3, INV-1 to INV-5.
3. **Can an update be accepted when it should be refused?** B6, INV-10.
4. **Can another app on the phone drive Rift, read its data or use its Binder interfaces?** B7, §10.7.
5. **Does Check say anything it cannot back up?** It must never call anything "safe", and a check that failed must say so.

Findings against stated residual risks (§24) are still welcome if the risk is larger than stated.

## Where to look

| Area | Code | Notes |
|---|---|---|
| Binder surface between the browser and the controller | `android/bridge/src/main/aidl/` (`ICore`, `ISession`, `IBrowser`), `android/app/.../CoreService.kt` | `signature` permission plus a UID and signer check on every call. The browser app is treated as hostile after a renderer escape. |
| Network lock and egress proxy | `android/app/.../NetworkLockService.kt`, `crates/rift-core/src/egress.rs` | VPN for the browser's UID that forwards nothing; loopback proxy with a per-session token; destination checks before name resolution (INV-13). |
| Browser app | `android/browser/` and `assets/decoys.js` | No permissions, no JavaScript interface; one string-only message channel (INV-6). The decoys script runs in every page. |
| Reset and disposal | `crates/rift-core/src/session.rs`, `android/app/.../AndroidBrowserDisposal.kt` | Crypto-shred, system wipe of the browser app, verification, generation counter (INV-8). |
| Downloads and quarantine | `crates/rift-core/src/download.rs`, `transfer.rs`, `seal.rs`, `store.rs` | Re-fetch with per-hop checks, byte limits, age encryption to a key held in memory. |
| Workers | `crates/rift-worker/`, `crates/rift-worker-ffi/`, `android/app/.../IsolatedWorker.kt` | `isolatedProcess` services that receive only file descriptors; output validated by `rift-protocol` (INV-3). |
| Signed updates | `crates/rift-update/`, `crates/rift-core/src/pack.rs`, `snapshot.rs` | TUF through `tough`; root rotation; rollback and expiry. Release keys are not generated yet (the ceremony is open); debug builds trust demo keys. |
| Untrusted text parsed by the core | `crates/rift-core/src/filters.rs`, `clean.rs`, `hostlists.rs`, `urlcanon.rs` | Filter lists, ClearURLs rules and threat lists are downloaded unsigned and parsed in the trusted process, with bounds. Each has a fuzz target. |
| Check's history | `android/app/.../CheckHistory.kt` | Off by default; AES-GCM under an Android Keystore key; deleted with the key when switched off (§10.13). |
| Rift AI | `crates/rift-core/src/urlmodel.rs` | Advisory only: it can ask before loading, never allow. A model in a signed pack replaces the shipped one. |

## How to build and run it

- Rust: `cargo test --workspace --locked`; fuzz targets are in `fuzz/fuzz_targets/` (`cargo +nightly fuzz run <target>`).
- Android: `sh android/build.sh`, then `sh android/run-tests.sh <out-dir>` on one emulator or device. An API 34 arm64 emulator image with `adb root` runs everything; a retail phone cannot run the fault rounds. `android/outsider` is a test app that plays a hostile app on the same device.
- The commands are in [CLAUDE.md](../../CLAUDE.md#commands).

## What is already known

- Every finding so far, fixed or not, is numbered in [project-status.md](project-status.md) and the phase reports; the most recent are 63 to 65 in [phase-7.md](phase-7.md).
- Not covered: undiscovered WebView or kernel escapes, a rooted or compromised OS, side channels (§3.3).
- Partly covered: escaped browser code can reach other apps' loopback servers (§24); an accessibility service the user installs can read Rift's windows; pages see the phone's IP address.
- Evidence is from emulators (API 33 to 36) and one partly run Huawei phone.

## How to report

Privately, through GitHub Security Advisories ([SECURITY.md](../../SECURITY.md)). No live malware: describe a sample or give its hash.
