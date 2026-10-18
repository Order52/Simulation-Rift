# Phase 3 report: scanner and signed intelligence (in progress)

**Status (18 Oct 2026):** built and tested on the host and on Android emulators. Host side: pack validation, scan verdicts with a versioned cache, the on-disk snapshot store, TUF verification for offline import, and the maintainer tool with a harmless demo pack. Android: every download is scanned (the core's hash and type checks, then the rules in a fresh isolated worker), the verdict is shown under the download, and debug builds can install a signed demo database. S16 and S21 pass on API 33 and 34 (x86_64, CI). **Not built yet:** an import screen for a user-chosen update with a production root, and an online update transport. The §22 gate (update-failure suite, offline operation, report) is met on the host and on emulators; a physical phone is still open, as for Phase 2. "Verified" means tested on macOS arm64, in CI (Ubuntu, macOS), and on the stated emulators. Nothing here claims that a file is safe: the best status is "not flagged" by named checks.

## What was built

| Part | What it does | Where |
|---|---|---|
| `rift-core::pack` | A pack is exactly four files: `metadata.json` (strict schema, 1 MiB), `url-hashes.bin`, `file-hashes.bin` (64 MiB each) and `rules.yar` (8 MiB, UTF-8). Unknown, missing or repeated files fail. Every table record must point into the metadata. Text fields are bounded and free of control characters. Rule ids must be YARA identifiers. The pack digest is SHA-256 over every file's name, length and hash. | `crates/rift-core/src/pack.rs` |
| `rift-core::scan` | Evidence to status (§12.3). A high-confidence file-hash or rule match gives "known malicious". A low-confidence match, a rule the pack does not describe, or a type mismatch gives "suspicious". Any gap (no pack, timeout, worker failure, match limit) gives "not fully scanned". Only complete checks with no match give "not flagged". The cache key is (object SHA-256, engine, pack digest, policy version); verdicts under another key are history, never current. | `crates/rift-core/src/scan.rs` |
| `rift-core::snapshot` | Snapshots live in `snapshots/<pack digest>/`, so no path comes from pack content. Install: validate, platform check (the worker compiles the rules), write and fsync into `staging/`, rename into place, then replace the `current` pointer (write, fsync, rename). Every load validates the pack again and compares its digest with the directory name. One previous snapshot is kept; older ones are removed. | `crates/rift-core/src/snapshot.rs` |
| `rift-update` | Verifies an offline TUF repository with tough 0.24.0 (no HTTP transport compiled in), using X2's metadata limits and a datastore for rollback protection. It reads only the four pack names, each within its limit (checked against the signed length before reading), then installs through the snapshot store. | `crates/rift-update` |
| `rift-pack` | Maintainer tool: Ed25519 role keys (0600, refused inside a git work tree), a signed root, the demo pack and signed releases with §13.2 expiries (timestamp 7 d, snapshot 14 d, targets 90 d). It validates every pack with the app's own validator before writing or signing. | `tools/rift-pack` |
| Demo pack | Labelled `demo: true` with a "DEMO: not real coverage" notice. Indicators: the SHA-256 of a harmless text file (`DEMO_FILE`) and a `.invalid` URL. Rules: a marker string (high confidence) and a byte pattern (low). No real malware and no third-party feed data. | `tools/rift-pack/src/lib.rs` |
| `SCAN_ENGINE` | The engine name in every cache key (`yara-x 1.21.0`). A test checks it against `Cargo.lock`. | `crates/rift-protocol` |
| `rift-ffi::scan` | The controller API: `Intel` (the store in `files/rift/intel`, kept across sessions, and the TUF datastore), `PendingIntel` (a verified update that a worker must compile before it can be installed), `ScanJob` (the frames for one scan; it validates every reply). The core decides the status; pack text is escaped for display. | `crates/rift-ffi/src/scan.rs` |
| Android | `IsolatedWorker`: binding, deadlines and the kill switch, now shared by previews and scans. `Scanner`: Hello (seccomp required), LoadRules, then Scan over a sealed memfd, one fresh worker per file. `Core` scans each download and keeps verdicts per session. The UI shows the status, the named checks and the gaps, and a database card (status, demo label, staleness). | `android/app/src/main/kotlin` |
| Demo database in debug builds | `android/build.sh` signs a fresh demo release on each build with keys outside the repository (`~/.local/share/simulation-rift/demo-keys` by default) and embeds only the public root and the signed repository. | `android/build.sh` |

## Results

| ID | Test | Result | Where |
|---|---|---|---|
| S11 | Bytes change after a scan | **Pass (core).** Different bytes are a different key: no current verdict and no history carried over. | `scan::tests::s11_*` |
| S16 | Bad signature, hash, version, expiry | **Pass (host).** Each is rejected for its own reason, and the current snapshot is unchanged: a repository signed by other keys ("Signature threshold of 1 not met for role timestamp (0 valid signatures)"); a target changed at the same length ("Hash mismatch … calculated 7536…, expected 2e5f…"); a target with bytes appended ("Maximum size 278 (specified by targets.json) exceeded"); version 1 replayed after version 2 ("Found version 1 of timestamp metadata when we had previously fetched version 2"); an expired timestamp ("timestamp metadata is expired"). A correctly signed pack whose install check fails is also refused. | `crates/rift-update/tests/update.rs` |
| S16 | Bad path | **Pass by construction, plus X2.** Target names are never used as paths: the client asks for four fixed names and stores files under the pack digest. X2 showed that tough normalizes hostile names. | `rift-update`, `snapshot` |
| S17 | Interrupted update | **Pass (host).** An install was stopped after staging, after the move, and after writing the new pointer but before renaming it. Each time, reopening the store showed the old snapshot, staging and the temporary pointer were cleaned up, and a retry succeeded. | `snapshot::tests::s17_*` |
| S21 | Demo rule and indicator match | **Pass.** In the real engine (rift-worker, YARA-X), the demo rules compile to the rule count the metadata declares, which is the install check. The demo file matches the marker rule (known malicious), the byte pattern matches the low rule (suspicious), and other content is not flagged. A verified, installed pack finds the demo file by hash, with the engine and pack digest in the verdict. | `crates/rift-worker/tests/demo_pack.rs`, `rift-update` tests |
| S22 | New pack adds or removes a rule | **Pass (core).** A pack with one more rule has a new digest: the old verdict is no longer current and appears as history. A different engine version also misses the cache. | `scan::tests::s22_*` |
| — | Damaged snapshot on disk | **Refused, not trusted.** A replaced rule file (valid, but not the pack the directory names), a missing file, and malformed pointers are each reported as damaged. | `snapshot::tests` |
| S16 | Android: tampered update | **Pass (API 33, 34).** A same-length change to the signed rules was refused on the device by tough's hash check ("Hash mismatch … calculated 7536…, expected 2e5f…"), and the database stayed missing. | `s16b`, [33](evidence/phase3-android-api33-x86_64/), [34](evidence/phase3-android-api34-x86_64/) |
| — | Android: no database | **Pass (API 33, 34).** Every scan says "Not fully scanned" and names both missing checks. The type check still runs: an executable served as `invoice.pdf` is "Suspicious" ("Named as .pdf, but the content is a Windows executable"). | `s16a` |
| S21 | Android: demo database | **Pass (API 33, 34).** The signed demo database installed after a fresh worker compiled its 2 rules. `demo-file.txt` was "Known malicious" by file hash and by `rift_demo_marker`, with engine `yara-x 1.21.0` and the installed snapshot in the verdict; `notes.txt` was "Not flagged" with no gaps. These scans ran in the worker that answers garbage if the parser-thread filter is missing on the scan path, so the filter was in force. A scan with a fresh worker took 0.3–0.5 s on the emulators. | `s21a` |
| S6 (scan) | Android: hung scan worker | **Pass (API 33, 34).** A worker that compiles the rules and then never answers was stopped by the controller's 17 s deadline (the whole scan took 17.3–17.4 s; the test saw 18.8–19.5 s including the download). The core's hash check still found the file ("Known malicious"), and the verdict named the missing rule scan ("the worker did not scan in time and was stopped"). | `s21b` |
| — | Maintainer CLI end to end | **Pass.** `rift-pack keys`, `root`, `demo` and `publish` on the host, then `cargo run -p rift-update --example verify`: "OK snapshot demo-…, targets v1, timestamp v1, demo=true, 1 file and 1 URL indicators, 2 rules". A key directory inside the repository was refused. | manual run, 18 Oct |

Android: the full instrumented suite (24 tests: the 20 from Phase 2 and the 4 above) and S13/S14 passed on API 33 and API 34 x86_64 in CI (run 39111591453). Not yet run on API 36, on the 16 KB page-size image or on a phone.

Host tests after this phase: rift-core 92 (+1 ignored network test), rift-ffi 8, rift-protocol 11, rift-update 7, rift-worker 10 (+1 Linux-only), rift-worker-ffi 4. `clippy -D warnings`, `fmt` and `cargo deny` (advisories, bans, licenses, sources) are clean.

## Findings

1. **A tampered target that only grows is caught by the length check, not the hash.** The first tamper test appended bytes, so it never exercised the hash. It now covers both cases.
2. **The X2 PoC's allowlist (`meta.json`, `notices.txt`) did not match the product format.** Notices are now part of `metadata.json`, so a pack is four files, and the allowlist is `rift_core::pack::FILES`, shared by the store and the update client.
3. **The first default key directory was inside a git work tree.** `build.sh` put the demo keys in `~/.config/simulation-rift`, and on the development machine `~/.config` is a git repository. `rift-pack` refused to write the keys there, as designed, and the default moved to `~/.local/share`. The check is worth keeping: a key directory can sit inside a repository the developer did not think of.
4. **Size.** `librift_ffi.so` grew from 3.15 MB to 7.45 MB (arm64) and from 3.52 MB to 8.32 MB (x86_64). Most of the growth is tough and aws-lc-rs (X2 bound: 4.8 MB standalone); the rest is not broken down. With the worker library (11.7 / 15.5 MB) and JNA, the native code is 19.3 MB (arm64) and 24.0 MB (x86_64) per ABI, against the 25 MB budget. x86_64 is an emulator ABI, but the margin is now small, and online updates (Phase 3 open item) must not add a second TLS stack.
5. **A worker stuck outside the engine costs the full controller deadline.** The worker's own 15 s limit is YARA-X's scan timeout, which only applies inside the engine. A worker hung elsewhere is caught by the controller at 17 s. Scans run one at a time, so the files queued behind it wait as well.
6. **Refusal messages are raw.** The tampered-update message shown in the UI is tough's full error, with internal `file://` paths and both hashes. That is accurate but not readable; the UI should show one sentence and keep the detail in the log.

## Verified

- Everything marked Pass above, on the host (macOS arm64; CI on Ubuntu and macOS).
- Pack and snapshot validation run in the trusted core with no parser or engine code; rules are compiled only in the worker.

## Unverified

- **Android beyond the emulators.** API 33 and 34 x86_64 only; not yet API 36, the 16 KB image or a phone. The import path for a user-chosen update is not built: release builds have no root and no install button, and debug builds install only the embedded demo database.
- **YARA-X's own timeout on the device.** The hung-worker test hangs in Kotlin, so it shows the controller's deadline, not the engine's. A slow rule or input that trips YARA-X's 15 s limit (`Gap::Timeout`) is tested on the host only.
- **Online updates.** Only offline import (a repository directory) exists. An HTTP transport over the core's own fetcher (INV-13 destination checks) is not written.
- **Key policy.** The tool makes 1-of-1 keys per role on one machine. The §13.2 policy (offline root and targets keys, thresholds, root rotation) is not exercised. Tough's root rotation is not tested here.
- **Clock problems.** Expiry is enforced by tough against the system clock. A wrong clock surfaces as "expired" or a false "current"; the UI side of §13.2 ("clock problems are surfaced") is not built.
- **Real-world coverage.** The demo pack has none, by design, and says so. Real feeds are blocked on licensing (§13.3).

## Could be improved

- Scans in progress should stay pinned to their starting snapshot (§13.2). The store keeps one previous snapshot, but nothing yet tracks which jobs hold which snapshot.
- `rift-pack` takes all four role keys from one directory. Separate key locations, and refusing to sign with the root key in day-to-day publishing, would match the policy better.
- The verdict cache is in memory only. A persisted cache must be bound to the vault (Phase 4).
- Run more than one scan worker at a time, with a limit, so that one hung worker does not hold up the queue (finding 5).
- Short refusal messages in the UI, with tough's detail in the log only (finding 6).
