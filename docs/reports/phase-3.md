# Phase 3 report: scanner and signed intelligence (in progress)

**Status (18 Oct 2026):** the trusted host side is built and tested: pack validation, scan verdicts with a versioned cache, the on-disk snapshot store, TUF verification for offline import, and the maintainer tool with a harmless demo pack. **Not built yet:** the Android wiring (scan jobs in the isolated worker after each download, the verdict in the UI, an import screen) and an online update transport. The §22 gate (update-failure suite, offline operation, report) is met on the host only. "Verified" means tested on macOS arm64 and in CI (Ubuntu, macOS). Nothing here claims that a file is safe: the best status is "not flagged" by named checks.

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
| — | Maintainer CLI end to end | **Pass.** `rift-pack keys`, `root`, `demo` and `publish` on the host, then `cargo run -p rift-update --example verify`: "OK snapshot demo-…, targets v1, timestamp v1, demo=true, 1 file and 1 URL indicators, 2 rules". A key directory inside the repository was refused. | manual run, 18 Oct |

Host tests after this phase: rift-core 90 (+1 ignored network test), rift-ffi 7, rift-protocol 11, rift-update 7, rift-worker 10 (+1 Linux-only), rift-worker-ffi 4. `clippy -D warnings`, `fmt` and `cargo deny` (advisories, bans, licenses, sources) are clean.

## Findings

1. **A tampered target that only grows is caught by the length check, not the hash.** The first tamper test appended bytes, so it never exercised the hash. It now covers both cases.
2. **The X2 PoC's allowlist (`meta.json`, `notices.txt`) did not match the product format.** Notices are now part of `metadata.json`, so a pack is four files, and the allowlist is `rift_core::pack::FILES`, shared by the store and the update client.

## Verified

- Everything marked Pass above, on the host (macOS arm64; CI on Ubuntu and macOS).
- Pack and snapshot validation run in the trusted core with no parser or engine code; rules are compiled only in the worker.

## Unverified

- **Android.** None of this is wired into the app yet: no scan job after a download, no verdict in the UI, no import screen, and no embedded root. The Android size of tough and aws-lc-rs inside Rift's library is still unmeasured (X2 bound: 4.8 MB standalone).
- **Online updates.** Only offline import (a repository directory) exists. An HTTP transport over the core's own fetcher (INV-13 destination checks) is not written.
- **Key policy.** The tool makes 1-of-1 keys per role on one machine. The §13.2 policy (offline root and targets keys, thresholds, root rotation) is not exercised. Tough's root rotation is not tested here.
- **Clock problems.** Expiry is enforced by tough against the system clock. A wrong clock surfaces as "expired" or a false "current"; the UI side of §13.2 ("clock problems are surfaced") is not built.
- **Real-world coverage.** The demo pack has none, by design, and says so. Real feeds are blocked on licensing (§13.3).

## Could be improved

- Scans in progress should stay pinned to their starting snapshot (§13.2). The store keeps one previous snapshot, but nothing yet tracks which jobs hold which snapshot.
- `rift-pack` takes all four role keys from one directory. Separate key locations, and refusing to sign with the root key in day-to-day publishing, would match the policy better.
- The verdict cache is in memory only. A persisted cache must be bound to the vault (Phase 4).
