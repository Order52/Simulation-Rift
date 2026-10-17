# Phase 1 report: foundations

**Status:** gate met with the limits stated below (18 Oct 2026). Phase 1 delivers the host-side Rust workspace that both platforms share: `rift-protocol`, `rift-core` and `rift-worker` (architecture §7, §22). "Verified" means tested in the stated environment only.

## Gate (architecture §22)

| Gate item | State | Evidence |
|---|---|---|
| Unit tests | 81 pass on macOS (62 `rift-core`, 11 `rift-protocol`, 8 `rift-worker`); the same plus the Linux-only `no_threads` test pass on Ubuntu x86_64 in CI | `cargo test --workspace`; CI job `rust` |
| Property tests | 3 (proptest): URL canonical form is ASCII and idempotent (4,000 cases, plus a URL-shaped generator), and arbitrary bytes never panic the protocol decoder (20,000 cases). Regression seeds are kept in `crates/rift-core/proptest-regressions/` | same |
| Fuzz tests | 6 cargo-fuzz targets, each asserting a property. Run locally for 60–120 s each; CI runs each for 60 s on every push (first run: all six clean, 0.1–47 M executions each) | `fuzz/`; CI job `fuzz`, [run 39076457752](https://github.com/Order52/Simulation-Rift/actions/runs/39076457752) |
| `cargo deny` | advisories, bans, licenses and sources ok, with the scoped Wasmtime exceptions from Phase 0 (finding 4) | `cargo deny check`; CI job `dependencies` |
| `clippy -D warnings` | clean on macOS, and on Linux (CI and Docker with rustc 1.99.1) | CI job `rust` |
| Report | this file | — |

## What the crates do

| Crate / module | Role | Untrusted input it handles |
|---|---|---|
| `rift-protocol` | Controller ⇄ worker messages. Frames are size-checked before allocation; every response is matched to its request (version, job, generation) and bounded field by field. | Everything a (possibly compromised) worker sends |
| `rift-core::urlcanon` | Safe Browsing-compatible canonicalization and lookup expressions | Every URL a page navigates to |
| `rift-core::intel` | Fully validated indicator tables, binary search lookups | Intelligence pack files |
| `rift-core::heuristics` | Explainable URL flags (UTS #39 confusables, mixed scripts, shorteners, depth) | URLs |
| `rift-core::policy` | Pure navigation decision; blocks without a verified sandbox | URLs and engine state |
| `rift-core::transfer` | Download destination policy, display-name hygiene, sealing writer | Server addresses, filenames, response bodies |
| `rift-core::store`, `session`, `vault` | Encrypted object store, disposable sessions with ephemeral keys, authenticated vault format | Files on disk that may have been replaced |
| `rift-worker` | Shared job logic: YARA-X rules and scans, bounded image decoding | Files being scanned or previewed (inside the confined worker) |

## Fuzz targets

| Target | Property checked | Local run |
|---|---|---|
| `protocol_response` | Decoding never panics; an accepted response answers the request it was matched to and respects its bounds (bitmap box, stride and size; match count) | 19.9 M runs / 60 s |
| `url_canonicalize` | Never panics; output is ASCII and a fixed point; at most 30 expressions | **found a bug**; after the fix 1.1 M runs / 120 s clean |
| `intel_table` | Never panics; a table that parses finds each of its records with that record's metadata index, always in range | 46 M runs / 60 s |
| `navigation` | Never panics; never anything but a block without a verified sandbox; never proceeds to a URL listed in the indicator table | 1.0 M runs / 180 s |
| `display_name` | Result is non-empty, ≤ 120 characters, has no separators, control or bidi/invisible characters, and is a fixed point | **found a bug**; after the fix 3.9 M runs / 120 s clean |
| `vault_index` | Never panics; arbitrary bytes are never accepted as a vault index (no MAC forgery) | 0.7 M runs / 60 s |

## Findings that changed the code

1. **Bracketed hosts were not canonicalized consistently (fuzz, `url_canonicalize`).** For `.[\x0e]\x02…`, the leading dot hid the `[` on the first pass, so the host went through the ordinary path. On the second pass the bracket branch kept only `[…]` and silently dropped the rest. Canonicalization is what indicator lookups hash, so an unstable result means the same URL could match differently. Brackets are now accepted only as a whole IPv6 literal (hex digits, `:` and `.`), optionally followed by a port. Every other use is the new `CanonError::InvalidHost`, which browsers also refuse and which the policy blocks as an invalid URL.
2. **Shortened display names could hide the real extension (fuzz, `display_name`).** The fuzzer found the non-idempotence: truncation could leave a trailing dot. Looking at why showed the more important problem: truncating at 120 characters kept the head, so `invoice<padding>.pdf.exe` displayed as `invoice<padding>.pdf`. That defeats the function's own purpose (§11.1). Long names now keep the final extension after an ellipsis.
3. Earlier in this phase, property tests found three idempotence bugs in URL canonicalization (Phase 0 finding 3).

## Verified

- All listed tests pass on macOS arm64 and Ubuntu x86_64 (CI run 39076457752, which also ran every fuzz target for 60 s without a finding).
- Both fuzz findings reproduce on the old code (the saved crash inputs) and pass on the new code, and each is kept as a unit test.
- After the fixes, every target ran clean for its local budget.

## Unverified

- Fuzzing depth: minutes per target, not the CPU-days a release would need, and no coverage report yet. Clean short runs are not evidence of absence of bugs.
- `rift-worker`'s decoders (YARA-X rule compilation, image decoding) are not fuzzed here. They run inside the confined worker, so a crash there is a failed job, not a breach, but it is still a reliability gap.
- `store`, `session` and `vault` crash recovery is covered by unit tests that simulate interrupted writes, not by fault injection (that is Phase 7).
- `rift-core` has not yet run on Android: only the PoC native library has. It will in Phase 2.

## Could be improved

- Add fuzz targets for `rift-worker` jobs (rule loading, image decoding with limits) and for `heuristics::assess` on raw bytes.
- Run longer campaigns on a schedule (nightly CI or OSS-Fuzz) and keep a minimized corpus outside the repository.
- Generate structured inputs (`arbitrary`) for the protocol target, so more runs reach validation rather than failing in postcard decoding.
- Measure coverage (`cargo fuzz coverage`) and set a floor per target.
