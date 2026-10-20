# Dependency and licence inventory (Android build)

**As of 20 Oct 2026, commit `1429cb5` or later.** This is the inventory that §24's release gates ask for: licences, advisory review, and an owner for each security-sensitive dependency. It covers what ships in the Android debug build. The Linux app does not exist yet. "Checked" means checked by the tools named here; nobody has audited these dependencies' source.

## How it is checked

| Check | Tool | When | Result on 20 Oct 2026 |
|---|---|---|---|
| Known advisories (RustSec) | `cargo deny check advisories` | Every push (CI job `dependencies`) and locally | None outside eight triaged exceptions (below) |
| Licences | `cargo deny check licenses`, against the allow list in `deny.toml` | Same | All allowed |
| Sources | `cargo deny check sources`: crates.io only, no git dependencies | Same | OK |
| Duplicates and wildcards | `cargo deny check bans` | Same | Duplicates are warnings (below); no wildcards |
| Exact versions | `Cargo.lock` is committed; builds use `--locked` | Every build | — |
| Android (Gradle) dependencies | Versions pinned in `build.gradle.kts` | — | **No automated advisory check.** See "Gaps" |

## What ships

| Library | Process | Crates (arm64, normal dependencies) |
|---|---|---|
| `librift_ffi.so` | Controller app (UID of `org.simulationrift.app`) | 243 |
| `librift_worker_ffi.so` | Isolated preview and scan workers | 187 |
| Both | | 350 distinct |

Of these, proc-macros run only at build time. **285 third-party crates are linked** into the two libraries for either ABI (292 for arm64 including Rift's own 7). The lockfile lists 390 crates in all; the rest are host tools (`tools/rift-pack`), tests, build scripts and the bindings generator.

## Licences

Everything is under licences in `deny.toml`'s allow list (Apache-2.0, Apache-2.0 WITH LLVM-exception, BSD-2-Clause, BSD-3-Clause, ISC, MIT, MPL-2.0, Unicode-3.0, Zlib). There is one listed exception: `webpki-roots` (CDLA-Permissive-2.0, Mozilla's CA list as data). Some crates are offered under several licences, including GPL-2.0-only (`self_cell`) and LGPL-2.1-or-later (`r-efi`). Rift uses each of them under a permissive licence from its OR list, which is what `cargo deny` checks.

`uniffi` (MPL-2.0, in both libraries) is file-level copyleft. It is used unmodified, and its source is public on crates.io; a release must state where that source can be obtained.

Android dependencies, as declared: AndroidX Compose (BOM 2026.09.00), `activity-compose` 1.13.0, `core-ktx` 1.17.0 (resolved to 1.18.0 through a transitive requirement) and `webkit` 1.17.1, all Apache-2.0; JNA 5.19.1, under Apache-2.0 OR LGPL-2.1-or-later, which Rift uses under Apache-2.0. The test-only libraries (AndroidX Test runner, ext-junit, UI Automator) are Apache-2.0 and do not ship.

## Notices in the apps (§25)

Each APK carries its third-party notices as assets, generated at build time, and the controller shows them ("Open-source licences" on the home screen; test l1).

- **Rust crates** (`android/notices.py`, run by `build.sh`): every crate linked into the two libraries, with its licence expression, source, and the licence and notice files it publishes; identical texts once. Twenty crates publish no licence file. For them, `android/licence-texts/crates.txt` names the licence files of their repository at the matching tag (for example YARA-X's BSD-3-Clause, uniffi's MPL-2.0, Wasmtime's Apache-2.0 with LLVM exception). Three crates have no licence file in their repository either. For two MIT crates (`ascii_tree`, `cookie-factory`) the standard MIT text is printed with the crate's listed authors as the holders. `io_tee` and `typed-path` are offered under Apache-2.0 and used under it. A crate that publishes no file and is not listed (with its exact version) fails the build.
- **Android libraries** (`android/notices.gradle.kts`, per APK): every module on the release runtime classpath with the licences its POM (or parent POM) declares. The build fails if one does not offer Apache-2.0, whose text each APK carries. Texts an archive does not carry are kept in `licence-texts/android/` and appended: JNA's licence statement, and libffi's MIT notice, which JNA's native library needs.

The texts in `licence-texts/` were downloaded from the upstream repositories on 20 Oct 2026 and read before being added.

## Security-sensitive dependencies

Owner: the project maintainer (Order52) is the only maintainer, so every row has the same owner. In practice that is a **single point of failure**. §24 asks for a named owner, and it is named; it does not show that the dependencies are actually watched.

| Dependency | Version | In | What Rift trusts it for | Upstream |
|---|---|---|---|---|
| `age` | 0.12.1 | Controller | Quarantine and vault encryption; scrypt passphrase wrapping (fixed N = 2^17, Phase 4 finding 6) | str4d/rage |
| `aws-lc-rs` (AWS-LC) | 1.18.2 | Controller | The only crypto library: TUF signature checks (through `tough`) and the core's TLS (through `rustls`) | aws/aws-lc-rs |
| `rustls`, `rustls-webpki`, `webpki-roots` | 0.23.46, 0.103.15, 1.0.9 | Controller | TLS and certificate checks for downloads and online updates; Mozilla's roots | rustls |
| `ureq` | 3.4.2 (pinned) | Controller | HTTP for downloads and updates. Rift supplies the resolver (destination checks on every hop) and the TLS provider | algesten/ureq |
| `tough` | 0.24.0 | Controller | TUF metadata verification for the threat database | awslabs/tough |
| `url`, `idna`, `unicode-security` | 2.5.8, 1.1.0, 0.1.2 | Controller | URL canonicalization and lookalike detection | servo/rust-url, unicode-rs |
| `hmac`, `sha2`, `scrypt`, `chacha20poly1305`, `x25519-dalek` | as locked | Controller | Index MAC, hashes, and age's primitives | RustCrypto, dalek-cryptography |
| `postcard`, `serde` | 1.1.3, 1.0.229 | Both | The worker protocol and on-disk formats (fuzzed: `protocol_response`, `vault_index`) | jamesmunns/postcard, serde-rs |
| `yara-x` (with `wasmtime`'s Pulley interpreter) | 1.21.0, 45.0.3 | Worker | Rule scanning of untrusted files, inside the isolated worker | VirusTotal/yara-x, bytecodealliance |
| `image`, `png`, `zune-jpeg`, `image-webp` | 0.25.10, 0.18.1, 0.5.15, 0.2.4 | Worker | Decoding untrusted images, inside the isolated worker | image-rs, etemesi254 |
| `seccompiler` | 0.5.0 | Worker | The parser thread's seccomp filter | firecracker-microvm |
| `uniffi`, JNA | 0.32.2, 5.19.1 | Both | The Kotlin–Rust boundary | mozilla/uniffi-rs, java-native-access |
| Android System WebView | The device's (124 on the API 35 emulator; Rift refuses below major version 100, `WebViewSandbox.MIN_WEBVIEW_MAJOR`) | Browser app | The web engine and its renderer sandbox. Not bundled: Google updates it through the Play Store | Chromium |
| `androidx.webkit` | 1.17.1 | Browser app | WebView settings (proxy override, Safe Browsing off, Media Integrity off) | AndroidX |

## Advisory exceptions

`deny.toml` ignores eight advisories, each with its reason. All are reached through `yara-x` 1.21.0, which pins Wasmtime 45.x; it is still the latest `yara-x` release on 20 Oct 2026. Seven are Wasmtime advisories, fixed in Wasmtime 48.0.6; the triage is in [`phase-0.md`](phase-0.md). Six need features Rift does not compile in or use (two Engines, `wasmtime-wasi`, the component model, async). One (RUSTSEC-2026-0359, a guest-defined recursive type chain) could crash the worker, but the guest wasm is generated by `yara-x` from verified rules, and a crash is contained in the isolated worker and reported as "not fully scanned". The eighth (RUSTSEC-2025-0141) says `bincode` is unmaintained, not vulnerable; Rift never deserializes untrusted `bincode`. **Exit condition:** all eight come out as soon as a `yara-x` release depends on Wasmtime ≥ 48.0.6.

## Changes made in this review

- **One crypto library instead of two.** `ureq`'s `rustls` feature brought `ring`, while `tough` already needs `aws-lc-rs`. The core now gives `ureq` rustls' aws-lc-rs provider, and `ring` is in no build. Effect on `librift_ffi.so`: arm64 7.76 → 7.50 MB; x86_64 8.66 → 8.99 MB, since aws-lc's x86_64 cipher code is now linked. All native code is now 19.2 MB (arm64) and 24.5 MB (x86_64), against the 25 MB budget. TLS was rechecked on the host (example.com verified; a wrong-host certificate refused) and on the API 35 emulator (x2).

## Duplicates

`cargo deny` warns about crates present in two versions (for example `sha2` 0.10 and 0.11, `hmac` 0.12 and 0.13, `getrandom` 0.2 and 0.4). They come from dependencies on different RustCrypto generations. Each copy adds size; none is known to be a security problem.

## Gaps

- **Android dependencies have no automated advisory check.** The AndroidX and JNA versions are pinned and current as of this date, but nothing in CI flags a new advisory for them.
- **Notices are as good as their sources.** Where neither a crate nor its repository publishes a licence file, the notice names the authors from the crate's metadata; that is not the same as a copyright statement from the holders. No legal review has been done.
- **No source audit.** Advisory databases list known problems only. The worker's parsers (`yara-x`, the image decoders) run on hostile input; containing them is the isolated worker's job (§8.6), not trust in the parsers.
- **One maintainer** for every dependency.
- **The WebView is outside Rift's control.** Its version on a given device depends on that device's updates; Rift refuses versions below its minimum.
