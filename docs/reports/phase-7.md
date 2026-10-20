# Phase 7 report: hardening (Android, in progress)

**Status (20 Oct 2026):** started on Android. Phase 7 (§22) covers fuzz campaigns, fault injection, privacy captures, the ProxyController study and a dependency review, and its gate is §24's release gates. So far this report covers the privacy measurements (x1, x2), the dependency and licence review ([`dependencies.md`](dependencies.md)), the licence notices in both apps (l1), and the faults these found. Fault injection beyond S13 and S14, long fuzz campaigns and an external review have not started. "Verified" means tested on macOS arm64 and the API 35 emulator (16 KB pages, arm64, WebView 124), and in CI on API 33 and 34 (x86_64) where stated. Nothing here has run on a physical phone.

## Privacy (§17): what Rift sends by itself

§17 asks for traffic captures of (a) local scanning, (b) a manual update and (c) ordinary browsing. On an unrooted device Rift cannot capture packets, so the tests count **bytes per UID on real networks** from Android's own accounting (`dumpsys netstats`, after a forced poll, from its "UID stats" section). Two kinds of traffic are left out by that accounting, and the tests depend on it:

- **Loopback** belongs to no network and is not counted. The fixture server and the test's update server listen on 127.0.0.1.
- **The network lock's tunnel** (type 17, VPN) is left out on purpose: it is where the browser's packets go to be dropped, and nothing in it leaves the device.

A zero means nothing only if the measurement can see traffic. So x1 ends with a **control**: one TCP handshake from the controller's UID to 1.1.1.1:443, which must then be counted.

| ID | Test | Result | Where |
|---|---|---|---|
| x1 | (a) and (b): local work and a manual update send nothing elsewhere | **Pass (API 35).** The steps: a manual update from the configured host (a loopback server, 8 requests, "Installed demo-…"); a download from the fixture; its scan and isolated preview; creating a vault, keeping the file, scanning the vault's copy and locking; then 15 s idle with a session open. Bytes on real networks were the same before and after for both UIDs (controller 18 458 → 18 458, browser 0 → 0). The control was counted (224 bytes). Rift had no alarm and no registered job (`dumpsys alarm`, the "JOB #" lines of `dumpsys jobscheduler`). | `x1_*`, [evidence](evidence/phase7-hardening-api35-16k/) |
| x2 | (c): ordinary browsing leaves only through the controller's proxy | **Pass (API 35).** With the lock on, loading https://example.org/ in the browser app added 8 722 bytes on real networks to the controller's UID (its egress proxy; the proxy counted one more allowed request) and 0 to the browser's UID. The core's own HTTPS (downloads and updates) was also checked on the device: `https://example.org/` was fetched and stored (577 bytes), and `https://wrong.host.badssl.com/` was refused for its certificate ("certificate not valid for name"). The test needs the internet; without it, it is skipped and says so. | `x2_*`, same |

Re-run with the change (`c4949b0`): x1, x2, S8, S9, S10, S10b, S16e and S25, the tests that use the core's fetcher or the proxy, all passed (8 of 8). The full suite of 42 tests last ran on `4a48846`, before the TLS and NAT64 changes ([Phase 4 evidence](evidence/phase4-vault-api35-16k/)).

**What this does not show:**

- **Destinations.** Bytes are counted, not captured. x2 shows that the browser's UID moves nothing on real networks and that the controller's traffic grows. It does not show where the controller's bytes went; INV-13's destination checks are tested separately (S9, S25, `transfer` and `egress` tests).
- **Isolated workers' UIDs.** Preview and scan workers run under isolated UIDs (`u0_iN`), which x1 does not measure. They have no network access by construction (S4 checks that a socket fails), so they are expected to move nothing; that expectation is not measured here.
- **Longer idle periods.** 15 s of idling shows no polling at that scale; Doze-length periods were not measured.
- **The always-on VPN gap** (§24): if the controller dies, the lock goes with it. Not measured here.

### The ProxyController study (§10.3)

Architecture 2.1 replaced the study's question with a design: the browser app's WebView uses `ProxyController` with the implicit bypass rules removed, and the network lock (a VPN for the browser's UID only, which drops every packet) makes the proxy the only route out. x2 is the measurement: the browser's UID moved 0 bytes on real networks while its page loaded through the proxy. S26 (WebRTC and direct sockets have no route) and S28 (losing the lock ends the session) cover the other routes. The residual risk stays as §24 states it: escaped browser code can still reach loopback services.

## Dependency review

Recorded in [`dependencies.md`](dependencies.md): how dependencies are checked, what ships in each library, licences, and the security-sensitive dependencies with their versions, use and upstream. No RustSec advisory applies outside eight triaged exceptions, all reached through `yara-x`'s pinned Wasmtime (each one's reason is in `deny.toml`, and they come out when `yara-x` moves to Wasmtime ≥ 48.0.6). Every licence is allowed, and all crates come from crates.io. The Android libraries are now locked like the crates (Gradle dependency locking: a `gradle.lockfile` per module, transitive versions included), and `android/scan-dependencies.sh` checks those on the runtime classpaths against OSV on every push. No advisories were found. A planted `commons-lang3` 3.16.0 on a runtime classpath was reported, and failed the check.

## Licence notices (§25)

| ID | Test | Result | Where |
|---|---|---|---|
| l1 | Both APKs carry their notices, and the controller shows them | **Pass (API 35, 3 of 3 runs).** The controller's assets hold the Android libraries (155 lines, with JNA and libffi's notice), the Rust crates (285 crates, 12 579 lines, with YARA-X's copyright and the MPL-2.0 text) and the Apache License. The browser APK holds its own list (with the WebView library and no JNA) and the Apache License. "Open-source licences" on the home screen opened the list, and Back returned to the home screen. A screenshot showed the list readable at 1080 px. The first version of the test swiped with UiAutomator's own scroll and did not reach the button in 2 of 3 runs; it now swipes along the column's right-hand margin, where there is no text field. Why the first one failed is not confirmed (a focused text field's keyboard is the suspect, as in S16d). | `l1_*`, `android/notices.py`, `android/notices.gradle.kts` |

## Fault injection

The host kills the controller with `SIGKILL` (as the OS or a crash would) at a random moment while it writes, then starts it again and checks what is left. The test controller writes in a loop and logs each completed step, so the host knows how far it got before the kill. `RIFT_FAULT_ONLY=1` runs only these rounds; `RIFT_FAULT_ROUNDS` sets their number (8 by default).

| ID | Test | Result | Where |
|---|---|---|---|
| F1/F2 | Kill while keeping files into the vault, then check the vault | **Pass (API 35, 8 of 8 kills, twice: alone and in the full run).** Kills came 0.15–3.0 s into each round, after 39–363 completed keeps. Each time the vault opened, held every completed entry and at most one more (a keep whose kill came after its write but before its log line), had no stored file without an entry, and every entry exported to the exact bytes kept (SHA-256), with no plaintext marker anywhere in the app's files. | `f0`–`f2`, [evidence](evidence/phase7-faults-api35-16k/) |
| F3/F4 | Kill while installing the threat database, then check it | **Pass (8 of 8, twice).** One install takes about 0.5–1.2 s on this emulator, and kills came 0.01–1.2 s into it, plus one after it finished. Each time the database was either installed whole or still missing, never damaged; once installed it still found the demo file; and no update copy was left behind (after the fix in finding 6). | `f3`, `f4` |

What this does not cover: a full disk, a kill of the browser app during a page load (S14 kills its renderer), a power loss (a kill leaves the kernel's page cache intact, so it does not test `fsync` ordering), and other Android versions.

## Findings

1. **NAT64 addresses refused every IPv4-only host** (project status finding 50). The core refused all of `64:ff9b::/32` as non-public, and the proxy and the downloader refuse a name if any of its addresses is refused. On a DNS64 network (common on IPv6-only mobile networks) every IPv4-only host also resolves to `64:ff9b::<IPv4>`, so browsing and downloads to all of them were refused. The host network test found it: on this development network, `wrong.host.badssl.com` resolved to such an address. Fixed: an address in RFC 6052's well-known prefix `64:ff9b::/96` is judged by the IPv4 address it carries (so `64:ff9b::7f00:1`, loopback, and `64:ff9b::a9fe:a9fe`, link-local, are still refused). The rest of the /32, including RFC 8215's local-use `64:ff9b:1::/48`, stays refused, because the address it carries says nothing about where the translator sends it. `transfer` tests cover each case.
2. **Two crypto libraries shipped** (finding 51). `ureq`'s `rustls` feature brought `ring`, while `tough` uses `aws-lc-rs`. The core's TLS now uses rustls' aws-lc-rs provider, so `ring` is in no build. Size: arm64 7.76 → 7.50 MB and x86_64 8.66 → 8.99 MB for `librift_ffi.so` (aws-lc's x86_64 cipher code is now linked). Native code totals 19.2 MB (arm64) and 24.5 MB (x86_64), against the 25 MB budget (§18), so x86_64 has 0.5 MB left. TLS was rechecked on the host and on the device (x2).
3. **The scrypt work factor could refuse the right passphrase** (Phase 4 finding 6, project status 48). Found by a full run in this phase and fixed in Phase 4's code: every passphrase wrapping uses N = 2^17.
4. **The local emulator's DNS stopped answering** (finding 49). x1's control first used a host name and failed; the shell could not resolve names either. The control now uses an IP address, so a broken resolver cannot make the measurement look sensitive or insensitive by accident. A restart of the emulator fixed DNS.
5. **Twenty shipped crates publish no licence file** (finding 52). Found while generating the notices: they include YARA-X (BSD-3-Clause, whose notice must be reproduced), the uniffi crates (MPL-2.0) and several Wasmtime crates. Their texts now come from their repositories, pinned by version, and three crates have none anywhere (see [`dependencies.md`](dependencies.md)). JNA's archive also carries no licence text, although its native library contains libffi (MIT).
6. **A kill during an install left the update's copy behind** (finding 53). F4 found the working copy of the update under `files/rift/import` after a kill. It is Rift's own state, on the disposal allowlist, so it did not break isolation, but it stayed on disk until the next import. It is now removed at every start, on the update executor, so before any new install.
7. **An install asked for before the database was open did nothing, silently** (finding 54). F4's first version installed right after the start, while the database was still opening; nothing happened and the home screen said nothing. It now says the database is not open yet.
8. **A browser window that never attached came back on CI** (finding 47, open). On API 34, Android removed a new browser window's task within milliseconds, right after a wipe, so the browser never registered. The cause is still not confirmed. The home screen and the tests now use `Core.openWindow`, which opens the window again if the browser has not registered within 15 s (at most twice) and logs it.

## Release gates (§24)

| Gate | State |
|---|---|
| Every invariant has a passing test on the declared device matrix | **Not met.** All invariant tests pass on emulators (API 33–36, both ABIs, 16 KB pages). The matrix itself has not been declared as a fixed list of devices (§18's reference devices are still unnamed). Whatever it becomes, it must include physical phones, none of which has been tested, and the Linux app, which does not exist yet. |
| Dependency advisories have been reviewed | **Met.** Rust: `cargo deny`, every push, with eight triaged exceptions and an exit condition. Android: the locked runtime classpaths are scanned with OSV-Scanner on every push (none found; a planted vulnerable library was caught). Build tools are reviewed by hand: 24 advisories, all in Android Lint's classpath, which never ships ([`dependencies.md`](dependencies.md)). |
| The licenses inventory is complete | **Met, without legal review.** The inventory is in [`dependencies.md`](dependencies.md). Both APKs carry generated notices for every linked Rust crate and every Android library, and the controller shows them (l1). The build fails when a crate or library has no known licence text. PDFium needs no notice from Rift: Android's `PdfRenderer` uses the system's copy, and Rift bundles none. |
| The evidence reports are published | **Met for what exists**: the phase reports and `evidence/` are in the repository. |
| Every security-sensitive dependency has a named maintenance owner | **Named** (the project maintainer, for all of them). One maintainer is a single point of failure. |

## Still to do in Phase 7

- **More fault injection:** a full disk, power loss (which a kill does not simulate), and the same rounds on other Android versions. Kills while keeping and while installing are done (F1–F4).
- **Long fuzz campaigns** with coverage measurement. The seven targets run for 60 s each on every push, which is not a release-grade campaign.
- **An external review.**
- **A physical phone**, for everything above and for the hardware Keystore.
