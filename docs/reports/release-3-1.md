# Architecture 3.1: Rift updates itself, a dark theme, Rift AI keeps a memory

**Date:** 26 October 2026. **Architecture:** 3.1 (§8.11, §16, §17). **Android:** 0.11.0. **Linux:** on hold ([TODO.md](../../TODO.md)).

## What changed

1. **Rift updates itself** (§8.11). Once a day, with the switch on (the default):
   - The core reads GitHub's answer for the latest release (`rift-core::appupdate`). It accepts only a final `vX.Y.Z` release that is newer than the installed version, with assets at exactly the release workflow's addresses.
   - It downloads the APK from addresses it derives from the version, and keeps the APK only if it has the published SHA-256.
   - The controller (`SelfUpdate.kt`) checks the package, a higher version code, and exactly Rift's signing certificates, then installs with `PackageInstaller`. The first time, Android asks. After that (API 31+), Rift updates by itself while none of its screens is in front and no browser window is open.
   - About → Updates has the switch, the state, **Check now** and **Install now**.
   - Debug builds never update themselves.
2. **Dark theme** for the controller and the sealed browser, following the system or forced to Light or Dark (About → Appearance).
   - The choice reaches the browser in its session grant (`Appearance`). An unknown value decodes to System.
   - The browser's WebView gets a themed context, so `prefers-color-scheme` follows the choice, and on dark, algorithmic darkening covers pages without a dark style.
3. **Rift AI keeps a memory.** The monthly retrain now also trains on the phishing pages of the last 24 months (`tools/rift-train/memory.py`, at most 1.5 million). The workflow hands the memory from run to run as an artifact. It is never committed ([rift-ai.md](rift-ai.md#learning-from-new-data)).
4. **Toolchains move by themselves.** A monthly workflow (`toolchains.yml`, `.github/scripts/bump_toolchains.py`) moves stable Rust, the fuzzing nightly, the NDK, cargo-ndk and OSV-Scanner (with the SHA-256 of the binary) to their latest releases. Its pull request merges itself when CI passes.
5. **The README's screenshots** are now the dark theme, taken from the instrumented tests' evidence (w1, n7, n10) on the API 34 emulator.

## Verified

- **Rust:** 264 tests in the product workspace pass, with `clippy -D warnings`, `fmt` and `cargo deny`. Five are new, in `appupdate`:
  - a release of Rift is read;
  - assets anywhere else are refused (another repository, a lookalike host, another tag's file, plain HTTP), as is a release without its SHA-256 file;
  - pre-releases, odd tags (`v0.10`, `v0.10.3.1`, `v0.10.-3`, `v0.10.3-beta`, `v0.10.+3`, too many digits) and malformed JSON are refused;
  - only a strictly newer version replaces the installed one, and an unparsable installed version is never replaced;
  - the digest is checked, and a SHA-256 file naming another file is refused.
- **Android build:** `android/build.sh` (both ABIs, bindings, debug APKs, JVM unit tests) passes.
- **On the API 34 arm64 emulator, in dark mode:**
  - n7, n10 and w1 pass, and their screenshots are the README's.
  - By hand: About shows the Appearance and Updates cards. Choosing Light while the system is dark turns both the controller and the browser light, and the page is served light. On a debug build the update switch is off and disabled, with "A test build".
- **The memory script** with fixtures: it keeps the newest month for a URL, drops entries older than 24 months and malformed lines, and refuses a bad month.
- **The toolchain bump** with stubbed answers, on a copy of the files: every pin moved, and a second run changed nothing.

## Unverified

- **No self-update from a real release has run.** The first release with this code (0.11.0) can only update itself to the release after it. Not tested on a device:
  - the confirmation the first time;
  - the install without asking on API 31+;
  - the background condition;
  - the replaced app restarting.
- The install-result broadcast is registered by the application context. Android ends the process on success, so a successful update is seen only as the new version.
- The memory hand-over, the toolchain bump and the automatic merges have not run on GitHub yet.
- x1 (nothing sent by itself) still ran on a debug build only, where self-update is off. A release build makes the daily request (§17).

## Could be improved

- A device test for self-update, from a local server serving a release with a higher version code, signed with the test key.
- The danger colour in dark mode is Material's dark `error` (light red, dark text): readable, but brighter than the rest of the dark theme.
- The browser's status bar is not themed when the appearance is forced against the system.
- The page model is still trained by hand: its 80,000 pages are not available to the workflow, so the memory covers the address model only.
- The memory lives in 90-day artifacts. After three months without a successful run it starts again.
