# Architecture 3.1: Rift updates itself, a dark theme, Rift AI keeps a memory

**Date:** 26 October 2026. **Architecture:** 3.1 (§8.11, §16, §17). **Android:** 0.11.0. **Linux:** on hold ([TODO.md](../../TODO.md)).

## What changed

- **Updates at launch (§8.11, 27 October 2026):** with *Check when Rift opens* on (the default), each launch asks GitHub for the latest release and a newer one is offered in a dialog: *Update* downloads it, checks it (published SHA-256, package, version, Rift's key, as before) and installs it. *Check for updates* in About works whatever the switches, and neither it nor the launch check downloads before the user taps Update.

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

6. **0.11.1: nobody needs to look after it.**
   - Rift AI's gate also holds every new model to the hand-checked model's report (`tools/rift-train/baseline.json`), not just the last one, so small losses within the limits cannot add up from month to month.
   - `caretaker.yml` runs a failed CI run's failed jobs once more (a flaky emulator test no longer holds back a merge or a release). Weekly, it turns every workflow on again (GitHub turns scheduled workflows off after 60 days without activity), rebases its own bots' pull requests that failed on an older `main` (Dependabot's it asks Dependabot to recreate), and closes monthly bot pull requests still open after 40 days. Every 6 hours it approves held CI runs: GitHub holds the `pull_request` runs on a branch a bot pushed ("action_required") until someone approves them, and branch protection counts only those runs, so a passing CI started another way (`workflow_dispatch`) left pull requests #3 and #4 blocked. It approves only runs on this repository's own branches whose actor is `github-actions[bot]` or `dependabot[bot]`, never a fork's.
   - The README has a one-tap **Add Rift to Obtainium** link, with the APK filter set.
   - `run-tests.sh` runs a device test that failed in the full run once more on its own, and records one that then passes as `PASS-ON-RETRY`, not `PASS`. The first failure stays in `instrumentation.txt`. CI's API 33 emulator failed n10 and v5 on one run and f2 on the next, each a timing or scrolling wait. Those three were also made steadier: f2 takes the quickest of five rounds, v5 reads the lists line where it is, and n10 waits between swipes.
   - **Rift AI's gate compares like with like.** `rift-train --champion` measures the shipped model on the new run's test sites, and the gate holds the new model to it with tighter limits. It also refuses a model trained when a feed failed or shrank (fewer than half the test sites of the last report). Fixed on the way: `retrain.sh` ran `cargo run -p rift-train` without `--bin`, which Cargo refuses since the crate has three binaries, so the first monthly retrain would have failed.
   - **Store metadata** in `fastlane/metadata/android/en-US` (title, descriptions, screenshots, the 0.11.1 changelog), the layout F-Droid and IzzyOnDroid read, ready for a listing.
7. **0.11.1: phones that refuse to start Rift Browser for Rift.** On a phone whose maker blocks one app from starting another (Huawei's App launch, Xiaomi's Autostart, ColorOS's auto launch and the like), the first cleanup failed with "the system would not start the browser app", and Rift stopped there.
   - The controller now opens the browser's `WakeActivity` when the system refuses to start the browser for a binding. It has no window, finishes at once, and needs the signature permission. These phones let the app in front open another app's screen. Once the browser's process runs, the controller binds again. The wipe and its inventory are unchanged, so a wake that left a file would still fail the reset.
   - If the phone blocks that too, the message names this phone maker's setting, and the card has a button for Rift Browser's app settings.
   - **Check keeps working** while cleanup has failed: the address field and Check stay on the card, and only Open in Rift waits for a clean session. Check needs no browser.

## Verified

- **Updates at launch:** N11 passes on the API 34 emulator (the dialog for a made-up release, its update button, Later, About's Update now and the launch switch); the About card with both switches seen in a debug build. JVM unit tests pass.

- **Learned brands (§10.3, 27 October 2026):** the shipped list (34 hand-picked, 75 learned) parses whole (`heuristics` test); the gate (`rift-train brands`) on 556,204 ordinary and 59,523 live phishing addresses: brand warnings 0.079% → 0.079% and 1.9% → 2.4%; on the API 34 emulator n2 and v1 pass with it, and n9 alone (run straight after v1 it once failed to find the cover; `run-tests.sh` retries a test on its own).
- **Test-open names redirect tracking and app attempts (§10.11, 27 October 2026):** on the API 34 emulator n9 test-opens a link whose redirect carries `utm_source` and `fbclid`; the report lists both under *Tracking in the addresses it went through*, with the hops, sites and warnings as before.
- **Links to other apps explained (§10.15, 27 October 2026):** the `applink` unit tests cover each kind of link in §10.15's table, values cut and escaped, unparseable and oversized links; on the API 34 emulator v1 shows a UPI payment link as *Dangerous app link* and a WhatsApp send link as *Opens WhatsApp*, `javascript:` still as *Rift won't open this*, and n1 still blocks a page's `intent:` link.
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
- **The wake screen, on the API 34 emulator (root):**
  - started after a clear, it brings up the browser's default process, leaves no file in its data directories, and no activity remains;
  - a caller without Rift's permission (the shell's UID) is refused (`Permission Denial … requires org.simulationrift.permission.RIFT`);
  - with SessionService disabled (a binding that can never succeed), launch ends in the new message with the settings button and the address field. Check works there (659 µs), and Retry cleanup recovers once the service is enabled ("browser wiped: pid 4884 -> 4932, no files");
  - a normal launch and s12 (a reset destroys every session store), l1 and s15 still pass.
- f2, v5 and n10 pass on the API 34 emulator after the change (f2: 1968 µs a check, the quickest of five rounds, against 439 µs for an empty call).
- **v0.11.2 released by the release workflow (27 October 2026):** with the toolchain bump (#4) and Dependabot's Android updates (#3), both merged by themselves once their held CI runs were approved. The workflow started CI on `main`, but the follow-on release never started: GitHub starts no workflow (here, `workflow_run`) for a run the workflow's own token started. Run again once CI had passed, it built and published `rift-0.11.2.apk` (SHA-256 `0cf00ee3…4729`) and `rift-browser-0.11.2.apk` (`4fecbdc6…546e`); the published `.sha256` files match GitHub's asset digests. `release.yml` now waits for the CI run it starts and releases in the same run, running failed jobs once more (the caretaker never sees that run); this new path has not run yet.
- **Every maintenance workflow run once by hand (26 October 2026):** the caretaker rebased Dependabot's pull request #3 and restarted its CI; the exploited-WebView update ran; the toolchain bump opened pull request #4 once its pins moved to `.github/toolchains.env` (GitHub refused its push while they were in workflow files); the retrain ran end to end once `prepare.py` stopped needing the URLhaus list, and its gate refused the month's model for flagging 1.37% of popular sites' pages High (the shipped model: 0.16%).
- **Champion and data checks:** `rift-train --champion models/url-model.bin` on synthetic sources measures the shipped model on the same 615 test addresses as the new one. The gate passes an unchanged report, and refuses a model 0.003 AUC below the champion on the same sites (which the 0.005 limit against the shipped report alone let through), one with an ordinary source 0.1 points higher at High, and one whose Common Crawl test sites fell to a third.
- **The gate's baseline:** an unchanged model passes; a model 0.004 AUC below the baseline passes; a further 0.004 drop passes against the shipped model alone (the old rule) but is refused against the baseline.
- **The caretaker's queries** on the live repository: they list every workflow, and they pick out both Dependabot pull requests, which had failed on a `main` without the `tools/kev` fix.
- **The toolchain bump** with stubbed answers, on a copy of the files: every pin moved, and a second run changed nothing.

## Unverified

- **The launch check against GitHub, and a one-tap update end to end:** only a release build checks, and none with this change has been installed over an older one yet. The first will be v0.11.4 updating to the release after it.

- **No self-update from a real release has run.** The first release with this code (0.11.0) can only update itself to the release after it. Not tested on a device:
  - the confirmation the first time;
  - the install without asking on API 31+;
  - the background condition;
  - the replaced app restarting.
- The install-result broadcast is registered by the application context. Android ends the process on success, so a successful update is seen only as the new version.
- The memory hand-over, the toolchain bump and the automatic merges have not run on GitHub yet.
- Whether the workflow's own token may approve a held run is not yet seen; approving with the owner's account worked (27 October 2026, PRs #3 and #4). The caretaker has not run on GitHub yet. That turning a workflow on again restarts GitHub's 60-day count is how GitHub documents and others use it, not something seen here. Rebasing a Dependabot branch with `gh pr update-branch` made Dependabot give up on that pull request ("edited by someone other than Dependabot", #3), so the caretaker now comments `@dependabot recreate` instead; whether Dependabot accepts that from `github-actions[bot]` is not yet seen.
- The Obtainium link was not opened on a phone.
- **The wake was not tried on a phone that blocks launches.** The emulator cannot block a binding the way these phones do, so the case where the wake itself lets the binding through is unverified. The Huawei CHZ-LX1 has passed before with App launch allowed (2.9).
- x1 (nothing sent by itself) still ran on a debug build only, where self-update is off. A release build makes the daily request (§17).

## Could be improved

- A device test for self-update, from a local server serving a release with a higher version code, signed with the test key.
- The danger colour in dark mode is Material's dark `error` (light red, dark text): readable, but brighter than the rest of the dark theme.
- The browser's status bar is not themed when the appearance is forced against the system.
- The page model is still trained by hand: its 80,000 pages are not available to the workflow, so the memory covers the address model only.
- The memory lives in 90-day artifacts. After three months without a successful run it starts again.
