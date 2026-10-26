# Architecture 3.0: Rift AI reads the page, trackers explained, old WebViews refused

**Date:** 26 October 2026. **Architecture:** 3.0 (§8.4, §10.11, §10.14, §11.1, §12, §16.1, §23 N10 and S15b, §24). **Android:** 0.10.0. **Linux:** on hold ([TODO.md](../../TODO.md)).

## What changed

1. **Rift AI's page model** (§16.1, [page-model.md](page-model.md)). A script in the sealed browser counts what each loaded page is made of (forms and where they send, links, frames, scripts, obfuscation, title and text); the core scores the counts with a logistic model and, at High, adds a *Warning* with its reasons to the live watch, before anything is typed. Trained by `tools/rift-train page` on 80,000 saved pages (CC BY 4.0), with the app's own feature code.
2. **Check the live page.** Test-open (§10.11) is now the prominent second button in Check, named for what it does, and its report has **Rift AI's reading of the page** and **Trackers (n)**. Check itself still never contacts the site, and the screen says why: the site cannot tell its link was looked at (§17).
3. **Trackers named and explained** (§10.14). Check lists the tracking parameters in a link (who adds each and what it tells them) with **Remove the tracking**; the live watch names each tracking service a page reaches (49 services, four kinds, each kind explained) and says how to stop it, and notes what the content filters blocked.
4. **A WebView missing an exploited fix is refused** (§8.4, INV-7): the Chromium entries of CISA's Known Exploited Vulnerabilities catalogue (6 for 2026, checked 23 Oct 2026). Debug builds may allow it, so tests can run on the emulators' WebView 113; S15b checks the refusal.
5. **Fixes from an internal security review:**
   - A download's redirects: each hop is checked against the threat database before it is fetched (`DownloadError::Listed`).
   - The scan cache: keyed by what the file claims to be as well as its hash, so the same bytes under a misleading name are scanned again; timed-out and failed scans are not cached. An Android app (DEX, or a ZIP with `AndroidManifest.xml`) under another name is a type mismatch.
   - IPv6: IPv4-compatible (`::/80`), SIIT (`::ffff:0:0/96`), discard (`100::/64`) and Teredo (`2001::/32`) addresses are refused; 6to4 (`2002::/16`) is judged by the IPv4 address it carries.
   - Files shared to Rift: only from a content provider that resolves, never from an authority with user information.
   - Every call to the browser app during a reset is bounded at 10 s.
   - The proxy caps pending connections, gives each request's head a deadline, and serves one plain-HTTP request per connection.
   - Runs of spaces in a file name are collapsed, so they cannot push the real extension out of view.
6. **Smaller and lighter.** Release native code is built for size (opt-level "s", fat LTO): the arm64 libraries went from 9.2 + 11.7 MB to 7.5 + 10.7 MB, and the release APK from 26.7 MB to 24.2 MB. The narrow-screen layout of Rift AI's score in Check was fixed.
7. **The repository**: the README has screenshots from the emulator (`docs/images/`), install and build steps; the page model's notice ships in the app.

## Verified

- **Rust:** 259 tests in the product workspace pass, with `clippy -D warnings`, `fmt` and `cargo deny` (advisories, bans, licences and sources ok; `scraper` and its html5ever stack are in the trainer only).
- **The page model** ([page-model.md](page-model.md)): on 8,674 pages of sites it never saw, AUC 0.950; at High it flags 54.2% of phishing pages and 0.23% of legitimate ones; at Elevated or High, 68.8% and 4.5%.
- **The full suite on the API 34 arm64 emulator** (WebView 113; [evidence](evidence/release-3.0-api34/)): all 64 instrumented tests that run there pass, n10 and s15b among them, with the host steps S16d, S16f, S14, S13, H1 and H4, 8 of 8 kills in F4, and the full disk (F6). Skipped as before: the fault rounds and H1 run from the host, v6 (the real lists) by hand, z1 needs Shizuku.
  - n10: a fixture shaped like a phishing kit was reported "closely resembling phishing pages: most of its links go nowhere; its form posts to a bare PHP script, as phishing kits do; it blocks the long-press menu".
  - s15b: with the debug allowance off, WebView 113 was refused, naming the exploited bug and the fixing version, and navigation was refused as sandbox-unavailable.
- **A regression found and fixed during this work.** Making `IBrowser.shutdown()` one-way let the browser's task removal overlap the reset's wipe. Once, on API 34, that left Android with a browser process record that never started (pid 0), so every reset failed until the browser was force-stopped. `shutdown()` is two-way again, bounded at 10 s; the next two full runs passed.
- **f2 (a filter check's cost)** failed once inside a full run (5.1 ms a check against 0.58 ms for an empty call; limit 8×), then passed three times alone and in the next two full runs. It measures the bridge under CheckJNI on a loaded emulator ([release-2-7.md](release-2-7.md), "f2 explained").
- **Trackers in Check**, by hand on API 34: a link with `utm_source`, `fbclid` and `gclid` showed "This link carries 3 trackers" with each explained ([screenshot](../images/check.png)); `rift-ffi` and `trackers` tests cover the explanations, the removal and the host lookup.

## Unverified

- **The page model on current pages and on a phone.** Its data is from 2020–2021, and it was run only on the emulator.
- **Tracker notes in the live watch on a real site.** The device tests have no internet, so no real tracking service was reached; the lookup is unit-tested.
- **The release build's refusal of an old WebView.** Tested in a debug build with the allowance off (s15b); the release build, which ignores the allowance, was built and signed but not installed, because the emulators' WebView 113 would refuse to browse there, which is the point. The owner's Huawei phone (WebView 114) will be refused until its WebView is updated.
- **x2** passed in the final run and skipped in an earlier one ("needs the internet"): it depends on the emulator's network.

## Could be improved

- A device test for the tracker notes, with a local fixture host named like a tracker.
- The KEV list is updated by hand each release; a signed pack could carry it, like Rift AI's model.
- The page model's data is old: retrain on current captured pages and add a time-separated test.
- An external security review and the signing-key ceremony are still needed before Rift can be called production-ready.
