# Report: opening listed links, test-open and page checks (architecture 2.6)

**Status (24 Oct 2026):** built and tested on one Android emulator (API 34, arm64, 4 KiB pages; [device](evidence/browser-2.6-api34/device.txt)). Full `run-tests.sh` run, host-driven steps included. Not run on a phone or on API 30/33/35/36.

## What was built

| Part | What it does | Where |
|---|---|---|
| Open a listed link anyway (§10.4) | Under the block, after a warning, "Open in a new session". The core decides the address again, refuses unless it is a known-malicious block, resets, and lets only that host through the navigation check and the proxy's threat-database check in the next session. Red bar, Danger event; the next reset ends it. | `Core.inspectAnyway`, `Sessions::allow_inspection`, `RiftScreen::listed`, `BrowserActivity.Blocked` |
| Test-open (§10.11) | From Check: a new session, the page covered for about 10 s, then the core's report (summary, addresses and decisions, watch events, sites reached, proxy refusals) with **Close and wipe** and **Show the page**. Downloads are reported, not fetched, while covered. | `Core.testOpen`, `Core.testOpenReport`, `TestReport`, `BrowserActivity.TestCover` |
| Page facts (§10.5) | A script reads the page's title, site name, first heading, and whether it has password or card fields; `rift-core::page` flags a protected brand on another site that asks for either, and a password over HTTP. | `ICore.reportPage`, `rift-core/src/page.rs` |
| Address checks (§12.2) | A protected brand inside another host (alone or joined to a lure), a protected name in the path, free hosting, file-name TLDs. | `rift-core/src/heuristics.rs` |
| Check and browser | The verdict's sentence under its title; "Open after a warning" for listed links; back, forward, reload, an editable address, a load bar; timing logs (no addresses). | `MainActivity`, `LinkCheckViews`, `BrowserActivity` |

## Results

| Test | Result |
|---|---|
| Rust: `cargo test --workspace` | Pass, including the new heuristics, `page` and egress `contacted` tests and `an_inspected_link_passes_the_proxy_in_its_session_only`, `pages_named_after_a_protected_brand_are_flagged`. fmt and clippy (`-D warnings`) clean. |
| v4: open a listed link anyway | **Pass.** Asking for a link that is not listed, or for `javascript:`, changed nothing. After the warning, session 20 opened it under a red bar with a Danger event; another listed host was still blocked there, and the proxy refused it (`does-not-resolve`, the demo hosts do not exist); after a reset it was blocked again. [screens](evidence/browser-2.6-api34/screens) |
| n9: test-open | **Pass** (5 of 5 single runs after the fixes below, and in the full run, where it first uses the session so that the test-open has to reset). Three addresses (the redirect, the page, the download), the brand claim, the password over HTTP, the card, the download not fetched, `localhost:8766` reached, level Warning; Show the page removed the cover. |
| `run-tests.sh` (instrumented, clean data) | 58 of 59. f2 failed (2,188 µs a check, limit 1,000); see finding 4. x2 passed once the emulator was started with `-dns-server`. [results](evidence/browser-2.6-api34/instrumented-results.txt) |
| `run-tests.sh` (host-driven) | All pass: S16d, S16f, S14, S13, H1, H4, F4, F6. [results](evidence/browser-2.6-api34/host-results.txt) |
| `cargo deny check` | Pass after a new advisory, RUSTSEC-2026-0387 (crypto-bigint 0.5, through age's P-256 recipients), was triaged and excepted in `deny.toml`: Rift seals with X25519 only, and the fix (0.7.6) cannot be taken by p256 0.13. |
| Speed ([timings](evidence/browser-2.6-api34/timings.txt)) | Over the full run: reset to a new session median 558 ms (90th percentile 1,188, max 1,683); after a reset, the new window registered in about 0.25 s and its network was confirmed about 0.45 s later; a fixture page loaded in a median 17 ms. Window-to-first-page times of 27–34 s are tests that open an empty window and send the link later, not slow starts. |

## Findings

1. **A test-open window kept its cover for a link opened directly.** A later link in the same session was covered and its downloads were reported, not fetched; seven tests after a failed n9 failed this way. A link the user opens directly now ends the test-open.
2. **API 34 kept a stale accessibility tree for the cover.** The report was on screen and UiAutomator still saw the countdown. n9 now reads the tree fresh (`awaitFresh`), as other tests on this Compose window do. The countdown, which changed four times a second, is now fixed text.
3. **v4 (first named n8) installed the demo database before s16a, which needs none.** It is renamed so it runs after s16, like the other tests that install it.
4. **f2 is unstable on this emulator, with or without these changes.** A filter check through the bridge took 499 µs once, right after a reboot, and 2.2–3.5 ms in every other run (limit 1 ms), including the committed build (b0f42c8), after `pm clear`, after a reboot, with ahead-of-time compilation and without `adb root`. The Rust call is a single adblock lookup with no lock contention, so the time is in the call through the bridge on this emulator. Not caused by this work; not explained. The browser's own log showed 1.8 ms for a real request.
5. **x2 needs the internet.** The emulator first resolved no names; started again with `-dns-server 1.1.1.1,8.8.8.8`, x2 passed.
6. **Speed.** A test-open in a session no page or window has used no longer resets first. Overlapping the sandbox check with applying the proxy was tried and measured: no gain, as both wait on the WebView provider loading (about 100 ms), so the order stays as it was. The debug timing log on every filter check was removed.

## Verified

- A listed link opens only after the warning, only in a new session, only for its host, and only until the next reset (v4, Rust tests).
- The browser cannot lift a block: the core decides the address again (v4).
- Test-open shows the report before the page, and a download is not fetched while covered (n9).
- A page that calls itself PayPal and asks for a password and a card on another site is flagged (n9, `page` tests).

## Unverified

- Real phishing pages and real known-malicious sites: only fixtures and demo indicators were used.
- Other API levels, a phone, 16 KiB pages, the release build.
- Whether a page can tell it is being test-opened (it can measure that it is not visible).
- The speed of session start on a phone.
- Why f2 is slow on this emulator.

## Could be improved

- Reset: about half of it is Android stopping and clearing the browser app, and the rest starting a fresh instance to check it holds no files; both are what the reset proves (§15), so they stay.
- The test-open report lists addresses without breaking long ones; on a 320 dp screen a long one wraps under its bullet.
- Test-open covers 10 s fixed; a page that waits longer is not seen.
