# Architecture 2.9: threat lists in Check, an optional history

**Date:** 24 October 2026. **Architecture:** 2.9 (§10.12, §10.13, §17, §23 v5 and v6, §24). **Android:** 0.9.1 (0.9.0 with the extra-isolation fix below). **Linux:** on hold ([TODO.md](../../TODO.md)).

## What changed

1. **Threat lists in Check** (§10.12). Four community lists of dangerous hosts, downloaded from their projects on the first tap and then once a day by themselves, and matched on the phone:
   - HaGeZi Threat Intelligence Feeds (medium) and Phishing Army: a host on them is **Listed as dangerous**.
   - uBlock Origin badware and StevenBlack hosts (the list URLCheck uses): a host on them is a warning sign.
   - They only add warnings: nothing is blocked because of a list, and the proxy does not consult them. The 10,000 most visited sites are never flagged by a list.
   - `rift-core::hostlists` reads hosts files, plain host lists, `*.` wildcards and `||host^` rules, with bounds (48 MiB a list, 3 million entries, 16 lists), and keeps hosts as keyed SipHash values. A new fuzz target, `host_lists`.
   - The Security tab has a card for them: a switch per list, the number of hosts and the date of each, Update now and Remove.
2. **Check's history** (§10.13), off by default. On, the last 200 checked links are kept, encrypted with AES-GCM under an Android Keystore key; a tap checks one again; Clear or turning it off deletes it, and off deletes the key too.
3. **"Open safely" and "View safely"** are now "Open in Rift" and "View in Rift": the old labels called something safe.
4. **A comparison tool,** `tools/rift-train/src/bin/compare.rs`, that runs Check's own code on files of links ([check-accuracy.md](check-accuracy.md)).
5. **For later and for others:** [TODO.md](../../TODO.md) (with Linux, which stays on hold) and a brief for an external reviewer ([review-brief.md](review-brief.md)).

## Verified

- **Rust:** 240 tests in the product workspace pass (8 new: list formats, wildcards, single labels refused, bad lists refused one by one, bounded hosts, lists named in Check, popular sites not flagged, trace hops checked), with `clippy -D warnings`, `fmt` and `cargo deny`. `host_lists` ran 1.4 million inputs in 2 minutes without a finding.
- **Accuracy** ([check-accuracy.md](check-accuracy.md)): on 300 current OpenPhish links, Check calls 97.7% dangerous with the lists and 20% without; URLCheck's hosts check flags none. On 20,000 ordinary pages it calls 0.1% dangerous and warns about 0.6%. The phishing figure is partly circular (Phishing Army includes OpenPhish).
- **The time-separated test** ([check-accuracy.md](check-accuracy.md#time-separated-test)): on 190 OpenPhish links whose hosts first appeared about two and a half hours after the lists were downloaded, Check calls 33.7% dangerous (17.9% without the lists) and warns about 63.7%; URLCheck's hosts check flags none.
- **The full suite on the API 34 arm64 emulator** ([evidence](evidence/release-2.9-api34/)): all 62 instrumented tests pass (v5 is new; v6 runs by hand), with the host steps S16d, S16f, S14, S13, H1 and H4, 8 of 8 kills in F4, and the full disk (F6). v5: a host on a danger list is "Listed as dangerous" with the list named, one on a warning list a warning sign, a popular and an unlisted site not flagged; the history keeps nothing while off, keeps a check encrypted when on, checks it again on a tap, and is deleted when switched off.
- **The real lists on the emulator** (v6, by hand): all four downloaded through the core's fetcher and loaded in 29 s; about 6.5 MB more native memory once loaded, with a passing peak of about 90 MB while loading; a whole Check from the app takes p50 1.0 ms, p95 1.4 ms ([v6-real-lists.txt](evidence/release-2.9-api34/v6-real-lists.txt)).

- **The full suite on the Huawei phone** (CHZ-LX1, Android 12, WebView 114, not rooted; [evidence](evidence/phone-huawei-chz-lx1-2.9/)): 52 of 62 instrumented tests pass, among them every session, browsing, download, scan, preview, Check (v1–v5), filter (f1, f2, f7), decoy (d1, i1), Test-open (n9) and other-app (h3) test. 3 fail: s02, because this phone grants POST_NOTIFICATIONS to every app, and x1 and x2, whose control connection the phone's traffic statistics did not count, so both are inconclusive. 7 skip: the fault rounds and H1 need `adb root`, z1 extra isolation, v6 is by hand. Screenshots and the phone's process list are left out of the evidence, since they show the owner's phone. One `adb install` over Wi-Fi hung for 25 minutes and passed when retried. On 0.8.0 the same phone passed 27 of 59, before Rift Browser was allowed under EMUI's App launch.

- **Extra isolation fixed in 0.9.1** (on the Huawei phone, Shizuku 13.7 started with adb, release build). In 0.9.0 the card showed "setting READ_CLIPBOARD failed (255): No UID for org.simulationrift.browser" when Rift Browser was not installed (after it was removed, until Rift's first session installs it again), and with root the firewall step would have thrown. Now each measure says "Applied once Rift Browser is installed, before the first page" and is applied when the browser registers. Checked by hand: with the browser removed the card says so; with it installed, six slow toggles alternated `READ_CLIPBOARD: ignore` and no setting, as read by `cmd appops get`; `pm clear` as shell succeeds and leaves the clipboard setting in place. z1 was not run on the phone (it needs a debug build).

## Unverified

- **A longer time-separated test.** One afternoon's feed (190 links) with a gap of two and a half hours; a day's gap, as the app's once-a-day update gives, was not measured.
- **Updates over days.** The once-a-day refresh shares the filters' timer, but a day's cycle was not observed on a device.
- **x1 and x2 on the phone.** Their control was not counted by the phone's traffic statistics, so they say nothing there either way.

## Could be improved

- **Signed lists.** The lists are not signed by Rift; a list's server decides what Check warns about (§24). A list can only add a warning.
- **Peak memory while loading.** Each list goes through the app as one string; reading the files in the core would avoid the copy.
- **Rift AI on fresh phishing.** It rates 20% of current OpenPhish links High (70% at Elevated or High); the lists carry most of Check's catch on reported phishing. Retraining on fresher feeds would help.
