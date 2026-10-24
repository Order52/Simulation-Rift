# Architecture 2.8: skip sign-ins and pop-ups, lists that keep themselves up to date, trackers in Check

**Date:** 24 October 2026. **Architecture:** 2.8 (§10.9, §10.10, §17). **Linux:** on hold, not touched.

## What changed

1. **One switch, "Skip sign-ins and pop-ups"** (Filters tab, on by default). It turns on the lists that take down sign-in walls and annoyances, and makes the browser dismiss pages' dialog boxes unseen.
   - New lists, all downloaded from their own projects: Dandelion Sprout's "Browse websites without logging in" and its uBlock Origin extension (Dandelicence), AdGuard's social, pop-up and other annoyance lists (GPL v3). Fanboy's social list and uBlock Origin's annoyances join the switch.
   - Dialogs: `alert` and `confirm` and `prompt` are cancelled (the page gets no, or nothing), and "Leave this page?" is answered yes. Each dismissal is a note in the live watch.
2. **Lists can now restyle and remove, not only hide.** A wall is usually a box over the page plus a page that will not scroll or is blurred, and the lists undo it with procedural rules (`:has-text`, `:upward`, `:style`, `:remove`, `:remove-class`, `:remove-attr`). Brave's adblock crate parses them (its `css-validation` feature, which pulls in Servo's `selectors` and `cssparser`, MPL-2.0).
   - The core checks every such rule (`filters::change`) and drops the whole rule on anything it does not know. A style may change how things look but cannot load anything (`safe_style`: no `url(`, `image(`, `@`, quotes, braces, comments and the rest).
   - A fixed script in the browser applies what passed. It is Rift's script, fed with checked data; **list scripts (`##+js`) never run**, so lists still cannot run code in a page (INV-6 unchanged).
3. **Hands-free updates.** After the user's first download, every list that is on, and Check's ClearURLs rules, are downloaded again when four days old: checked a minute after start and every six hours while Rift runs. "Keep the lists up to date" (on by default) turns it off.
4. **Trackers in Check.** Check already named tracking parameters and redirect links (ClearURLs). It now also says when the content filters list the link's server itself as an ad or tracker server (a host rule, such as EasyPrivacy's). It informs; the verdict does not change.
5. **A test helper.** A test run on its own could ask for the local-host allowance before the first session was up; `allowFixtureHost` now waits for the session.

## Verified

- **Rust:** 232 tests in the product workspace pass, with `clippy -D warnings`, `fmt` and `cargo deny`. New tests:
  - Sign-in walls are taken down by the rule shapes the real lists use for Reddit, Quora, Instagram and Pinterest (a style, a removal, text plus `upward`, a class and an attribute taken off).
  - A list's script and `:matches-css` are dropped.
  - A style can only change how things look (`url(`, `@import`, braces, quotes and the rest are refused).
  - The number and size of changes are bounded.
  - An attempt to write a second rule through a style is refused.
- **F7 on the API 34 arm64 emulator** (WebView 113), with the user's own rules and no downloaded list:
  - With the switch on: the sign-up box and a later one are removed, the feed's blur class, `inert` attribute and blur style are taken off, and scrolling comes back. A nag found by its text is hidden, `confirm` and `prompt` get no and nothing, the alert is dismissed, and the watch notes it.
  - A `+js` rule does nothing.
  - Check names a server a host rule lists, and not one it does not.
  - With the switch off, the page is as it was, and dialogs are no longer dismissed.
- **F1 and V3** pass unchanged (filters, link cleaning).
- **The full suite on the API 34 arm64 emulator** ([evidence](evidence/release-2.8-api34/)): all 60 instrumented tests pass (f7 is the new one; the 6 that skip there run from the host or need extra isolation), and the host steps S16d, S16f, S14, S13, H1 and H4, 8 of 8 kills in F4, and the full disk (F6).
- **Real lists, by hand on the host:** the new lists compile with the others, in about 13 ms in a release build, and a page's lookup takes microseconds.

## Unverified

- **Real social sites on a device.** The rules were checked against the real lists' shapes, not against live Reddit, Instagram or Pinterest pages in Rift. Sites change their walls often, and the lists follow them, so how well it works depends on the lists.
- **The automatic updates over days.** The timer's logic is simple, but a four-day cycle was not observed on a device.
- **The phone.** 2.8 has not been run on the Huawei phone.

## Could be improved

- **Walls built with scripts only** (LinkedIn's, some of Quora's) stay, because list scripts never run. A small set of Rift's own fixed scriptlets, fed checked arguments, would cover them without running list code.
- **Location by IP address.** Pages see the phone's IP address and so roughly where it is. Rift hides the device's model, time zone, GPU and memory, and gives made-up location and sensors (i1), but cannot hide the address while its network lock takes Android's only VPN slot. A relay (Tor, or a VPN chained behind the proxy) would.
- **Tracking in Rift AI.** Rift AI scores phishing and malware addresses; it was not trained to recognise tracking, so Check's tracking notes come from ClearURLs and the filter lists only.
