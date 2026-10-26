# Rift

Open any link, and any image or PDF, without letting it near your phone. Rift is a local Android app (Linux is on the to-do list and not supported now) with two jobs:

- **Check a link before you open it.** Paste it, or share it to Rift from any app: a sheet comes up over that app with a verdict (*Known malicious*, *Listed as dangerous*, *Looks dangerous*, *Warning signs*, *Rift won't open this* or *No known threats found*, never "safe"), **See what's wrong** for the reasons, and **Open in Rift**. The check runs on the phone and sends nothing anywhere: the threat database, the address checks (lookalikes of well-known sites, shorteners, links that hide their real host), **Rift AI**, a model of phishing and malware addresses trained on public feeds ([how well it does](docs/reports/rift-ai.md)), and community **threat lists** (HaGeZi, Phishing Army, uBlock Origin badware, StevenBlack) that update themselves once you have downloaded them. On 300 current phishing links it called 97.7% dangerous, where URLCheck's hosts check flagged none ([comparison, with its caveats](docs/reports/check-accuracy.md)). A history of checked links is there if you turn it on, encrypted on the phone.
- **Open it safely and watch what it does.** Links open in a sealed, disposable browser: a separate app with its own Linux user, no permissions, and no network except Rift's checking proxy. Everything it held is wiped by Android when the session ends. While the page is open, the **live check** lists what it tries: a listed address, your local network, a connection around the proxy, a download, and every device feature it asks for.

**Decoys.** A page that asks for the camera, microphone, screen, location, files, notifications, clipboard, motion sensors or battery is told yes and given something made up: a live video of a dim room, near-silence, a position near a city centre, a generated photo, an empty clipboard. A phishing or spying page carries on as if it had won, and you see what it was after. Nothing real is given: the browser app holds none of those permissions, and the engine still refuses a page that gets past the decoys.

**Files.** Downloads and files shared to Rift go into an encrypted quarantine for the session, are scanned in isolated workers, and images and PDFs are drawn by an isolated worker that has no files and no network. Text is shown as plain text, never run.

**Extra isolation (optional, Shizuku or root).** With [Shizuku](https://shizuku.rikka.app) or Sui running, one switch lets Rift use Android's own tools on its browser: Android ignores the browser's clipboard (so a page cannot swap what you copy), Android itself wipes the browser at each reset, and with root a firewall keeps the browser to Rift's proxy on the phone too, closing the one gap the VPN leaves (other apps' local servers). Each change is checked after it is made, and undone when you switch it off. Copy and paste in Rift's browser stop working while it is on.

**Filters.** Rift blocks ads and trackers and hides cookie banners, pop-ups and "Sign in with Google or Facebook" prompts in its sealed browser, with the lists the community already keeps (EasyList, uBlock Origin, Fanboy). Rift writes none of the rules; you download the lists when you choose, switch each one on or off, and can add rules of your own. The app is five tabs: Home, Filters, Activity, Security and About.

**One file.** Rift is one APK. On first launch it installs the sealed browser it carries (Android asks you to allow it), because the browser has to be a separate app to be isolated. If you need your own VPN, the **Network lock** switch turns Rift's off; sessions are then labelled "reduced isolation" and still go only through Rift's checking proxy.

**This week.** The home screen counts the threats blocked, dangerous files, warnings and links checked over seven days, kept as numbers only. Nothing else is kept after a session, and nothing asks for a password.

<p align="center">
  <img src="docs/images/home.png" width="23%" alt="Home: the link field and this week's counts">
  <img src="docs/images/check.png" width="23%" alt="Check: a verdict with Rift AI's reasons and the trackers in the link">
  <img src="docs/images/live-check.png" width="23%" alt="Check the live page: Rift AI's reading, the trackers and the sites the page reached">
  <img src="docs/images/browser.png" width="23%" alt="The sealed browser with the live watch in its bar">
</p>

**Trackers, explained (0.10).** Check names each tracking parameter in a link (`fbclid`, `gclid`, `utm_…` and others), says who added it and what it tells them, and removes them with one tap. While a page is open, the live check names each tracking service the page reaches (Google Analytics, Meta's pixel, Hotjar's session replay …), explains what that kind of tracker records, and says how to stop it.

**Rift AI reads the page too (0.10).** Besides the address model, a second model looks at what an opened page is made of: password forms that send to another site, brand names that do not match the site, urgent "your account is locked" text, hidden frames, obfuscated scripts. It warns before you type anything ([how well it does](docs/reports/page-model.md)). **Check the live page** in Check loads the link out of sight for 10 seconds in a new sealed session and reports where it went, what it asked for, its trackers, the sites it reached and Rift AI's reading of it. Plain Check never contacts the site, so the sender cannot tell the link was looked at.

**Old WebViews are refused (0.10).** If the phone's Android System WebView lacks the fix for a Chromium bug known to be exploited in the wild (CISA's catalogue), Rift will not open pages in it and says which update fixes it.

## Install

Download `rift-<version>.apk` (arm64) from [Releases](https://github.com/Order52/Simulation-Rift/releases) and check its SHA-256 against the one in the release notes. Open it on the phone (Android 11 or newer, arm64) and allow the install. On first launch Rift installs the sealed browser it carries; Android asks you to allow that too. The release also offers that browser on its own, `rift-browser-<version>.apk`, which is **optional**: download it only if your phone blocks Rift from installing it (some Huawei phones do), install it by hand, then open Rift. Installing a newer release over an older one keeps your settings.

## Build from source

```sh
sh android/build.sh            # Rust libraries, bindings, debug APKs and unit tests (needs the NDK, cargo-ndk and JDK 21)
sh android/run-tests.sh <dir>  # the device suite on an attached emulator, with evidence written to <dir>
cargo test --workspace --locked
```

[`CLAUDE.md`](CLAUDE.md) lists every command; [`docs/architecture.md`](docs/architecture.md) §21 the conventions.

> **Status: in development; not audited.** The Android debug build is tested on emulators (API 33–36) and installed on one phone (Android 12). [`STATUS.md`](STATUS.md) says what works, what is left and the limitations; [`docs/architecture.md`](docs/architecture.md) is the design; [`docs/reports/`](docs/reports/) is the evidence for each claim.

## What it is not

- It is not an antivirus, a VM, or a malware detonation lab. It never runs downloaded programs.
- It sends no content to a cloud service.
- It does not claim perfect isolation or that any link is safe. Each security claim names its boundary and the test that shows it; what is not covered is in [architecture §24](docs/architecture.md).

## Repository layout

| Path | Contents |
|---|---|
| `docs/architecture.md` | Architecture, threat model, invariants, roadmap |
| `docs/reports/` | Per-phase evidence: verified, unverified, and could be improved |
| `docs/images/` | Screenshots from the API 34 emulator |
| `poc/` | Phase 0 feasibility harnesses (not product code) |
| `crates/` | Rust workspace (Phase 1 onward) |
| `android/` | Android app (Phase 2 onward) |
| `models/` | Rift AI's models (address and page), their notices and data sources |
| `tools/` | Maintainer tools: the signed-pack builder and `rift-train` (Rift AI's trainer) |

## License

Dual-licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
