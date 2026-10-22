# Rift

Open any link, and any image or PDF, without letting it near your phone. Rift is a local Android app (Linux later) with two jobs:

- **Check a link before you open it.** Paste it, or share it to Rift from any app: a sheet comes up over that app with a verdict (*Known malicious*, *Looks dangerous*, *Warning signs*, *Rift won't open this* or *No known threats found*, never "safe"), **See what's wrong** for the reasons, and **Open safely**. The check runs on the phone in microseconds and sends nothing anywhere: the threat database, the address checks (lookalikes of well-known sites, shorteners, links that hide their real host) and **Rift AI**, a model of phishing and malware addresses trained on public feeds ([how well it does](docs/reports/rift-ai.md)).
- **Open it safely and watch what it does.** Links open in a sealed, disposable browser: a separate app with its own Linux user, no permissions, and no network except Rift's checking proxy. Everything it held is wiped by Android when the session ends. While the page is open, the **live check** lists what it tries: a listed address, your local network, a connection around the proxy, a download, and every device feature it asks for.

**Decoys.** A page that asks for the camera, microphone, screen, location, files, notifications, clipboard, motion sensors or battery is told yes and given something made up: a live video of a dim room, near-silence, a position near a city centre, a generated photo, an empty clipboard. A phishing or spying page carries on as if it had won, and you see what it was after. Nothing real is given: the browser app holds none of those permissions, and the engine still refuses a page that gets past the decoys.

**Files.** Downloads and files shared to Rift go into an encrypted quarantine for the session, are scanned in isolated workers, and images and PDFs are drawn by an isolated worker that has no files and no network. Text is shown as plain text, never run.

**Extra isolation (optional, Shizuku or root).** With [Shizuku](https://shizuku.rikka.app) or Sui running, one switch lets Rift use Android's own tools on its browser: Android ignores the browser's clipboard (so a page cannot swap what you copy), Android itself wipes the browser at each reset, and with root a firewall keeps the browser to Rift's proxy on the phone too, closing the one gap the VPN leaves (other apps' local servers). Each change is checked after it is made, and undone when you switch it off. Copy and paste in Rift's browser stop working while it is on.

**This week.** The home screen counts the threats blocked, dangerous files, warnings and links checked over seven days, kept as numbers only. Nothing else is kept after a session, and nothing asks for a password.

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
| `poc/` | Phase 0 feasibility harnesses (not product code) |
| `crates/` | Rust workspace (Phase 1 onward) |
| `android/` | Android app (Phase 2 onward) |
| `models/` | Rift AI's model file, its report and the notice for its data |
| `tools/` | Maintainer tools: the signed-pack builder and `rift-train` (Rift AI's trainer) |

## License

Dual-licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
