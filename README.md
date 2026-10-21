# Simulation-Rift

A fully local, modular workspace for Android and Linux. It lets you open unfamiliar links and view untrusted files safely, keeping nothing afterwards, while reducing your device's exposure to that content. Android comes first; the Linux app is future work.

> **Status: early development (Phase 3, scanner and signed updates; tested on Android emulators, not yet on a phone).** Nothing here is a usable or audited security product yet. [`STATUS.md`](STATUS.md) is the current status: what works, what is left and the limitations. Read [`docs/architecture.md`](docs/architecture.md) for the design; the evidence reports in [`docs/reports/`](docs/reports/) state what has actually been verified.

## What it is

- **Rift Browser:** a disposable, restricted browser session. It uses the platform engine's own sandbox and has no native bridges, sensor access, or automatic external-app launches.
- **Rift Files:** downloads and imports go into an encrypted, session-scoped quarantine. PDFs and images are previewed in OS-confined worker processes with no file or network access; text is shown as escaped plain text, never interpreted.
- **Rift Scanner:** offline checks using URL and hash indicators, explainable URL heuristics, and YARA-X rules. Results state their coverage. There is never a "100% safe" label.
- **Check a link, or open it:** Check judges a link without opening it: the threat database, the navigation policy, and **Rift AI**, a model of phishing and malware addresses trained on public feeds that runs on the device in microseconds and sends nothing anywhere. It gives a score and its reasons, and it is advisory: it asks before opening a link it rates high risk and never calls anything safe ([how well it does](docs/reports/rift-ai.md)).
- **This week:** the home screen counts what Rift blocked and checked over seven days, stored as numbers only.
- **Signed intelligence updates:** delivered through [TUF](https://theupdateframework.io/). They can be fetched or imported offline.

## What it is not

- It is not an antivirus, a VM, or a malware detonation lab.
- It never executes downloaded programs.
- It sends no content to a cloud service.
- It does not claim perfect isolation. Each security claim names its boundary and the test that demonstrates it.

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
