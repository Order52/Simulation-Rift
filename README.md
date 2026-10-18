# Simulation-Rift

A fully local, modular workspace for Android and Linux. It lets you open unfamiliar links, download and inspect untrusted files, and keep the files you choose in encrypted storage, while reducing your device's exposure to that content.

> **Status: early development (Phase 3, scanner and signed updates; tested on Android emulators, not yet on a phone).** Nothing here is a usable or audited security product yet. [`STATUS.md`](STATUS.md) is the current status: what works, what is left and the limitations. Read [`docs/architecture.md`](docs/architecture.md) for the design; the evidence reports in [`docs/reports/`](docs/reports/) state what has actually been verified.

## What it is

- **Rift Browser:** a disposable, restricted browser session. It uses the platform engine's own sandbox and has no native bridges, sensor access, or automatic external-app launches.
- **Rift Files:** downloads and imports go into an encrypted, session-scoped quarantine. PDFs and images are previewed in OS-confined worker processes with no file or network access; text is shown as escaped plain text, never interpreted.
- **Rift Scanner:** offline checks using URL and hash indicators, explainable URL heuristics, and YARA-X rules. Results state their coverage. There is never a "100% safe" label.
- **Rift Vault:** persistent [age](https://age-encryption.org)-encrypted storage, unlocked through the Android Keystore or a passphrase.
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

## License

Dual-licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
