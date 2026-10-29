# Rift documentation

Start with the guide for what you want to do. Every security claim in these documents means "tested in the stated environment": each names its boundary and the test that shows it.

## Guides

| Guide | For |
|---|---|
| [User guide](user-guide.md) | Installing Rift and using every screen: Check, the sealed browser, files, filters, updates, troubleshooting |
| [Developing Rift](development.md) | Setting up, the code map, building, testing, CI, the rules for changes |
| [Listing Rift in app stores](distribution.md) | IzzyOnDroid and F-Droid: what is ready, how to submit, what F-Droid still needs |
| [Maintaining Rift](maintenance.md) | Releases, signing keys, Rift AI's retraining, the automated workflows, what to do when one fails |

## Reference

| Document | What it covers |
|---|---|
| [architecture.md](architecture.md) | The spec: threat model (§3), trust boundaries (§4), invariants INV-1…INV-14 (§5), Android design (§8), the browser (§10), files (§11), scanning (§12), signed updates (§13), sessions (§15), Rift AI (§16), privacy (§17), acceptance tests (§23), residual risks (§24) |
| [STATUS.md](../STATUS.md) | What works now, how it was tested, and its limits |
| [TODO.md](../TODO.md) | Planned work, including what needs a person and the Linux version |
| [SECURITY.md](../SECURITY.md) | How to report a vulnerability |

## Reports

Evidence for each claim, in the sections **Verified**, **Unverified** and **Could be improved**. Raw outputs from test runs are in [reports/evidence/](reports/evidence/).

**Releases**

| Report | Covers |
|---|---|
| [release-3-3.md](reports/release-3-3.md) | Rift AI retrained weekly with a forward test; the page model reads words and adds boosted trees |
| [release-3-2.md](reports/release-3-2.md) | A relay for the user's address, fingerprinting named, fixed page rules, held list updates, a store build, Safe Browsing comparison, Pages host |
| [release-3-1.md](reports/release-3-1.md) | Rift updates itself (with a check at launch), a dark theme, Rift AI keeps a memory |
| [release-3-0.md](reports/release-3-0.md) | Rift AI reads the page, trackers explained, old WebViews refused |
| [release-2-9.md](reports/release-2-9.md) | Threat lists in Check, an optional history |
| [release-2-8.md](reports/release-2-8.md) | Skip sign-ins and pop-ups, lists that keep themselves up to date |
| [release-2-7.md](reports/release-2-7.md) | Rift AI with factors and in packs, real feeds, a phone |
| [browser-2-6.md](reports/browser-2-6.md) | Opening listed links, Test-open, page checks |
| [browser-isolation.md](reports/browser-isolation.md) | The browser in its own app behind a network lock (2.1) |

**Rift AI and Check**

| Report | Covers |
|---|---|
| [rift-ai.md](reports/rift-ai.md) | The address model: data, results, retraining |
| [page-model.md](reports/page-model.md) | The page model: data, results, learning from new pages |
| [check-accuracy.md](reports/check-accuracy.md) | How well Check finds phishing, compared with URLCheck |

**Keys, dependencies, review**

| Report | Covers |
|---|---|
| [key-policy.md](reports/key-policy.md) | Signing keys: policy and response plan, including the APK key |
| [key-ceremony.md](reports/key-ceremony.md) | The production-key ceremony, step by step |
| [dependencies.md](reports/dependencies.md) | Dependency and licence inventory |
| [review-brief.md](reports/review-brief.md) | Brief for an external security review |

**Phases**

[Project status and history](reports/project-status.md) · [Phase 0](reports/phase-0.md) (feasibility) · [Phase 1](reports/phase-1.md) (foundations) · [Phase 2](reports/phase-2.md) (Android slice) · [Phase 3](reports/phase-3.md) (scanner and signed intelligence) · [Phase 4](reports/phase-4.md) (the vault, since removed) · [Phase 5](reports/phase-5-qt-design.md) (Linux on Qt) · [Phase 7](reports/phase-7.md) (hardening)
