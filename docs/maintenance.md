# Maintaining Rift

What runs by itself, what needs a person, and how to do each by hand. Building and testing are in [development.md](development.md).

## Contents

1. [What runs by itself](#1-what-runs-by-itself)
2. [Repository settings it needs](#2-repository-settings-it-needs)
3. [Releases](#releases)
4. [Rift AI](#rift-ai)
5. [Threat-database packs and keys](#5-threat-database-packs-and-keys)
6. [Dependencies and toolchains](#6-dependencies-and-toolchains)
7. [When something breaks](#7-when-something-breaks)
8. [What still needs a person](#8-what-still-needs-a-person)

## 1. What runs by itself

| Workflow | When | What it does |
|---|---|---|
| `ci.yml` | Every pull request; pushes to `main` that touch code | Lints, tests, fuzzing, the device suite on API 33 and 34 ([development.md](development.md#6-ci)) |
| `release.yml` | Wednesdays 06:41 UTC, or by hand | Builds, signs and publishes the next patch release if the app's code changed since the last tag and CI passed it |
| `retrain.yml` | 1st of the month 03:17 UTC; page collection at 05:41 and 17:41 UTC daily | Retrains Rift AI's address model, page model and brand list; each opens a pull request only if its gate passes |
| `compare.yml` | Tuesdays 06:23 UTC (about 3½ hours) | Measures Check against Google Safe Browsing and URLCheck's hosts check on phishing links newer than Check's lists; the table is in the run's summary ([check-accuracy.md](reports/check-accuracy.md#against-safe-browsing)). Needs the `SAFE_BROWSING_KEY` secret |
| `kev.yml` | Sundays 05:23 UTC | Adds Chromium bugs from CISA's Known Exploited Vulnerabilities catalogue to the WebView refusal list (`KnownExploited.kt`) |
| `toolchains.yml` | 8th of the month 04:29 UTC | Moves stable Rust, the fuzzing nightly, the NDK, cargo-ndk and OSV-Scanner to their latest releases |
| Dependabot | Weekly | Rust, Gradle and Actions updates, at least 7 days old |
| `dependabot-automerge.yml` | On Dependabot's pull requests | Turns on auto-merge, so they merge when the required checks pass |
| `caretaker.yml` | After each CI run; weekly; every 6 hours | Re-runs a failed CI run's failed jobs once; keeps scheduled workflows from being switched off after 60 quiet days; rebases failed bot pull requests onto `main`; approves CI runs GitHub holds on the bots' own branches; closes monthly bot pull requests a newer one replaced |
| `fuzz-campaign.yml` | By hand | Long fuzz runs (default 60 minutes per target), with corpora and coverage uploaded |
| `linux-app.yml`, `linux-qt-poc.yml` | By hand (the PoC also on changes to it) | The Linux app and its proofs of concept; Linux is on hold |

Every bot pull request (retrain, KEV, toolchains, Dependabot) merges itself only when the required CI checks pass, and the next weekly release ships it. Nothing is merged on a failed check.

## 2. Repository settings it needs

- **Branch protection on `main`** requiring the CI checks, so auto-merge waits for them.
- **Actions → "Allow GitHub Actions to create and approve pull requests"**, for the retrain, KEV and toolchain workflows.
- **The `release` environment** (limited to `main`) with the secrets `RIFT_RELEASE_KEYSTORE` (the keystore, base64) and `RIFT_RELEASE_PASSWORD`.
- **`RIFT_SEARCH_TOKEN`** (optional): a token with no permissions, used for GitHub code search when sampling hosting-platform sites for the address model. Without it the model trains without that sample, and the pull request says so.

## Releases

### On the schedule

Each Wednesday `release.yml`:

1. compares `main` with the last `v*` tag, ignoring paths CI ignores (docs and the like); if no code changed, it stops;
2. looks for a successful CI run on the same tree; if there is none, it starts CI on `main` and waits for it;
3. builds the release with `android/release.sh`, with the version taken from the last tag plus one patch (`v0.11.3` → `v0.11.4`);
4. checks the APK carries the release certificate (`RIFT_RELEASE_CERT`, SHA-256 `8b5952…ee8b`);
5. publishes `rift-<version>.apk` and `rift-browser-<version>.apk` with their SHA-256s as the latest release.

Installed copies of Rift find it within a day (or at launch, or with **Check for updates**) and install it after checking the digest and the signature ([architecture §8.11](architecture.md#811-updating-itself-31)). Obtainium finds it too.

### By hand

```sh
gh workflow run release.yml
gh run watch "$(gh run list --workflow release.yml --limit 1 --json databaseId -q '.[0].databaseId')"
```

The same rules apply: nothing is released from a tree CI has not passed.

### The signing key

The APK signing key is in the `release` environment's secrets, and a copy must be kept offline. Every release must be signed with it: Android installs an update only over an app with the same certificate, and Rift installs its browser only if it carries Rift's own. **A lost key means everyone has to uninstall Rift to install a build signed with another**; a leaked key lets its holder ship code to every install. See [key-policy.md](reports/key-policy.md#the-apk-signing-key).

## Rift AI

`retrain.yml` keeps three things current. Each has a gate that compares the new result with the shipped one; only a result that passes is proposed, as a pull request that merges itself when CI passes. Downloaded feeds and pages stay on the runner and are never committed.

| Job | When | Script | Gate | Output |
|---|---|---|---|---|
| `retrain` (address model) | Monthly | `tools/rift-train/retrain.sh` | `gate.py`: no more false alarms, no lower AUC, no slower scoring, against the shipped model and the hand-checked baseline (`baseline.json`) | `models/url-model.bin`, `.json` |
| `collect-pages` | Twice daily | `retrain_pages.sh collect` | none; it only adds to the memory | the `rift-page-memory` artifact |
| `pages` (page model) | Monthly | `retrain_pages.sh train` | `rift-train page train --champion` against the shipped model | `models/page-model.txt` |
| `brands` | Monthly | `retrain_brands.sh` | `rift-train brands`: no more warnings on ordinary addresses than the shipped list (by 0.05 points or 0.5%) | `models/brands.txt` |

### Memory

The models learn from more than one month's data:

- **`rift-ai-memory`** keeps each month's phishing addresses for 24 months (`memory.py`); the address model trains on it too.
- **`rift-page-memory`** keeps counts of fetched pages (never the pages themselves) for 24 months, up to 300,000 (`page_memory.py`).

Both are workflow artifacts that each run takes from the last one (`take_memory.sh`) and hands on, whether or not its model passes. Artifacts last 90 days, so if no run succeeds for three months, a memory starts again.

### Running by hand

From the repository root, with work directories **outside** the repository:

```sh
gh workflow run retrain.yml -f models=all        # or address, pages, brands, collect

sh tools/rift-train/retrain.sh <download-dir> <prepared-dir>
sh tools/rift-train/retrain_pages.sh collect <work-dir> <memory.tsv>
sh tools/rift-train/retrain_pages.sh train <work-dir> <memory.tsv>
sh tools/rift-train/retrain_brands.sh <work-dir> /usr/share/dict/words

gh workflow run compare.yml -f wait=180          # the Safe Browsing comparison
sh tools/rift-train/compare.sh lists <work-dir>  # then, hours later:
SAFE_BROWSING_KEY=... sh tools/rift-train/compare.sh run <work-dir>
```

These download hundreds of megabytes of feeds and datasets; prefer the workflow on a metered connection. Exit status 2 means the gate refused the result: the shipped model stays.

Results and history: [rift-ai.md](reports/rift-ai.md), [page-model.md](reports/page-model.md), [check-accuracy.md](reports/check-accuracy.md).

## 5. Threat-database packs and keys

The threat database is a pack signed as a TUF repository and verified by `rift-update` before it is installed.

```sh
cargo run -p rift-pack -- keys <key-dir>                 # development: one key per role, 1-of-1
cargo run -p rift-pack -- demo <pack-dir>                # the harmless demo pack
sh tools/rift-pack/feeds.sh <work-dir> <version>         # a pack from today's public feeds
```

Debug builds trust the demo keys that `android/build.sh` makes. Release builds trust only a production root, which does not exist yet: it is made at the **signing-key ceremony** (`tools/rift-pack/ceremony.sh`, [key-ceremony.md](reports/key-ceremony.md)), with a 2-of-3 root, offline targets keys and root rotation ([key-policy.md](reports/key-policy.md)). Until then, release builds say they cannot install database updates. After it, a build is given the root with `RIFT_INTEL_ROOT` and the update address with `RIFT_INTEL_URL`, both read by `android/build.sh`.

`rift-pack` lists all its commands when run without arguments (`root-draft`, `root-sign`, `targets-draft`, `targets-sign`, `publish-signed` and others).

The threat lists Check uses (HaGeZi, Phishing Army, uBlock Origin badware, StevenBlack) and the filter lists are fetched by the app from their own maintainers; they are not part of the pack.

## 6. Dependencies and toolchains

- **Rust, Gradle and Actions** dependencies: Dependabot, weekly, versions at least 7 days old. Actions are pinned by commit SHA.
- **Toolchains** Dependabot does not see: `toolchains.yml` updates `rust-toolchain.toml` and `.github/toolchains.env`. If a new compiler's lints fail CI, the pull request stays open and nothing moves.
- **Licences and advisories**: `cargo deny check` (`deny.toml`) and OSV-Scanner on every CI run. The inventory is in [dependencies.md](reports/dependencies.md).
- **Third-party notices** in both apps are generated at build time (`android/notices.gradle.kts`).

## 7. When something breaks

| Symptom | Where to look |
|---|---|
| A bot pull request stays open | Its CI run. Caretaker re-runs a failure once and rebases a stale one weekly; a real failure needs a fix on `main` |
| No release this week | The `release` run: either no code changed since the last tag, or CI failed on `main` |
| A retrain opened no pull request | The run's summary: "refused" means the gate kept the shipped model, which is normal |
| `collect-pages` fails | Usually a feed or Common Crawl being down; `cc_index.py` retries and fails the run if more than 5% of blocks fail. The memory is never restarted by a failed run |
| `kev.yml` fails | A new bug with no fixed version in NVD yet; it fails rather than leaving it out. Re-run later |
| A scheduled workflow stopped | GitHub switches them off after 60 quiet days; caretaker turns them back on weekly, or turn it on under Actions |

## 8. What still needs a person

From [TODO.md](../TODO.md):

- Hold the signing-key ceremony and put the production root in the release build.
- Set up an update host (any static HTTPS host) for threat-database packs.
- An external security review ([review-brief.md](reports/review-brief.md)).
- Run the device suite on physical phones from several makers.
