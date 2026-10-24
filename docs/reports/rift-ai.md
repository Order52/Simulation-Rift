# Rift AI: the URL model

**Model:** `models/url-model.bin`, SHA-256 `d6c2bc607dfdc4d7f0d4e6117e0d1e751629c8c9025a11d0fe66f67454348e04`, 1,802,976 bytes, feature schema 1, with a factor table (below)
**Trained:** 24 October 2026 by `tools/rift-train` (deterministic: the same data and arguments give the same file), on feeds fetched 21–24 October 2026, without URLhaus (below). Phishing.Database's links are of two ages: its single `phishing-links-ACTIVE.txt` stopped changing on 22 December 2025, and the live list has since been published as split files (`phishing-links-ACTIVE/`, last updated 2 October 2026 when fetched). The model of 21 October learned from the December 2025 file only, which its report wrongly called "fetched that day"; this one learns from both.
**Full numbers:** `models/url-model.json` (written by the trainer, alongside the model)
**Architecture:** §16

Rift AI looks at a web address, nothing else, and says how closely it resembles the phishing and malware addresses it learned from. It runs on the device, in about 2 µs per address, and sends nothing anywhere. Its answer is advisory: it adds a warning before a page loads, or a note, and never blocks, never overrides the threat database, and never calls anything safe.

## What it learned from

| Source | What | Used as | Licence | Examples kept |
|---|---|---|---|---|
| [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database), ACTIVE links, `phishing-links-ACTIVE.txt` (frozen 22 Dec 2025) | Phishing URLs, checked as still live | malicious | MIT | 553,528 |
| Phishing.Database, ACTIVE links, `phishing-links-ACTIVE/` split files (2 Oct 2026) | The same, current | malicious | MIT | 47,130 |
| ~~[URLhaus](https://urlhaus.abuse.ch/)~~, through [malware-filter's urlhaus-filter](https://gitlab.com/malware-filter/urlhaus-filter) | Hosts serving malware | **not used since 24 Oct 2026** | abuse.ch terms (below) | 0 (18,548 before) |
| [PhiUSIIL](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) (UCI), label 0 | Phishing URLs | malicious | CC BY 4.0 | 69,437 |
| [Common Crawl](https://commoncrawl.org/) CC-MAIN-2026-39, 1,000 random index blocks | Ordinary pages that answered 200 with HTML | benign | Terms of use | 361,015 |
| Common Crawl, one block per site of the 3,000 most visited | Real sign-in, mail and file pages of large sites | benign | Terms of use | 24,929 |
| Common Crawl, up to 8 blocks per hosting platform (35 platforms: github.io, vercel.app, workers.dev, web.app, netlify.app…) | Ordinary sites on the platforms phishing also uses | benign | Terms of use | 36,011 |
| GitHub code search: links in public `README.md` files to pages.dev, web.app and firebaseapp.com sites (`gh_platforms.py`), at most 2 per site; sites any feed lists, and names with a brand or sign-in word (a "clone" project's), left out | Projects' own demo, documentation and blog sites, on the platforms Common Crawl barely covers | benign | links only (facts), from public files | 10,274 |
| [Tranco](https://tranco-list.eu/) top 1M | Site names, most visited first | benign, hosts (first 200,000) | cited as requested | 200,000 |
| PhiUSIIL, label 1 | Legitimate URLs (names only, no paths) | benign | CC BY 4.0 | 134,765 |
| [Public Suffix List](https://publicsuffix.org/), both sections | Where a site's name begins | site boundaries | MPL-2.0 | 10,396 rules |

The URLs themselves are never committed: they are real malicious addresses (§21). `prepare.py` turns the downloads into one-entry-per-line files; nothing in them is opened or fetched. The app's licences screen carries the notices (`models/url-model-notice.txt`).

**Not URLhaus, since 24 October 2026.** The mirror says CC0, but the data is abuse.ch's, and [abuse.ch's terms](https://abuse.ch/terms-of-use/) (effective 4 Nov 2025, updated 21 Oct 2026) say in s. 7.3 that its data "may not be used by users to customise, train, or otherwise improve any artificial intelligence model or product" without Spamhaus's written consent, and forbid derived works. Earlier models (to 22 October) were trained on it; this one is not. Leaving it out cost nothing measurable: on 622 URLhaus hosts this model never saw, it rates 90.8% High, against 91.2% for a model trained on them (bare IP addresses and the words malware paths use carry over from the phishing feeds). URLhaus can come back with written consent.

**Not VirusTotal.** VirusTotal's terms do not allow building a product's detection on its verdicts, its API needs a key that would have to ship in the app, and every lookup would send the user's link to a third party. Rift sends no link anywhere (§17).

## How it works

- **Features** (`rift_core::urlmodel::for_each_feature`, shared by the trainer and the app, so they cannot disagree): character 3- to 5-grams of the host, its labels, words and shape, the top-level domain and last two labels, how random the name looks, the scheme, the path's words, word pairs, opening characters, extension and shape, query keys, and an address embedded in the address. They are hashed into 2^19 signed buckets.
- **Model:** a factorization machine: logistic regression over the hashed features, plus a learned 4-number vector for each feature (folded into 2^16 rows), so that every pair of features in an address adds the dot product of their vectors to the score. Pairs let it weigh words that mean more together (`metamask` in a `pages.dev` name, `login` after a bare IP address) without listing pairs by hand; the score is still one sum, computed in O(features × 4). Trained by AdaGrad, with the two classes weighted equally. Weights and factors are stored as 16-bit integers with one scale each (1 MiB + 0.5 MiB). When pairs raise a score past Low, the reasons include "how the parts of the address go together".
- **Why the factors.** Tried against the linear model on the same data, seeds and selection: on never-seen sites, validation recall at 0.1% false positives 61.96% against 61.01%, test 61.86% against 60.34%, a second seed 63.09% against 61.69%; on the time-separated test (below) 49.4% against 47.8% High. False alarms did not change. Factor L2 matters: 0.01 or none overfits (validation recall falls below the linear model's); 0.1 is used. 8 factors, or 2^18 rows, did no better and broke the 2 MiB limit.
- **Chosen on the validation sites, not by hand.** The trainer tries five L2 strengths (0 to 0.01) for up to six passes each and keeps the setting with the best validation recall at a 0.1% false-positive rate (ties to the lower validation loss); the test sites take no part. Passes are what matter: validation loss is lowest after two or three and then rises as the model starts to memorise the sites it trained on, so more passes overfit. Penalties strong enough to change anything (0.001 and up) only lowered validation recall, so the linear model is not over-fitted by its weights but limited by what an address shows. This model: no penalty, 1 pass (factors with L2 0.1). Every setting tried is in `url-model.json` under `selection`.
- **Two views:** the whole address (Check, and navigations), and the host alone, which is all the live watch's proxy sees of an HTTPS request.
- **Sites** are what the Public Suffix List says, private section included. So `someone.workers.dev` is a site of its own, and so is `bbc.co.uk`. The rules ship inside the model.
- **The 10,000 most visited sites are not scored.** Their real sign-in pages and the fakes hosted on them (Google Forms, Drive, Docs) have the same kind of address, and an earlier model rated `mail.google.com` and `login.microsoftonline.com` as high risk. For those sites the check says "not scored", and the threat database still checks every page. The model carries 64-bit hashes of these sites, not their names.
- **Hosting platforms are balanced.** The feeds list about 25,000 fakes on workers.dev alone, and before platforms were balanced every github.io or vercel.app site scored high, whatever it was. Training now takes at most 2,500 malicious pages per platform, as many as the ordinary pages sampled from it. Validation and test keep every page.
- **Thresholds** come from the validation split: High at a 0.1% and Elevated at a 1% false-positive rate, averaged over the benign sources (each kind of page counts the same). A source with fewer than 2,000 scored pages does not set them. High is 0.977 and Elevated 0.807. The 0–99 score shown is banded so that Elevated starts at 50 and High at 90.

## How well it does

Every source is split **by site** (80% train, 10% validation, 10% test), so the test measures sites the model has never seen. That is the honest number for a new phishing site. "Seen" is a site in the training split: most links in a feed on any one day are on sites that were in the feed before.

**Whole address (Check, navigation), test split: sites never seen**

| Source | Pages | High | Elevated or High | Not scored |
|---|---:|---:|---:|---:|
| Source | Pages | High | Elevated or High | Not scored | 22 Oct model, High |
|---|---:|---:|---:|---:|---:|
| Phishing.Database, December 2025 | 62,889 | 57.9% | 82.3% | 0% | 56.2% |
| Phishing.Database, October 2026 | 5,055 | 60.3% | 82.4% | 0% | 58.8% |
| PhiUSIIL phishing | 7,441 | 24.3% | 44.1% | 0% | 21.9% |
| Common Crawl, ordinary pages (falsely flagged) | 36,045 | 0.08% | 0.89% | 0.36% | 0.07% |
| Common Crawl, hosting platforms (falsely flagged) | 3,506 | 0.03% | 2.91% | 0% | 0.03% |
| GitHub READMEs' pages.dev, web.app and firebaseapp.com sites (falsely flagged) | 1,076 | 0.09% | 4.55% | 0% | 0.09% |
| Common Crawl, most visited sites (falsely flagged) | 2,280 | 0% | 0.75% | 91% | 0% |
| Tranco names (falsely flagged) | 19,973 | 0.02% | 0.42% | 4.7% | 0.02% |
| PhiUSIIL legitimate (falsely flagged) | 13,397 | 0% | 0.19% | 1.5% | 0% |

URLhaus hosts, never trained on (622 of a random 2,000 that are plain hosts or addresses): 90.8% High, 92.1% flagged.

**Sites seen in training:** Phishing.Database 72.1% High, 90.6% flagged (October 2026: 68.6% / 89.1%); ordinary pages 0.01% / 0.11%.

**Host only (the live watch, for HTTPS requests), never seen:** Phishing.Database 21.5% High, 46.9% flagged (October 2026: 36.0% / 64.7%; many fakes are only recognisable by their path); ordinary hosts 0.00% / 0.73%; hosting platforms 0.11% / 1.61%.

AUC on the test split of the trained sources: 0.9803 (22 October model: 0.9772).

**Fit (over- and underfitting).** Trained sources, whole address, scored pages, at the shipped High threshold:

| Split | Pages | Log loss | Malicious at High | Benign at High |
|---|---:|---:|---:|---:|
| Train (sites it learned) | 1,102,775 | 0.116 | 67.8% | 0.013% |
| Validation (chose the setting and thresholds) | 148,260 | 0.186 | 55.2% | 0.045% |
| Test (never used until here) | 148,322 | 0.189 | 54.7% | 0.049% |

Validation and test agree closely, so the choices made on validation hold on new sites. The gap from train is the model recognising sites it has seen, which is what it should do with a link on a site already in a feed; it is why the honest number is the test's.

**Time-separated test.** Phishing changes, so a site split can flatter a model. A model trained the same way on the December 2025 file only (the configuration that shipped on 21 October) was tested on the October 2026 links, ten months later:

| Training | October 2026 links on sites not in the December file (32,154) | All October 2026 links not in the December file (15,828) |
|---|---:|---:|
| Shipped 21 Oct (4 passes, fixed) | 48.0% High, 69.7% flagged | 74.8% / 91.7% |
| Chosen on validation (3 passes) | 48.0% / 70.9% | 78.0% / 92.5% |
| Chosen on validation, with the GitHub platform sites | 46.9% / 69.7% | 77.5% / 92.4% |
| The same data on 24 Oct, linear (3 passes) | 47.8% / 69.3% (host only 28.4%) | |
| The same data on 24 Oct, with factors (2 passes) | **49.4% / 71.0%** (host only 29.6%) | |

Ten months on, a model without the new links catches about half the fakes on new sites at High, against 57% on the site split: drift costs about 9 points, which is why this model trains on the October 2026 links too, and why the model must be retrained as the feeds change. The GitHub platform sites cost about a point here and lower false alarms on hosting platforms (High 0.11% against 0.14% on the same data without them; 0.03% for this model); they are kept because a false alarm on an ordinary pages.dev or web.app site was the most visible mistake of the 21 October model (below). The heuristics alone (§10.3) warn on 0.003% of the never-seen Phishing.Database pages and 0.03% of PhiUSIIL's: they look for specific tricks (a lookalike of a protected brand, an `@` in the address), not for resemblance.

**Speed:** p50 2.1 µs, p95 4.7 µs per address on the training machine, idle (the factors add about 0.2 µs; 3.3 / 7.6 µs measured while a fuzz campaign used four cores). On the Android emulator, a whole check (navigation policy, threat database, Rift AI) takes p50 19 µs and p95 64 µs (v1).

**Addresses checked by hand** (made up for the probe, so none in the training data):

| Address | 21 Oct model | 22 Oct model | This model |
|---|---|---|---|
| `https://accounts.google.com/signin`, `github.com/login`, `www.paypal.com/signin`, `www.amazon.co.uk/gp/cart`, `online.chase.com` | not scored (most visited) | not scored | not scored |
| `https://my-portfolio.pages.dev/` | **High (95)** | Low (4) | Low (5) |
| `https://todo-app-3f2a1.web.app/` | Elevated (86) | Low (17) | Low (23) |
| `https://www.uotechnology.edu.iq/` | Low (8) | Low (8) | Low (9) |
| `https://paypa1.com/login` | Elevated (85) | Elevated (85) | Elevated (86) |
| `https://secure-login-paypal.verify-account.xyz/webscr` | High (99) | High (99) | High (98) |
| `https://appleid-verify-account.web.app/`, `metamask-wallet-restore.pages.dev/`, `microsoft-office365-login.firebaseapp.com/index.html` | High (98) | High (96–97) | High (97–98; metamask's reasons include "how the parts of the address go together") |
| `https://usps-redelivery-track.com/track`, `netflix-billing-update.com/account`, `free-iphone-giveaway.top/claim` | High (98) | High (97–98) | High (97–98) |
| `http://192.168.1.1/login`, `http://45.133.1.20/bins/mips` | High (98) | High (98) | High (97–98) |

`crates/rift-ffi/src/ai.rs` tests the shipped file on addresses like these: the most visited sites are not scored, the fakes are High (now including fakes on pages.dev and web.app), and the ordinary platform sites are Low (now including pages.dev and web.app).

## Limits

- **It judges the address, not the page.** A phishing page at an ordinary-looking address on a site it has not seen is missed: about 1 in 5 of the never-seen Phishing.Database pages are not even Elevated. That is why it never says "safe".
- **Look-alike-free phishing is hard.** PhiUSIIL's phishing set is mostly bare names that look like any small business; the model catches 21.9% of it at High.
- **Real login pages of small sites** can be Elevated, and sometimes High (webmail and sign-in pages share words with the fakes). High asks before loading; it never blocks.
- **pages.dev and web.app**: Common Crawl's index had almost no ordinary pages on pages.dev (43 entries, none an HTML page) and few on web.app, so ordinary sites there are learned from GitHub READMEs' links, about 10,000 sites: projects' own sites, not a random sample of the platforms. About 3% of them are still Elevated.
- **Not scored on the 10,000 most visited sites**, including fakes hosted on them; those are for the threat database.
- **Time:** ten months of drift cost about 9 points of High on new sites (above). The model does not update itself; it needs retraining as the feeds change.
- **Malware hosts are not learned directly** since URLhaus left the training data; they are caught by resemblance (90.8% of a URLhaus sample at High), and the threat database is what lists them.
- **No comparison with Google Safe Browsing**: that needs its API, which Rift does not use offline.

## Learning from new data

The model learns when it is retrained on fresh feeds. It does not learn on the device and never from what the user opens (§16). A new model reaches devices two ways: in the next app release, or **inside a signed threat-database pack** (`url-model.bin`, optional in a pack, §13.1): while that pack is installed, the app uses its model in place of the one it ships, and the protection details say which one is on. A pack's model is checked like the shipped one (`UrlModel::parse`), and a pack whose model does not parse is refused whole.

**Retraining** is one script, `tools/rift-train/retrain.sh <download-dir> <prepared-dir>` (both outside the repository): it downloads every source above (the newest Common Crawl collection, Phishing.Database's live split files), prepares them, samples the platforms (GitHub's needs a signed-in `gh`), and trains with the settings above into `models/`. `tools/rift-train/gate.py <old report> <new report>` then refuses a model that rates more than 0.2% of any ordinary source High, loses more than 0.005 AUC or 3 points of never-seen Phishing.Database at High, or scores slower than 5 µs p50. The `retrain rift ai` workflow (`.github/workflows/retrain.yml`) does both on the 1st of every month and opens a pull request with the model and the gate's summary; nothing ships until a maintainer merges it, checks addresses (`cargo run -q --release -p rift-ffi --example ai_probe -- <addresses>`, `RIFT_MODEL=<file>` for another model), and updates this report and `url-model-notice.txt`. `cargo test -p rift-ffi ai::` must still pass.

A time-separated test: train without the newest feed and add it as `--source <name>:malicious:urls:<file>:eval` (`new_sites.py` keeps the links on sites the older feed never had).
