# Rift AI: the URL model

**Model:** `models/url-model.bin`, SHA-256 `2b92d427004b212625ecf1b16c78371bd43bf966072d884f3906e4892b531594`, 1,278,656 bytes, feature schema 1
**Trained:** 22 October 2026 by `tools/rift-train` (deterministic: the same data and arguments give the same file), on feeds fetched 21–22 October 2026. Phishing.Database's links are of two ages: its single `phishing-links-ACTIVE.txt` stopped changing on 22 December 2025, and the live list has since been published as split files (`phishing-links-ACTIVE/`, last updated 2 October 2026 when fetched). The model of 21 October learned from the December 2025 file only, which its report wrongly called "fetched that day"; this one learns from both.
**Full numbers:** `models/url-model.json` (written by the trainer, alongside the model)
**Architecture:** §16

Rift AI looks at a web address, nothing else, and says how closely it resembles the phishing and malware addresses it learned from. It runs on the device, in about 2 µs per address, and sends nothing anywhere. Its answer is advisory: it adds a warning before a page loads, or a note, and never blocks, never overrides the threat database, and never calls anything safe.

## What it learned from

| Source | What | Used as | Licence | Examples kept |
|---|---|---|---|---|
| [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database), ACTIVE links, `phishing-links-ACTIVE.txt` (frozen 22 Dec 2025) | Phishing URLs, checked as still live | malicious | MIT | 553,528 |
| Phishing.Database, ACTIVE links, `phishing-links-ACTIVE/` split files (2 Oct 2026) | The same, current | malicious | MIT | 47,130 |
| [URLhaus](https://urlhaus.abuse.ch/), through [malware-filter's urlhaus-filter](https://gitlab.com/malware-filter/urlhaus-filter) (the official download now returns 410) | Hosts serving malware | malicious, hosts | CC0 (the mirror) | 18,548 |
| [PhiUSIIL](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) (UCI), label 0 | Phishing URLs | malicious | CC BY 4.0 | 69,437 |
| [Common Crawl](https://commoncrawl.org/) CC-MAIN-2026-39, 1,000 random index blocks | Ordinary pages that answered 200 with HTML | benign | Terms of use | 361,015 |
| Common Crawl, one block per site of the 3,000 most visited | Real sign-in, mail and file pages of large sites | benign | Terms of use | 24,929 |
| Common Crawl, up to 8 blocks per hosting platform (35 platforms: github.io, vercel.app, workers.dev, web.app, netlify.app…) | Ordinary sites on the platforms phishing also uses | benign | Terms of use | 36,011 |
| GitHub code search: links in public `README.md` files to pages.dev, web.app and firebaseapp.com sites (`gh_platforms.py`), at most 2 per site; sites any feed lists, and names with a brand or sign-in word (a "clone" project's), left out | Projects' own demo, documentation and blog sites, on the platforms Common Crawl barely covers | benign | links only (facts), from public files | 10,274 |
| [Tranco](https://tranco-list.eu/) top 1M | Site names, most visited first | benign, hosts (first 200,000) | cited as requested | 200,000 |
| PhiUSIIL, label 1 | Legitimate URLs (names only, no paths) | benign | CC BY 4.0 | 134,765 |
| [Public Suffix List](https://publicsuffix.org/), both sections | Where a site's name begins | site boundaries | MPL-2.0 | 10,396 rules |

The URLs themselves are never committed: they are real malicious addresses (§21). `prepare.py` turns the downloads into one-entry-per-line files; nothing in them is opened or fetched. The app's licences screen carries the notices (`models/url-model-notice.txt`).

**Not VirusTotal.** VirusTotal's terms do not allow building a product's detection on its verdicts, its API needs a key that would have to ship in the app, and every lookup would send the user's link to a third party. Rift sends no link anywhere (§17).

## How it works

- **Features** (`rift_core::urlmodel::for_each_feature`, shared by the trainer and the app, so they cannot disagree): character 3- to 5-grams of the host, its labels, words and shape, the top-level domain and last two labels, how random the name looks, the scheme, the path's words, word pairs, opening characters, extension and shape, query keys, and an address embedded in the address. They are hashed into 2^19 signed buckets.
- **Model:** logistic regression trained by AdaGrad, with the two classes weighted equally. Weights are stored as 16-bit integers with one scale (1 MiB).
- **Chosen on the validation sites, not by hand.** The trainer tries five L2 strengths (0 to 0.01) for up to six passes each and keeps the setting with the best validation recall at a 0.1% false-positive rate (ties to the lower validation loss); the test sites take no part. Passes are what matter: validation loss is lowest after two or three and then rises as the model starts to memorise the sites it trained on, so more passes overfit. Penalties strong enough to change anything (0.001 and up) only lowered validation recall, so the linear model is not over-fitted by its weights but limited by what an address shows. This model: no penalty, 2 passes. Every setting tried is in `url-model.json` under `selection`.
- **Two views:** the whole address (Check, and navigations), and the host alone, which is all the live watch's proxy sees of an HTTPS request.
- **Sites** are what the Public Suffix List says, private section included. So `someone.workers.dev` is a site of its own, and so is `bbc.co.uk`. The rules ship inside the model.
- **The 10,000 most visited sites are not scored.** Their real sign-in pages and the fakes hosted on them (Google Forms, Drive, Docs) have the same kind of address, and an earlier model rated `mail.google.com` and `login.microsoftonline.com` as high risk. For those sites the check says "not scored", and the threat database still checks every page. The model carries 64-bit hashes of these sites, not their names.
- **Hosting platforms are balanced.** The feeds list about 25,000 fakes on workers.dev alone, and before platforms were balanced every github.io or vercel.app site scored high, whatever it was. Training now takes at most 2,500 malicious pages per platform, as many as the ordinary pages sampled from it. Validation and test keep every page.
- **Thresholds** come from the validation split: High at a 0.1% and Elevated at a 1% false-positive rate, averaged over the benign sources (each kind of page counts the same). A source with fewer than 2,000 scored pages does not set them. High is 0.986 and Elevated 0.844. The 0–99 score shown is banded so that Elevated starts at 50 and High at 90.

## How well it does

Every source is split **by site** (80% train, 10% validation, 10% test), so the test measures sites the model has never seen. That is the honest number for a new phishing site. "Seen" is a site in the training split: most links in a feed on any one day are on sites that were in the feed before.

**Whole address (Check, navigation), test split: sites never seen**

| Source | Pages | High | Elevated or High | Not scored |
|---|---:|---:|---:|---:|
| Phishing.Database, December 2025 | 62,911 | 56.2% | 81.7% | 0% |
| Phishing.Database, October 2026 | 5,055 | 58.8% | 81.5% | 0% |
| URLhaus hosts | 1,697 | 89.8% | 91.6% | 0% |
| PhiUSIIL phishing | 7,454 | 21.9% | 41.8% | 0% |
| Common Crawl, ordinary pages (falsely flagged) | 36,045 | 0.07% | 0.75% | 0.36% |
| Common Crawl, hosting platforms (falsely flagged) | 3,506 | 0.03% | 3.17% | 0% |
| GitHub READMEs' pages.dev, web.app and firebaseapp.com sites (falsely flagged) | 1,076 | 0.09% | 3.16% | 0% |
| Common Crawl, most visited sites (falsely flagged) | 2,280 | 0% | 0.61% | 91% |
| Tranco names (falsely flagged) | 19,973 | 0.02% | 0.40% | 4.7% |
| PhiUSIIL legitimate (falsely flagged) | 13,397 | 0% | 0.25% | 1.5% |

**Sites seen in training:** Phishing.Database 70.8% High, 90.4% flagged (October 2026: 67.4% / 88.5%); URLhaus 90.5% / 93.0%; ordinary pages 0.01% / 0.07%.

**Host only (the live watch, for HTTPS requests), never seen:** Phishing.Database 20.4% High, 46.3% flagged (October 2026: 35.4% / 63.9%; many fakes are only recognisable by their path); URLhaus 89.8% / 91.1%; ordinary hosts 0.00% / 0.59%; hosting platforms 0.00% / 2.07%.

AUC on the test split of the trained sources: 0.9772.

**Fit (over- and underfitting).** Trained sources, whole address, scored pages, at the shipped High threshold:

| Split | Pages | Log loss | Malicious at High | Benign at High |
|---|---:|---:|---:|---:|
| Train (sites it learned) | 1,117,651 | 0.111 | 67.0% | 0.008% |
| Validation (chose the setting and thresholds) | 150,022 | 0.193 | 54.2% | 0.038% |
| Test (never used until here) | 150,052 | 0.195 | 53.8% | 0.041% |

Validation and test agree closely, so the choices made on validation hold on new sites. The gap from train is the model recognising sites it has seen, which is what it should do with a link on a site already in a feed; it is why the honest number is the test's.

**Time-separated test.** Phishing changes, so a site split can flatter a model. A model trained the same way on the December 2025 file only (the configuration that shipped on 21 October) was tested on the October 2026 links, ten months later:

| Training | October 2026 links on sites not in the December file (32,154) | All October 2026 links not in the December file (15,828) |
|---|---:|---:|
| Shipped 21 Oct (4 passes, fixed) | 48.0% High, 69.7% flagged | 74.8% / 91.7% |
| Chosen on validation (3 passes) | 48.0% / 70.9% | 78.0% / 92.5% |
| Chosen on validation, with the GitHub platform sites | 46.9% / 69.7% | 77.5% / 92.4% |

Ten months on, a model without the new links catches about half the fakes on new sites at High, against 57% on the site split: drift costs about 9 points, which is why this model trains on the October 2026 links too, and why the model must be retrained as the feeds change. The GitHub platform sites cost about a point here and lower false alarms on hosting platforms (High 0.11% against 0.14% on the same data without them; 0.03% for this model); they are kept because a false alarm on an ordinary pages.dev or web.app site was the most visible mistake of the 21 October model (below). The heuristics alone (§10.3) warn on 0.003% of the never-seen Phishing.Database pages and 0.03% of PhiUSIIL's: they look for specific tricks (a lookalike of a protected brand, an `@` in the address), not for resemblance.

**Speed:** p50 1.9 µs, p95 4.0 µs per address on the training machine. On the Android emulator, a whole check (navigation policy, threat database, Rift AI) takes p50 19 µs and p95 64 µs (v1).

**Addresses checked by hand** (made up for the probe, so none in the training data):

| Address | 21 Oct model | This model |
|---|---|---|
| `https://accounts.google.com/signin`, `github.com/login`, `www.paypal.com/signin`, `www.amazon.co.uk/gp/cart`, `online.chase.com` | not scored (most visited) | not scored |
| `https://my-portfolio.pages.dev/` | **High (95)** | Low (4) |
| `https://todo-app-3f2a1.web.app/` | Elevated (86) | Low (17) |
| `https://www.uotechnology.edu.iq/` | Low (8) | Low (8) |
| `https://paypa1.com/login` | Elevated (85) | Elevated (85) |
| `https://secure-login-paypal.verify-account.xyz/webscr` | High (99) | High (99) |
| `https://appleid-verify-account.web.app/`, `metamask-wallet-restore.pages.dev/`, `microsoft-office365-login.firebaseapp.com/index.html` | High (98) | High (96–97) |
| `https://usps-redelivery-track.com/track`, `netflix-billing-update.com/account`, `free-iphone-giveaway.top/claim` | High (98) | High (97–98) |
| `http://192.168.1.1/login`, `http://45.133.1.20/bins/mips` | High (98) | High (98) |

`crates/rift-ffi/src/ai.rs` tests the shipped file on addresses like these: the most visited sites are not scored, the fakes are High (now including fakes on pages.dev and web.app), and the ordinary platform sites are Low (now including pages.dev and web.app).

## Limits

- **It judges the address, not the page.** A phishing page at an ordinary-looking address on a site it has not seen is missed: about 1 in 5 of the never-seen Phishing.Database pages are not even Elevated. That is why it never says "safe".
- **Look-alike-free phishing is hard.** PhiUSIIL's phishing set is mostly bare names that look like any small business; the model catches 21.9% of it at High.
- **Real login pages of small sites** can be Elevated, and sometimes High (webmail and sign-in pages share words with the fakes). High asks before loading; it never blocks.
- **pages.dev and web.app**: Common Crawl's index had almost no ordinary pages on pages.dev (43 entries, none an HTML page) and few on web.app, so ordinary sites there are learned from GitHub READMEs' links, about 10,000 sites: projects' own sites, not a random sample of the platforms. About 3% of them are still Elevated.
- **Not scored on the 10,000 most visited sites**, including fakes hosted on them; those are for the threat database.
- **Time:** ten months of drift cost about 9 points of High on new sites (above). The model does not update itself; it needs retraining as the feeds change.
- **No comparison with Google Safe Browsing**: that needs its API, which Rift does not use offline.

## Learning from new data

The model learns when it is retrained on fresh feeds, and a new file ships with the app (later, in a signed pack, §13). It does not learn on the device and never from what the user opens (§16).

```sh
D=<download dir>; P=<prepared dir>     # outside the repository
curl -sL -o $D/phishing-db-active.txt https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt  # frozen since Dec 2025
# The live list: every split file in phishing-links-ACTIVE/ (one, phishing-links-ACTIVE1.txt, on 22 Oct 2026), joined.
gh api repos/Phishing-Database/Phishing.Database/contents/phishing-links-ACTIVE \
  --jq '.[] | select(.name | test("ACTIVE[0-9]+\\.txt$")) | .download_url' | xargs -n1 curl -sL > $D/phishing-db-now.txt
curl -sL -o $D/mf-urlhaus-filter.txt https://malware-filter.gitlab.io/malware-filter/urlhaus-filter.txt
curl -sL -o $D/tranco.zip https://tranco-list.eu/top-1m.csv.zip && unzip -o $D/tranco.zip -d $D/tranco
curl -sL -o $D/phiusiil.zip "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip" && unzip -o $D/phiusiil.zip -d $D/phiusiil
curl -sL -o $D/public_suffix_list.dat https://publicsuffix.org/list/public_suffix_list.dat
C=CC-MAIN-2026-39; curl -sL -o $D/cc-cluster.idx https://data.commoncrawl.org/cc-index/collections/$C/indexes/cluster.idx
T=tools/rift-train
python3 -I $T/cc_sample.py $C $D/cc-cluster.idx $D/cc-benign.txt 1000
python3 -I $T/prepare.py $D $P     # first pass: tranco-hosts.txt and the feeds
python3 -I $T/cc_popular.py $C $D/cc-cluster.idx $P/tranco-hosts.txt 3000 $D/cc-popular.txt
python3 -I $T/cc_platforms.py $C $D/cc-cluster.idx $T/platforms.txt $D/cc-platforms.txt $P/phishing-db.txt $P/urlhaus-hosts.txt $P/phiusiil-phishing.txt
python3 -I $T/gh_platforms.py pages.dev,web.app,firebaseapp.com $D/gh-platforms.txt $P/phishing-db.txt $P/urlhaus-hosts.txt $P/phiusiil-phishing.txt  # signed-in gh; ~30 min
python3 -I $T/prepare.py $D $P     # again, with the Common Crawl and GitHub samples
cargo run --release -p rift-train -- --bits 19 --epochs 6 \
  --out models/url-model.bin --report models/url-model.json \
  --suffixes $P/psl-ascii.txt --popular $P/tranco-hosts.txt:10000 --platforms $T/platforms.txt \
  --source phishdb:malicious:urls:$P/phishing-db.txt --source phishdb-2026:malicious:urls:$P/phishing-db-now.txt \
  --source urlhaus:malicious:hosts:$P/urlhaus-hosts.txt \
  --source phiusiil-phish:malicious:urls:$P/phiusiil-phishing.txt --source commoncrawl:benign:urls:$P/commoncrawl.txt \
  --source popular:benign:urls:$P/commoncrawl-popular.txt --source platforms:benign:urls:$P/commoncrawl-platforms.txt \
  --source github-platforms:benign:urls:$P/github-platforms.txt \
  --source tranco:benign:hosts:$P/tranco-hosts.txt --source phiusiil-legit:benign:urls:$P/phiusiil-legit.txt
# A time-separated test: train without the newest feed and add it as `--source <name>:malicious:urls:<file>:eval`
# (new_sites.py keeps the links on sites the older feed never had).
cargo run -q --release -p rift-ffi --example ai_probe -- <addresses>   # look before shipping (RIFT_MODEL=<file> for another model)
```

Then update this report and `url-model-notice.txt` (dates, counts), and run `cargo test -p rift-ffi ai::`, whose checks on the shipped file must still hold.
