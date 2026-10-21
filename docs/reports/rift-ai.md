# Rift AI: the URL model

**Model:** `models/url-model.bin`, SHA-256 `a3b979eb4568390e7c24013f5e4aee0a59ba2344b0b1fc5a89246732d4fb35d7`, 1,278,656 bytes, feature schema 1
**Trained:** 21 October 2026, on feeds fetched that day, by `tools/rift-train` (deterministic: the same data and arguments give the same file)
**Full numbers:** `models/url-model.json` (written by the trainer, alongside the model)
**Architecture:** §16

Rift AI looks at a web address, nothing else, and says how closely it resembles the phishing and malware addresses it learned from. It runs on the device, in about 2 µs per address, and sends nothing anywhere. Its answer is advisory: it adds a warning before a page loads, or a note, and never blocks, never overrides the threat database, and never calls anything safe.

## What it learned from

| Source | What | Used as | Licence | Examples kept |
|---|---|---|---|---|
| [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database), ACTIVE links | Phishing URLs, checked as still live | malicious | MIT | 573,639 |
| [URLhaus](https://urlhaus.abuse.ch/), through [malware-filter's urlhaus-filter](https://gitlab.com/malware-filter/urlhaus-filter) (the official download now returns 410) | Hosts serving malware | malicious, hosts | CC0 (the mirror) | 18,558 |
| [PhiUSIIL](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) (UCI), label 0 | Phishing URLs | malicious | CC BY 4.0 | 74,541 |
| [Common Crawl](https://commoncrawl.org/) CC-MAIN-2026-39, 1,000 random index blocks | Ordinary pages that answered 200 with HTML | benign | Terms of use | 361,015 |
| Common Crawl, one block per site of the 3,000 most visited | Real sign-in, mail and file pages of large sites | benign | Terms of use | 24,929 |
| Common Crawl, up to 8 blocks per hosting platform (35 platforms: github.io, vercel.app, workers.dev, web.app, netlify.app…) | Ordinary sites on the platforms phishing also uses | benign | Terms of use | 36,011 |
| [Tranco](https://tranco-list.eu/) top 1M | Site names, most visited first | benign, hosts (first 200,000) | cited as requested | 200,000 |
| PhiUSIIL, label 1 | Legitimate URLs (names only, no paths) | benign | CC BY 4.0 | 134,765 |
| [Public Suffix List](https://publicsuffix.org/), both sections | Where a site's name begins | site boundaries | MPL-2.0 | 10,396 rules |

The URLs themselves are never committed: they are real malicious addresses (§21). `prepare.py` turns the downloads into one-entry-per-line files; nothing in them is opened or fetched. The app's licences screen carries the notices (`models/url-model-notice.txt`).

**Not VirusTotal.** VirusTotal's terms do not allow building a product's detection on its verdicts, its API needs a key that would have to ship in the app, and every lookup would send the user's link to a third party. Rift sends no link anywhere (§17).

## How it works

- **Features** (`rift_core::urlmodel::for_each_feature`, shared by the trainer and the app, so they cannot disagree): character 3- to 5-grams of the host, its labels, words and shape, the top-level domain and last two labels, how random the name looks, the scheme, the path's words, word pairs, opening characters, extension and shape, query keys, and an address embedded in the address. They are hashed into 2^19 signed buckets.
- **Model:** logistic regression trained by AdaGrad, with the two classes weighted equally, 4 passes. Weights are stored as 16-bit integers with one scale (1 MiB). More passes did not help: with 8, the AUC fell from 0.9781 to 0.9766.
- **Two views:** the whole address (Check, and navigations), and the host alone, which is all the live watch's proxy sees of an HTTPS request.
- **Sites** are what the Public Suffix List says, private section included. So `someone.workers.dev` is a site of its own, and so is `bbc.co.uk`. The rules ship inside the model.
- **The 10,000 most visited sites are not scored.** Their real sign-in pages and the fakes hosted on them (Google Forms, Drive, Docs) have the same kind of address, and an earlier model rated `mail.google.com` and `login.microsoftonline.com` as high risk. For those sites the check says "not scored", and the threat database still checks every page. The model carries 64-bit hashes of these sites, not their names.
- **Hosting platforms are balanced.** The feeds list about 25,000 fakes on workers.dev alone, and before platforms were balanced every github.io or vercel.app site scored high, whatever it was. Training now takes at most 2,500 malicious pages per platform, as many as the ordinary pages sampled from it. Validation and test keep every page.
- **Thresholds** come from the validation split: High at a 0.1% and Elevated at a 1% false-positive rate, averaged over the benign sources (each kind of page counts the same). A source with fewer than 2,000 scored pages does not set them. High is 0.992 and Elevated 0.897. The 0–99 score shown is banded so that Elevated starts at 50 and High at 90.

## How well it does

Every source is split **by site** (80% train, 10% validation, 10% test), so the test measures sites the model has never seen. That is the honest number for a new phishing site. "Seen" is a site in the training split: most links in a feed on any one day are on sites that were in the feed before.

**Whole address (Check, navigation), test split: sites never seen**

| Source | Pages | High | Elevated or High | Not scored |
|---|---:|---:|---:|---:|
| Phishing.Database | 62,911 | 57.3% | 80.7% | 0% |
| URLhaus hosts | 1,697 | 89.9% | 91.3% | 0% |
| PhiUSIIL phishing | 7,514 | 26.5% | 47.0% | 0% |
| Common Crawl, ordinary pages (falsely flagged) | 36,045 | 0.05% | 0.54% | 0.36% |
| Common Crawl, hosting platforms (falsely flagged) | 3,506 | 0.06% | 3.39% | 0% |
| Common Crawl, most visited sites (falsely flagged) | 2,280 | 0% | 0.57% | 91% |
| Tranco names (falsely flagged) | 19,973 | 0.01% | 0.18% | 4.7% |
| PhiUSIIL legitimate (falsely flagged) | 13,397 | 0% | 0.22% | 1.5% |

**Sites seen in training:** Phishing.Database 69.9% High, 89.9% flagged; URLhaus 90.4% / 92.8%; ordinary pages 0.00% / 0.03%.

**Host only (the live watch, for HTTPS requests), never seen:** Phishing.Database 23.0% High, 47.3% flagged (many fakes are only recognisable by their path); URLhaus 89.9% / 90.9%; ordinary hosts 0.00% / 0.46%; hosting platforms 0.11% / 2.41%.

AUC on the test split of the trained sources: 0.9781. The heuristics alone (§10.3) warn on 0.003% of the never-seen Phishing.Database pages and 0.03% of PhiUSIIL's: they look for specific tricks (a lookalike of a protected brand, an `@` in the address), not for resemblance.

**Speed:** p50 1.9 µs, p95 4.0 µs per address on the training machine. On the Android emulator, a whole check (navigation policy, threat database, Rift AI) takes p50 19 µs and p95 64 µs (c1).

**Addresses checked by hand** (none in the training data):

| Address | Result |
|---|---|
| `https://mail.google.com/mail/u/0/`, `login.microsoftonline.com`, `outlook.live.com/mail`, `github.com/login`, `www.paypal.com/signin` | not scored (most visited) |
| `https://rust-lang.github.io/rustup/`, `my-portfolio.vercel.app`, `hello-world.workers.dev`, `my-shop.myshopify.com/products/shoes` | Low (0–13) |
| `https://login.my-university.edu/cas/login` | Elevated (63) |
| `https://webmail.smallbusiness.net/login` | Elevated (88) |
| `https://svelte-demo.pages.dev/about`, `myapp-12345.web.app` | Elevated (73, 75) |
| `http://secure-paypal-login.verify-account.xyz/signin/update.php?id=1` | High (99) |
| `https://appleid.apple.com.account-verify.top/`, `chase-online-verify.netlify.app/login`, `metamask-io.web.app/restore` | High (98) |
| `https://paypa1-secure.workers.dev/login` | High (94) |
| `http://192.168.4.20/bank/login.php` | High (98) |

`crates/rift-ffi/src/ai.rs` tests the shipped file on addresses like these: the most visited sites are not scored, the fakes are High, and the ordinary platform sites are Low.

## Limits

- **It judges the address, not the page.** A phishing page at an ordinary-looking address on a site it has not seen is missed: about 1 in 5 of the never-seen Phishing.Database pages are not even Elevated. That is why it never says "safe".
- **Look-alike-free phishing is hard.** PhiUSIIL's phishing set is mostly bare names that look like any small business; the model catches 26.5% of it at High.
- **Real login pages of small sites** can be Elevated, and sometimes High (webmail and sign-in pages share words with the fakes). High asks before loading; it never blocks.
- **pages.dev and web.app**: Common Crawl's index had almost no ordinary pages on pages.dev (43 entries, none an HTML page) and few on web.app. Their ordinary sites can be Elevated.
- **Not scored on the 10,000 most visited sites**, including fakes hosted on them; those are for the threat database.
- **Time:** the test splits by site, not by date. A time-separated test (train on one month's feeds, test on the next) has not been run, and phishing changes. The model needs retraining as feeds change.
- **No comparison with Google Safe Browsing**: that needs its API, which Rift does not use offline.

## Learning from new data

The model learns when it is retrained on fresh feeds, and a new file ships with the app (later, in a signed pack, §13). It does not learn on the device and never from what the user opens (§16).

```sh
D=<download dir>; P=<prepared dir>     # outside the repository
curl -sL -o $D/phishing-db-active.txt https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt
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
python3 -I $T/prepare.py $D $P     # again, with the Common Crawl samples
cargo run --release -p rift-train -- --bits 19 --epochs 4 \
  --out models/url-model.bin --report models/url-model.json \
  --suffixes $P/psl-ascii.txt --popular $P/tranco-hosts.txt:10000 --platforms $T/platforms.txt \
  --source phishdb:malicious:urls:$P/phishing-db.txt --source urlhaus:malicious:hosts:$P/urlhaus-hosts.txt \
  --source phiusiil-phish:malicious:urls:$P/phiusiil-phishing.txt --source commoncrawl:benign:urls:$P/commoncrawl.txt \
  --source popular:benign:urls:$P/commoncrawl-popular.txt --source platforms:benign:urls:$P/commoncrawl-platforms.txt \
  --source tranco:benign:hosts:$P/tranco-hosts.txt --source phiusiil-legit:benign:urls:$P/phiusiil-legit.txt
cargo run -q --release -p rift-ffi --example ai_probe -- <addresses>   # look before shipping
```

Then update this report and `url-model-notice.txt` (dates, counts), and run `cargo test -p rift-ffi ai::`, whose checks on the shipped file must still hold.
