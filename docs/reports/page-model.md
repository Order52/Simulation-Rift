# Rift AI's page model: data, results and limits

**26 Oct 2026, app 0.10.0, architecture 3.0 (§16.1).** The model reads an opened page in the sealed browser and warns before anything is typed into it. It is advisory: it can add a warning and never clears one.

## Data

The Phishing Websites Dataset (Ariyadasa, Fernando and Fernando, Mendeley Data, 2021, [doi:10.17632/n96ncsr5g4.1](https://data.mendeley.com/datasets/n96ncsr5g4/1), CC BY 4.0): 80,000 saved pages with their URLs, 50,000 legitimate and 30,000 phishing (PhishTank, OpenPhish and PhishRepo, December 2020 to October 2021). The index (`index.sql`) and the eight parts were downloaded from Mendeley's public files and each part was checked against the SHA-256 Mendeley publishes. The data is not in the repository; `models/page-model-notice.txt` carries the attribution, and the app shows it under its open-source notices.

The pages were read as text by the trainer only (an HTML5 parser, no scripts run, nothing rendered).

## Method

- **Same counts as the app.** `tools/rift-train page` counts in each saved page what the browser's script counts in a live one (`PageCounts`; architecture §16.1), and calls `rift_core::pagemodel::features`, the code the app runs, so training and use share the features. The trainer's test checks a page counted as the script counts it.
- **Model.** Logistic regression over 33 features, standardised for training and folded back into raw weights; full-batch Adam, 400 passes.
- **Splits by site** (the last two labels of the host, as the app compares sites): 80% train (64,503 pages), 10% validation (6,823), 10% test (8,674). No site is in two splits.
- **Choices on validation only.** L2 strength from {0, 1e-4, 1e-3, 1e-2}, by recall at 0.5% false alarms (chosen: 1e-2). Thresholds: High where 0.5% of validation's legitimate pages score above it (0.874), Elevated at 2% (0.725). The test split was used once, after.

## Results (test: 8,674 pages of sites never seen)

| | Phishing pages flagged | Legitimate pages flagged |
|---|---|---|
| High (a *Warning* in the watch) | **54.2%** | **0.23%** |
| Elevated or High | 68.8% | 4.50% |

AUC 0.950 (validation 0.954). A first run on 20,000 pages gave AUC 0.951, so more data changed little: the model is limited by what 33 counts can see, not by the amount of data.

What raises the score most (weights on raw features): links that go nowhere (`#`, `javascript:`), links that lead to another site, a form posting to a bare `.php` script, a blocked context menu, a form with no real destination, a password field, a password form sending to another site, a meta refresh, an icon from another site and an empty title. What lowers it most: the site's own name in the title or the text, and many scripts, links and forms (a full site rather than a single page).

On the API 34 emulator (N10), the fixture `kit.html` (a harmless page shaped like a kit) was reported as "closely resembling phishing pages: most of its links go nowhere; its form posts to a bare PHP script, as phishing kits do; it blocks the long-press menu", in the watch and in the Test-open report.

## Learning from new pages (since 27 October 2026)

Phishing pages stay up for hours or days, so they are gathered as they appear and learned from monthly (`.github/workflows/retrain.yml`, jobs `collect-pages` and `pages`; `tools/rift-train/retrain_pages.sh`):

1. **Twice a day** (as OpenPhish's feed changes), `fetch_pages.py` fetches up to 1,500 phishing pages, the freshest first (OpenPhish's feed, Phishing.Database's links new today, then its live links), and 400 ordinary ones (Common Crawl's pages of the newest crawl, sampled once per crawl, and 3,000 popular sites' home pages), one page per site, as a phone's browser asks for them. Only the HTML is read; nothing in it is run. Both kinds go through the same fetch and filters, so the model cannot learn the fetch instead of the page: a page is kept if it answered 200 with HTML, stayed on its site (a kit that sends visitors elsewhere shows nothing of itself), is not a hosting error, parking or bot-check page, and is not a copy of one kept. Addresses that resolve to private, loopback or link-local networks are refused before connecting and at each redirect.
2. **Counts, not pages.** `rift-train page counts` turns each page into the report the browser's script sends (numbers, the title and the start of the text). The pages are then deleted.
3. **Memory.** `page_memory.py` adds the counts to those of the last 24 months (at most 300,000 pages), kept as a workflow artifact, never in the repository. `take_memory.sh` takes the newest one by asking GitHub for it directly and fails if it cannot, so a memory is never restarted empty by a failed lookup; collections run one at a time.
4. **Monthly training** on the 2021 dataset (downloaded from Mendeley and checked against the SHA-256 Mendeley publishes, `page-dataset.txt`) and the memory, the memory weighing as much in all as the dataset (each recent page at most ten times one old page). Splits are by site as before; the split is fixed by the site's name, so a site in the test split is never trained on, this month or any other.
5. **Gate.** On the memory's test-split pages, as the app scores them (`PageModel`), the new model must flag at most 1% of ordinary pages at High and at most 0.25 points more than the shipped model, catch at least as many phishing pages at High, and lose no more than 0.002 of AUC; at least 150 of each kind are needed to judge. It must then pass the shipped-model tests (`pagemodel::` and `rift-ffi`). Only then is a pull request opened; it merges itself when CI passes.

The trainer was split into `counts` and `train` for this. Trained from counts, the 2021 data gives a model identical, line for line, to the shipped one, so the split changed nothing.

**What the first run found (27 October 2026).** A single fetch kept 261 of 6,000 phishing pages tried (4,123 of the sites no longer resolve: Phishing.Database's live list lags) and 4,621 of 6,000 ordinary ones. On the 504 of them from test-split sites, the **shipped model catches 12% of today's phishing pages at High (AUC 0.74)**, against 54% on the 2021 test: phishing pages have changed. A model trained with them did no better on so few pages (12%, AUC 0.745), and the gate refused it for having 25 phishing pages to judge by. Hence the twice-daily collection: it is the only way to gather enough of today's phishing pages, and the monthly run will be judged on them.

## Fixed rules beside the model (3.2)

Three rules over the same counts, on pages with a password field, measured on the 80,000 pages of the 2021 dataset (all of it; nothing was fitted, so there is no test split to keep apart):

| Rule | Phishing pages (30,000) | Ordinary pages (50,000) |
|---|---|---|
| Links go nowhere: 4 in 5 of 5 or more, or no link | 14.85% | 0.144% |
| A form to a `.php` script on another site | 3.26% | 0.124% |
| The right-click menu blocked | 1.20% | 0.088% |
| Any of the three | 18.00% | 0.346% |

Rules tried and left out, for their false alarms on ordinary pages with a password: an icon from another site (20% of them), a form to another site in general (5.6%), three or more `eval`/`atob`-style calls (11%), a hidden frame (3.5%). The rules are `rift_core::page::rules`, shown as Warnings in the watch; they share the model's caveat that the dataset is from 2020 to 2021.

## Verified

- The trained model parses, scores a kit page High with reasons and an ordinary page Low (`pagemodel` tests), and is used by `Navigator::assess_page` (`rift-ffi` test). A malformed or oversized report gives no score.
- End to end on the API 34 emulator (N10): the browser's script, the bridge, the bounds and the model together produce the warning.
- The figures above, on sites the model never saw.

## Unverified

- **Accuracy on today's pages** is poor: 12% of today's phishing pages at High on the first, small sample (see *Learning from new pages*). The data is from 2020–2021; the model is being retrained on new pages as they are gathered. Phishing kits and ordinary sites have changed since; no time-separated test was possible with this dataset. The 0.23% false-alarm rate is for the dataset's legitimate pages, which lean towards popular sites' home pages; ordinary pages deeper in sites may differ.
- **Saved versus live pages.** The dataset holds the HTML as fetched; the browser counts the page after its scripts have run. Pages that build themselves with scripts look different to the two. N10 checks the counting matches on one page, not the distributions.
- **On a phone.** Tested on the emulator only.

## Could be improved

- Count fresh pages in the sealed browser itself, after their scripts run, as the app does, instead of their HTML as fetched.
- Test each month's model on the next month's pages (a forward test), not only on test-split sites of the same months.
- A visual model (a screenshot compared with well-known brands' sign-in pages) would catch kits that copy a page exactly, which counts cannot; it would need a far larger model.
- A user-facing "why" screen showing each reason's weight.
