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

## Verified

- The trained model parses, scores a kit page High with reasons and an ordinary page Low (`pagemodel` tests), and is used by `Navigator::assess_page` (`rift-ffi` test). A malformed or oversized report gives no score.
- End to end on the API 34 emulator (N10): the browser's script, the bridge, the bounds and the model together produce the warning.
- The figures above, on sites the model never saw.

## Unverified

- **Accuracy on today's pages.** The data is from 2020–2021. Phishing kits and ordinary sites have changed since; no time-separated test was possible with this dataset. The 0.23% false-alarm rate is for the dataset's legitimate pages, which lean towards popular sites' home pages; ordinary pages deeper in sites may differ.
- **Saved versus live pages.** The dataset holds the HTML as fetched; the browser counts the page after its scripts have run. Pages that build themselves with scripts look different to the two. N10 checks the counting matches on one page, not the distributions.
- **On a phone.** Tested on the emulator only.

## Could be improved

- Train on newer pages (for example a crawl of current PhishTank and OpenPhish pages, captured in the sealed browser itself, if a licence allows) and test on a later month.
- A visual model (a screenshot compared with well-known brands' sign-in pages) would catch kits that copy a page exactly, which counts cannot; it would need a far larger model.
- A user-facing "why" screen showing each reason's weight.
