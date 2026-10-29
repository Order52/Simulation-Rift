# Architecture 3.3: Rift AI keeps up weekly, and its page model reads words and combinations

**Date:** 29 October 2026. **Architecture:** 3.3 (§16, §16.1). **Android:** 0.11.6 (the next weekly release). **Linux:** on hold ([TODO.md](../../TODO.md)).

## What changed

1. **Weekly, not monthly.** `retrain.yml` retrains the address model, the page model and the protected brands every Tuesday at 03:17 UTC, each behind its own gate as before. A model that passes merges itself when CI passes, and the release on Wednesday at 06:41 ships it. Nothing else about the gates changed: a model is still replaced only by a better one.
2. **More recent pages, dated.** Page collection runs four times a day instead of twice. The page memory now dates each page by the day it was counted (`YYYY-MM-DD`; the first collections' lines keep their month and are still read).
3. **A forward test.** Before training, each weekly run scores the shipped page model on the pages gathered in the last 7 days. None of them existed when that model was trained. The result is printed as "Forward test" in the run's summary and pull request: how well last week's model keeps up with this week's pages.
4. **The page model reads words and combinations** ([page-model.md](page-model.md#words-and-trees-33)).
   - Beside the 33 counts, it weighs the page's own words, learned from recent pages: at most 5,000, chosen from words that appear in at least 20 training pages.
   - It adds up to 300 boosted trees, three splits deep, over the counts. The trees catch combinations of signs that a weighted sum cannot.
   - Its thresholds are set with each page counting by its training weight, so recent pages set them.
   - The reasons still name what was seen. The trees' share is credited to the counts they split on, and the words show as "its wording is that of recent phishing pages". The page's own words are never shown.
   - The model file stays text, read with bounds; a model without words and trees still reads.
   - `rift-train page eval` scores any counts with a model, as the app does.

## Verified

- **Cross-validation on recent pages.** Five folds by site, on the 6,521 pages gathered on 27 and 28 October (628 phishing). Each fold trains on the 2021 dataset plus the other four folds, and is tested on sites it never saw. Means of the folds:

  | Design | AUC | High: phishing | High: ordinary |
  |---|---|---|---|
  | 3.0 regression, same data | 0.862 | 16.5% | 0.61% |
  | **3.3, words and trees** | **0.904** | **23.2%** | 0.69% |

  At Elevated or High the 3.3 design catches 42.8% of phishing pages against 29.5%, with fewer false alarms (1.63% against 2.35%).
- **The trainer's test split** for the model trained on everything: 9,345 pages of sites never seen, 8,674 from 2021 and 671 recent. AUC 0.985; at High it catches 71.7% of phishing pages, with 0.41% false alarms. The shipped model's own test, on 2021 pages alone, was AUC 0.950, with 54.2% caught and 0.23% false alarms.
- **Trained on 2021 alone, the new design is worse on today's pages** than the old one (AUC 0.818 against 0.848). The words only help when they are learned from recent pages, which is what the weekly retraining provides.
- **Unit tests** (`pagemodel`):
  - words are lower-cased, distinct and split correctly, including a letter whose lower case adds a mark (İ);
  - bad word and tree lines are refused;
  - a word and a tree add exactly their weights to the log-odds and name their reasons.
- **The model trained on everything passes the shipped-model tests**: `pagemodel::` and `rift-ffi`, including the kit page at High. So a model of this design that passes the gate can ship.
- **Rust:** all 290 tests in the product workspace pass, with `clippy -D warnings` and `fmt`.
- **`page_memory.py`** keeps old month-dated lines and dates new ones by day (checked on a sample of the memory).

## Unverified

- **The new design is not shipped yet.** The page model in the app is still the 3.0 regression.
  - On the trainer's test split of recent pages, the model trained on everything has AUC 0.844 against the shipped model's 0.780, and at Elevated or High it catches 28.8% against 23.7% of phishing pages.
  - At High it catches 5 of the 59 phishing pages there, against the shipped model's 8, and 59 are too few to judge. The gate needs 150 and refused it.
  - The weekly run will train the new design on the growing memory, at about 500 phishing pages a day. It replaces the shipped model only when the gate, on enough pages, finds it better.
- **The cross-validation used about 125 phishing pages per fold**, gathered over two days. The figures will move as the memory grows.
- **The address model's training is unchanged.** Weekly retraining only makes it catch up sooner, and no measurement of the gain exists yet.
- **No run of the weekly schedule yet.** The first is on Tuesday 3 November.
- **On a phone.** The page model has only been tested on emulators (N10, on the 3.0 model).

## Could be improved

- Gate on the forward test as well as on the test split, once a few weeks of dated pages exist.
- Within the memory, weigh pages by how recent they are, not only recent pages against the 2021 data.
- Deliver the page model and the brands in the signed threat-database pack as the address model can be, so they can update between app releases once the key ceremony is held.
