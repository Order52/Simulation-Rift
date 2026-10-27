#!/bin/sh
# Retrains Rift AI's page model on the 2021 dataset, today's pages and the
# memory of earlier months (docs/reports/page-model.md, "Learning from new
# pages"), and writes models/page-model.txt only if the gate passes. Run
# from the repository root; D must be outside it (the pages are real
# phishing pages and are never committed).
#
#   sh tools/rift-train/retrain_pages.sh <work-dir>
#
# With RIFT_PAGE_MEMORY set, the memory at that path (if there is one) gains
# this month's counted pages and is written back there before the gate.
# Exit status 2: the gate refused the new model (the shipped one is kept).
set -eu
D="$1"
T=tools/rift-train
PER_LABEL="${RIFT_PAGES_PER_LABEL:-6000}"
month="$(date -u +%Y-%m)"
mkdir -p "$D/dataset" "$D/feeds" "$D/fetched"
fetch() { curl -fsSL --retry 3 -o "$1" "$2"; }
train() { cargo run --quiet --locked --release -p rift-train --bin page -- "$@"; }

# The 2021 dataset, checked against Mendeley's hashes and counted a part at a time.
grep -v '^#' $T/page-dataset.txt | while read -r name url sha; do
  case "$url" in https://data.mendeley.com/public-files/datasets/n96ncsr5g4/*) ;; *) echo "unexpected address: $url" >&2; exit 1 ;; esac
  [ -f "$D/dataset/$name" ] || fetch "$D/dataset/$name" "$url"
  echo "$sha  $D/dataset/$name" | sha256sum -c --quiet
done
: > "$D/base.tsv"
for part in "$D"/dataset/dataset_part_*.zip; do
  rm -rf "$D/part" && mkdir "$D/part"
  unzip -q -j -n "$part" -d "$D/part"
  train counts "$D/dataset/index.sql" "$D/part" "$D/part.tsv"
  cat "$D/part.tsv" >> "$D/base.tsv"
done
rm -rf "$D/part" "$D/part.tsv"
echo "2021 dataset: $(wc -l < "$D/base.tsv") pages counted."

# Today's phishing pages (OpenPhish's feed, Phishing.Database's live links)
# and ordinary ones (Common Crawl's pages of this crawl, Tranco's sites).
fetch "$D/feeds/openphish.txt" https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
fetch "$D/feeds/active-index.json" https://api.github.com/repos/Phishing-Database/Phishing.Database/contents/phishing-links-ACTIVE
python3 -I -c '
import json, sys
for entry in json.load(open(sys.argv[1])):
    name = entry.get("name", "")
    if name.startswith("phishing-links-ACTIVE") and name.endswith(".txt"):
        print(entry["download_url"])
' "$D/feeds/active-index.json" > "$D/feeds/active-urls.txt"
: > "$D/feeds/phishing-db.txt"
while read -r url; do
  case "$url" in https://raw.githubusercontent.com/Phishing-Database/*) ;; *) echo "unexpected list address: $url" >&2; exit 1 ;; esac
  curl -fsSL --retry 3 "$url" >> "$D/feeds/phishing-db.txt"
done < "$D/feeds/active-urls.txt"
fetch "$D/feeds/collinfo.json" https://index.commoncrawl.org/collinfo.json
C="$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))[0]["id"])' "$D/feeds/collinfo.json")"
case "$C" in CC-MAIN-[0-9][0-9][0-9][0-9]-[0-9][0-9]) ;; *) echo "unexpected collection: $C" >&2; exit 1 ;; esac
fetch "$D/feeds/cc-cluster.idx" "https://data.commoncrawl.org/cc-index/collections/$C/indexes/cluster.idx"
python3 -I $T/cc_sample.py "$C" "$D/feeds/cc-cluster.idx" "$D/feeds/cc-pages.txt" 400
fetch "$D/feeds/tranco.zip" https://tranco-list.eu/top-1m.csv.zip
unzip -oq "$D/feeds/tranco.zip" -d "$D/feeds/tranco"
# Home pages of popular sites, a few: most ordinary pages are not home pages.
head -n 3000 "$D/feeds/tranco/top-1m.csv" | cut -d, -f2 | tr -d '\r' | sed 's|^|https://|; s|$|/|' > "$D/feeds/tranco-sites.txt"

python3 -I $T/fetch_pages.py "$D/fetched" "$PER_LABEL" "$month" \
  --phishing "$D/feeds/openphish.txt" "$D/feeds/phishing-db.txt" \
  --legit "$D/feeds/cc-pages.txt" "$D/feeds/tranco-sites.txt"
train counts "$D/fetched/index.tsv" "$D/fetched/pages" "$D/fresh.tsv"
rm -rf "$D/fetched/pages"

previous=-
if [ -n "${RIFT_PAGE_MEMORY:-}" ] && [ -s "$RIFT_PAGE_MEMORY" ]; then
  cp "$RIFT_PAGE_MEMORY" "$D/memory-before.tsv"; previous="$D/memory-before.tsv"
fi
python3 -I $T/page_memory.py "$month" "$previous" "$D/memory.tsv" "$D/recent.tsv" "$D/fresh.tsv"
[ -n "${RIFT_PAGE_MEMORY:-}" ] && cp "$D/memory.tsv" "$RIFT_PAGE_MEMORY"

# Recent pages count double: the 2021 dataset is far larger and older.
train train "$D/page-model.txt" --counts "$D/base.tsv" --recent "$D/recent.tsv:2" --champion models/page-model.txt
cp "$D/page-model.txt" models/page-model.txt
