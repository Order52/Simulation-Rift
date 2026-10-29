#!/bin/sh
# Rift AI's page model learns from new pages (docs/reports/page-model.md,
# "Learning from new pages"). Run from the repository root; the work
# directory must be outside it (the pages are real phishing pages and are
# never committed).
#
#   sh tools/rift-train/retrain_pages.sh collect <work-dir> <memory.tsv> [<ordinary-urls>]
#     Four times a day: fetches the newest phishing pages and some ordinary ones,
#     counts them, deletes them, and adds the counts to the memory.
#     <ordinary-urls> is a cached Common Crawl sample; made if missing.
#
#   sh tools/rift-train/retrain_pages.sh train <work-dir> <memory.tsv>
#     Weekly: scores the shipped model on the pages gathered in the last 7
#     days (a forward test: it was trained before they were), then trains on
#     the 2021 dataset and the memory, and writes models/page-model.txt only
#     if the gate passes. Exit status 2: refused.
set -eu
mode="$1"; D="$2"; MEMORY="$3"
T=tools/rift-train
day="$(date -u +%Y-%m-%d)"
mkdir -p "$D"
fetch() { curl -fsSL --retry 3 -o "$1" "$2"; }
page() { cargo run --quiet --locked --release -p rift-train --bin page -- "$@"; }

# Every list file of a Phishing.Database folder, joined.
phishing_db() {
  fetch "$D/index.json" "https://api.github.com/repos/Phishing-Database/Phishing.Database/contents/$1"
  python3 -I -c '
import json, sys
for entry in json.load(open(sys.argv[1])):
    name = entry.get("name", "")
    if name.endswith(".txt") and "manifest" not in name:
        print(entry["download_url"])
' "$D/index.json" > "$D/list-urls.txt"
  : > "$2"
  while read -r url; do
    case "$url" in https://raw.githubusercontent.com/Phishing-Database/*) ;; *) echo "unexpected list address: $url" >&2; exit 1 ;; esac
    curl -fsSL --retry 3 "$url" >> "$2"
  done < "$D/list-urls.txt"
}

case "$mode" in
collect)
  ORDINARY="${4:-$D/cc-pages.txt}"
  if [ ! -s "$ORDINARY" ]; then
    fetch "$D/collinfo.json" https://index.commoncrawl.org/collinfo.json
    C="$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))[0]["id"])' "$D/collinfo.json")"
    case "$C" in CC-MAIN-[0-9][0-9][0-9][0-9]-[0-9][0-9]) ;; *) echo "unexpected collection: $C" >&2; exit 1 ;; esac
    fetch "$D/cc-cluster.idx" "https://data.commoncrawl.org/cc-index/collections/$C/indexes/cluster.idx"
    python3 -I $T/cc_sample.py "$C" "$D/cc-cluster.idx" "$ORDINARY" 400
    rm "$D/cc-cluster.idx"
  fi
  fetch "$D/openphish.txt" https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
  phishing_db phishing-links-NEW-today "$D/phishing-db-new.txt"
  phishing_db phishing-links-ACTIVE "$D/phishing-db-active.txt"
  fetch "$D/tranco.zip" https://tranco-list.eu/top-1m.csv.zip
  unzip -oq "$D/tranco.zip" -d "$D/tranco"
  # Home pages of popular sites, a few: most ordinary pages are not home pages.
  head -n 3000 "$D/tranco/top-1m.csv" | cut -d, -f2 | tr -d '\r' | sed 's|^|https://|; s|$|/|' > "$D/tranco-sites.txt"
  # The freshest feeds first; ordinary pages about as many as phishing ones kept.
  rm -rf "$D/fetched"
  python3 -I $T/fetch_pages.py "$D/fetched" 1500 "$(date -u +%Y-%m-%dT%H)" \
    --phishing "$D/openphish.txt" "$D/phishing-db-new.txt" "$D/phishing-db-active.txt" \
    --legit "$ORDINARY" "$D/tranco-sites.txt" \
    --legit-max 400
  page counts "$D/fetched/index.tsv" "$D/fetched/pages" "$D/fresh.tsv"
  rm -rf "$D/fetched/pages"
  previous=-
  if [ -s "$MEMORY" ]; then cp "$MEMORY" "$D/memory-before.tsv"; previous="$D/memory-before.tsv"; fi
  python3 -I $T/page_memory.py "$day" "$previous" "$MEMORY" "$D/recent.tsv" "$D/fresh.tsv"
  ;;
train)
  # The 2021 dataset, checked against Mendeley's hashes and counted a part at a time.
  mkdir -p "$D/dataset"
  grep -v '^#' $T/page-dataset.txt | while read -r name url sha; do
    case "$url" in https://data.mendeley.com/public-files/datasets/n96ncsr5g4/*) ;; *) echo "unexpected address: $url" >&2; exit 1 ;; esac
    [ -f "$D/dataset/$name" ] || fetch "$D/dataset/$name" "$url"
    echo "$sha  $D/dataset/$name" | sha256sum -c --quiet
  done
  : > "$D/base.tsv"
  for part in "$D"/dataset/dataset_part_*.zip; do
    rm -rf "$D/part" && mkdir "$D/part"
    unzip -q -j -n "$part" -d "$D/part"
    page counts "$D/dataset/index.sql" "$D/part" "$D/part.tsv" 2>&1 | tail -n 1
    cat "$D/part.tsv" >> "$D/base.tsv"
  done
  rm -rf "$D/part" "$D/part.tsv"
  echo "2021 dataset: $(wc -l < "$D/base.tsv") pages counted."
  [ -s "$MEMORY" ] || { echo "No page memory: nothing new to learn from."; exit 2; }
  cut -f2- "$MEMORY" > "$D/recent.tsv"
  # The forward test: the shipped model on the week's pages, all new to it.
  since="$(python3 -I -c 'import datetime; print(datetime.date.today() - datetime.timedelta(days=7))')"
  awk -F '\t' -v since="$since" 'length($1) == 10 && $1 >= since' "$MEMORY" | cut -f2- > "$D/week.tsv"
  if [ -s "$D/week.tsv" ]; then
    echo "Forward test, the shipped model on the pages gathered since $since:$(page eval models/page-model.txt "$D/week.tsv" | cut -d: -f2-)"
  fi
  # Recent pages weigh as much in all as the 2021 dataset (at most ten times each).
  weight="$(python3 -I -c 'import sys; b, r = (sum(1 for _ in open(p)) for p in sys.argv[1:]); print(min(10, max(1, round(b / max(r, 1)))))' "$D/base.tsv" "$D/recent.tsv")"
  echo "Page memory: $(wc -l < "$D/recent.tsv") pages, each weighing $weight."
  page train "$D/page-model.txt" --counts "$D/base.tsv" --recent "$D/recent.tsv:$weight" --champion models/page-model.txt
  cp "$D/page-model.txt" models/page-model.txt
  ;;
*)
  echo "usage: retrain_pages.sh collect|train <work-dir> <memory.tsv> [<ordinary-urls>]" >&2
  exit 1
  ;;
esac
