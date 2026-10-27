#!/bin/sh
# Relearns the brands Check protects (models/brands.txt; architecture §10.3)
# from today's feeds, and keeps the new list only if the gate passes
# (src/bin/brands.rs). Run from the repository root; D must be outside it.
#
#   sh tools/rift-train/retrain_brands.sh <work-dir> <dictionary>
#
# Exit status 2: the gate refused the new list (the shipped one is kept).
set -eu
D="$1"; WORDS="$2"
T=tools/rift-train
mkdir -p "$D"
fetch() { curl -fsSL --retry 3 -o "$1" "$2"; }

fetch "$D/openphish.txt" https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
fetch "$D/phishing-db.txt" https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt
fetch "$D/tranco.zip" https://tranco-list.eu/top-1m.csv.zip
unzip -oq "$D/tranco.zip" -d "$D/tranco"
cut -d, -f2 "$D/tranco/top-1m.csv" | tr -d '\r' > "$D/tranco-hosts.txt"
fetch "$D/collinfo.json" https://index.commoncrawl.org/collinfo.json
C="$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))[0]["id"])' "$D/collinfo.json")"
case "$C" in CC-MAIN-[0-9][0-9][0-9][0-9]-[0-9][0-9]) ;; *) echo "unexpected collection: $C" >&2; exit 1 ;; esac
fetch "$D/cc-cluster.idx" "https://data.commoncrawl.org/cc-index/collections/$C/indexes/cluster.idx"
python3 -I $T/cc_sample.py "$C" "$D/cc-cluster.idx" "$D/cc-pages.txt" 1000

python3 -I $T/brands.py "$D/tranco-hosts.txt" $T/brands-picked.txt $T/brands-never.txt \
  crates/rift-core/src/heuristics.rs "$WORDS" "$D/brands.txt" \
  --phishing "$D/openphish.txt" "$D/phishing-db.txt" --legit "$D/cc-pages.txt"
cargo run --quiet --locked --release -p rift-train --bin brands -- models/brands.txt "$D/brands.txt" \
  --legit "$D/cc-pages.txt" --phishing "$D/openphish.txt" "$D/phishing-db.txt"
cp "$D/brands.txt" models/brands.txt
