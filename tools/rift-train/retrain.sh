#!/bin/sh
# Retrains Rift AI on today's feeds (docs/reports/rift-ai.md, "Learning from
# new data"): downloads every source, prepares it, trains, and writes
# models/url-model.bin and models/url-model.json. Run from the repository
# root; D and P must be outside it (the feeds are real malicious URLs and
# are never committed).
#
#   sh tools/rift-train/retrain.sh <download-dir> <prepared-dir>
#
# The GitHub sample of hosting-platform sites (gh_platforms.py, ~30 min)
# needs a signed-in gh; without one the last sample in <download-dir> is
# used if there is one, and the model trains without it otherwise.
set -eu
D="$1"; P="$2"
T=tools/rift-train
mkdir -p "$D" "$P"
fetch() { curl -fsSL --retry 3 -o "$1" "$2"; }

fetch "$D/phishing-db-active.txt" https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt
# The live list: every split file in phishing-links-ACTIVE/, joined.
fetch "$D/active-index.json" https://api.github.com/repos/Phishing-Database/Phishing.Database/contents/phishing-links-ACTIVE
python3 -I -c '
import json, sys
for entry in json.load(open(sys.argv[1])):
    name = entry.get("name", "")
    if name.startswith("phishing-links-ACTIVE") and name.endswith(".txt"):
        print(entry["download_url"])
' "$D/active-index.json" > "$D/active-urls.txt"
: > "$D/phishing-db-now.txt"
while read -r url; do
  case "$url" in https://raw.githubusercontent.com/Phishing-Database/*) ;; *) echo "unexpected list address: $url" >&2; exit 1 ;; esac
  curl -fsSL --retry 3 "$url" >> "$D/phishing-db-now.txt"
done < "$D/active-urls.txt"
fetch "$D/tranco.zip" https://tranco-list.eu/top-1m.csv.zip
unzip -oq "$D/tranco.zip" -d "$D/tranco"
[ -f "$D/phiusiil/PhiUSIIL_Phishing_URL_Dataset.csv" ] || {
  fetch "$D/phiusiil.zip" "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"
  unzip -oq "$D/phiusiil.zip" -d "$D/phiusiil"
}
fetch "$D/public_suffix_list.dat" https://publicsuffix.org/list/public_suffix_list.dat

# The newest Common Crawl collection.
fetch "$D/collinfo.json" https://index.commoncrawl.org/collinfo.json
C="$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))[0]["id"])' "$D/collinfo.json")"
case "$C" in CC-MAIN-[0-9][0-9][0-9][0-9]-[0-9][0-9]) ;; *) echo "unexpected collection: $C" >&2; exit 1 ;; esac
echo "Common Crawl collection $C"
fetch "$D/cc-cluster.idx" "https://data.commoncrawl.org/cc-index/collections/$C/indexes/cluster.idx"

python3 -I $T/cc_sample.py "$C" "$D/cc-cluster.idx" "$D/cc-benign.txt" 1000
python3 -I $T/prepare.py "$D" "$P"
python3 -I $T/cc_popular.py "$C" "$D/cc-cluster.idx" "$P/tranco-hosts.txt" 3000 "$D/cc-popular.txt"
python3 -I $T/cc_platforms.py "$C" "$D/cc-cluster.idx" $T/platforms.txt "$D/cc-platforms.txt" "$P/phishing-db.txt" "$P/phiusiil-phishing.txt"
if gh auth status >/dev/null 2>&1; then
  python3 -I $T/gh_platforms.py pages.dev,web.app,firebaseapp.com "$D/gh-platforms.txt" "$P/phishing-db.txt" "$P/phiusiil-phishing.txt"
fi
python3 -I $T/prepare.py "$D" "$P"

github=""
[ -s "$P/github-platforms.txt" ] && github="--source github-platforms:benign:urls:$P/github-platforms.txt"
# shellcheck disable=SC2086 # $github is one option or none
cargo run --quiet --locked --release -p rift-train -- --bits 19 --epochs 3 --factors 4,16,0.1 \
  --out models/url-model.bin --report models/url-model.json \
  --suffixes "$P/psl-ascii.txt" --popular "$P/tranco-hosts.txt:10000" --platforms $T/platforms.txt \
  --source "phishdb:malicious:urls:$P/phishing-db.txt" --source "phishdb-2026:malicious:urls:$P/phishing-db-now.txt" \
  --source "phiusiil-phish:malicious:urls:$P/phiusiil-phishing.txt" --source "commoncrawl:benign:urls:$P/commoncrawl.txt" \
  --source "popular:benign:urls:$P/commoncrawl-popular.txt" --source "platforms:benign:urls:$P/commoncrawl-platforms.txt" \
  $github \
  --source "tranco:benign:hosts:$P/tranco-hosts.txt" --source "phiusiil-legit:benign:urls:$P/phiusiil-legit.txt" \
  > /dev/null
