#!/bin/sh
# Check against Google Safe Browsing and URLCheck's hosts check, time-separated
# (docs/reports/check-accuracy.md, "Against Safe Browsing"). Run from the
# repository root; the work directory must be outside it (feeds and lists are
# never committed).
#
#   sh tools/rift-train/compare.sh lists <work-dir>
#     Takes what Check would have: the four threat lists, a threat database
#     pack from Phishing.Database, and OpenPhish's feed as it is now. Also a
#     sample of ordinary pages from Common Crawl.
#
#   SAFE_BROWSING_KEY=... sh tools/rift-train/compare.sh run <work-dir>
#     Hours later: OpenPhish's links whose hosts were not in it then, so no
#     list could have taken them from it, checked by Rift (with the lists as
#     taken) and by Safe Browsing (now). Prints the table.
set -eu
mode="$1"; D="$2"
T=tools/rift-train
mkdir -p "$D"
fetch() { curl -fsSL --retry 3 -o "$1" "$2"; }
OPENPHISH=https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
# The hosts of a file of links, one a line.
hosts() { python3 -I -c '
import sys, urllib.parse
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    host = urllib.parse.urlsplit(line.strip()).hostname
    if host: print(host)' "$1" | sort -u; }

case "$mode" in
lists)
  # The addresses in ThreatLists.kt.
  fetch "$D/tif.txt" https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.medium-onlydomains.txt
  fetch "$D/phishing-army.txt" https://phishing.army/download/phishing-army-domains.txt
  fetch "$D/badware.txt" https://ublockorigin.github.io/uAssets/filters/badware.min.txt
  fetch "$D/hosts" https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
  fetch "$D/phishing-db.txt" https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt
  mkdir -p "$D/pack"
  cargo run --quiet --locked --release -p rift-pack -- feeds "$D/pack" models/url-model.bin "phishing-database=$D/phishing-db.txt"
  fetch "$D/openphish-then.txt" "$OPENPHISH"
  fetch "$D/collinfo.json" https://index.commoncrawl.org/collinfo.json
  C="$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))[0]["id"])' "$D/collinfo.json")"
  case "$C" in CC-MAIN-[0-9][0-9][0-9][0-9]-[0-9][0-9]) ;; *) echo "unexpected collection: $C" >&2; exit 1 ;; esac
  fetch "$D/cc-cluster.idx" "https://data.commoncrawl.org/cc-index/collections/$C/indexes/cluster.idx"
  python3 -I $T/cc_sample.py "$C" "$D/cc-cluster.idx" "$D/ordinary.txt" 2000
  date -u +%Y-%m-%dT%H:%MZ > "$D/taken"
  ;;
run)
  fetch "$D/openphish-now.txt" "$OPENPHISH"
  hosts "$D/openphish-then.txt" > "$D/hosts-then.txt"
  python3 -I -c '
import sys, urllib.parse
seen = set(open(sys.argv[1]).read().split())
for line in open(sys.argv[2], encoding="utf-8", errors="replace"):
    link = line.strip()
    host = urllib.parse.urlsplit(link).hostname
    if host and host not in seen: print(link)' "$D/hosts-then.txt" "$D/openphish-now.txt" > "$D/new-phishing.txt"
  echo "Lists taken $(cat "$D/taken"); checked $(date -u +%Y-%m-%dT%H:%MZ): $(wc -l < "$D/new-phishing.txt" | tr -d ' ') new phishing links, $(wc -l < "$D/ordinary.txt" | tr -d ' ') ordinary pages."
  echo
  python3 -I $T/safebrowsing.py "$D/new-phishing.txt" "$D/ordinary.txt" "$D/safebrowsing.txt"
  cargo run --quiet --locked --release -p rift-train --bin compare -- --safebrowsing "$D/safebrowsing.txt" \
    models/url-model.bin "$D/pack" "$D/new-phishing.txt" "$D/ordinary.txt" \
    "tif=$D/tif.txt:wildcard" "phishing-army=$D/phishing-army.txt" "badware=$D/badware.txt:wildcard" "stevenblack=$D/hosts"
  ;;
*) echo "usage: compare.sh lists|run <work-dir>" >&2; exit 1 ;;
esac
