#!/bin/sh
# Builds a pack from today's public feeds (docs/architecture.md §13.3) and
# drafts its targets metadata, for the targets holders to sign offline
# (docs/reports/key-ceremony.md, "Each release").
#
#   sh tools/rift-pack/feeds.sh <work-dir> <version>
#
# <work-dir> is outside the repository (the feeds are real malicious URLs):
# it gets feeds/, pack/ (with Rift AI's model, models/url-model.bin) and
# targets-<version>.json. Only Phishing.Database (MIT) goes in: abuse.ch's
# terms do not allow URLhaus to be redistributed without consent
# (docs/architecture.md §13.3).
set -eu
W="$1" version="$2"
mkdir -p "$W/feeds"
rm -rf "$W/pack" && mkdir "$W/pack"
curl -fsSL --retry 3 -o "$W/feeds/active-index.json" https://api.github.com/repos/Phishing-Database/Phishing.Database/contents/phishing-links-ACTIVE
python3 -I -c '
import json, sys
for entry in json.load(open(sys.argv[1])):
    name = entry.get("name", "")
    if name.startswith("phishing-links-ACTIVE") and name.endswith(".txt"):
        print(entry["download_url"])
' "$W/feeds/active-index.json" > "$W/feeds/active-urls.txt"
: > "$W/feeds/phishing-db.txt"
while read -r url; do
  case "$url" in https://raw.githubusercontent.com/Phishing-Database/*) ;; *) echo "unexpected list address: $url" >&2; exit 1 ;; esac
  curl -fsSL --retry 3 "$url" >> "$W/feeds/phishing-db.txt"
done < "$W/feeds/active-urls.txt"
pack() { cargo run --quiet --locked --release -p rift-pack -- "$@"; }
pack feeds "$W/pack" models/url-model.bin phishing-database="$W/feeds/phishing-db.txt"
pack targets-draft "$W/pack" "$version" "$W/targets-$version.json"
