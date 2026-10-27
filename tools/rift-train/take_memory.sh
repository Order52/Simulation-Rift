#!/bin/sh
# Takes the newest unexpired artifact called <name> (a retrain memory) into
# <dir>. Fails if GitHub cannot be asked, so a memory is never restarted
# empty by mistake; starts empty only when no such artifact exists.
#
#   sh tools/rift-train/take_memory.sh <name> <dir>     (needs GH_TOKEN, GITHUB_REPOSITORY)
set -eu
name="$1"; dir="$2"
mkdir -p "$dir"
id="$(gh api "repos/$GITHUB_REPOSITORY/actions/artifacts?name=$name&per_page=20" \
  -q '[.artifacts[] | select(.expired == false)] | sort_by(.created_at) | last | .id // empty')"
if [ -z "$id" ]; then
  echo "No $name yet: it starts empty."
  exit 0
fi
gh api "repos/$GITHUB_REPOSITORY/actions/artifacts/$id/zip" > "$dir/$name.zip"
unzip -oq "$dir/$name.zip" -d "$dir"
rm "$dir/$name.zip"
echo "$name: artifact $id, $(cat "$dir"/*.tsv | wc -l) lines."
