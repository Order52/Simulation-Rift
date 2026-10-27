#!/bin/sh
# The threat database's update host on GitHub Pages (docs/reports/key-ceremony.md,
# "GitHub Pages as the update host"). Run from the repository root.
#
#   sh tools/rift-pack/pages.sh bundle <targets.json> <pack-dir> <bundle.tar.gz> <root.json>...
#     After the targets holders signed (offline): the signed targets, the
#     pack and the whole root chain (oldest first), for an intel-<version>
#     pre-release. Nothing in it is secret; the host serves it all.
#
#   sh tools/rift-pack/pages.sh publish <bundle.tar.gz> <online-key-dir> <site-dir>
#     The workflow's step (intel-pages.yml), every 5 days: signs a new
#     snapshot and timestamp with the online keys only (rift-snapshot-publisher.pk8,
#     rift-timestamp-publisher.pk8), checks the result as the app would from
#     the oldest root, and lays it out under <site-dir>/rift/.
set -eu
mode="$1"; shift
pack() { cargo run --quiet --locked --release -p rift-pack -- "$@"; }

case "$mode" in
bundle)
  targets="$1" packdir="$2" out="$3"; shift 3
  [ $# -ge 1 ] || { echo "pages.sh bundle: give the root chain, oldest first" >&2; exit 1; }
  B="$(mktemp -d)"
  mkdir "$B/roots"
  cp "$targets" "$B/targets.json"
  cp -R "$packdir" "$B/pack"
  n=0
  for root in "$@"; do
    n=$((n + 1))
    cp "$root" "$B/roots/$n.root.json"
  done
  tar -czf "$out" -C "$B" targets.json pack roots
  rm -rf "$B"
  echo "bundle: $out ($n roots); publish it with: gh release create intel-<version> --prerelease --latest=false $out"
  ;;
publish)
  bundle="$1" keys="$2" site="$3"
  W="$(mktemp -d)"
  tar -xzf "$bundle" -C "$W"
  for f in targets.json pack roots/1.root.json; do
    [ -e "$W/$f" ] || { echo "pages.sh: the bundle has no $f" >&2; exit 1; }
  done
  # Minutes since 1970: higher at every run, as snapshot and timestamp versions must be.
  version=$(( $(date -u +%s) / 60 ))
  roots="$(ls "$W/roots" | sort -n | sed "s|^|$W/roots/|")"
  # shellcheck disable=SC2086 # the root paths have no spaces (mktemp, numbered names)
  pack publish-signed "$W/targets.json" "$W/pack" "$W/repo" "$version" $roots \
    -- "$keys/rift-snapshot-publisher.pk8" "$keys/rift-timestamp-publisher.pk8"
  cargo run --quiet --locked -p rift-update --example verify -- "$W/roots/1.root.json" "$W/repo" "$W/datastore"
  rm -rf "$site"
  mkdir -p "$site/rift"
  cp -R "$W/repo/." "$site/rift/"
  touch "$site/.nojekyll"
  printf '%s\n' '<!doctype html><meta charset="utf-8"><title>Rift updates</title>' \
    '<p>The signed threat database for <a href="https://github.com/Order52/Simulation-Rift">Rift</a>. The app fetches it from <code>rift/</code>; there is nothing to open here.</p>' \
    > "$site/index.html"
  rm -rf "$W"
  echo "published snapshot and timestamp v$version to $site/rift"
  ;;
*) echo "usage: pages.sh bundle|publish …" >&2; exit 1 ;;
esac
