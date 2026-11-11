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
#     If the bundle's signed targets delegate the model (key-policy.md, "The
#     model key"), the model key (rift-model-publisher.pk8 in the same
#     directory) signs the model too, and RIFT_MODEL_FILE, if set, replaces
#     the bundle's model first: it must pass the app's canary, or nothing is
#     published. Without a delegation a newer model is refused, because the
#     offline targets pin the one in the bundle.
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
  delegated=no
  python3 -I -c 'import json, sys; sys.exit(0 if json.load(open(sys.argv[1]))["signed"].get("delegations", {}).get("roles") else 1)' \
    "$W/targets.json" && delegated=yes
  if [ -n "${RIFT_MODEL_FILE:-}" ]; then
    [ "$delegated" = yes ] || { echo "pages.sh: a newer model was given, but the signed targets do not delegate the model" >&2; exit 1; }
    cp "$RIFT_MODEL_FILE" "$W/pack/url-model.bin"
  fi
  model_key=""
  if [ "$delegated" = yes ]; then
    [ -f "$keys/rift-model-publisher.pk8" ] || { echo "pages.sh: the targets delegate the model, but there is no rift-model-publisher.pk8" >&2; exit 1; }
    model_key="$keys/rift-model-publisher.pk8"
  fi
  # shellcheck disable=SC2086 # the root paths have no spaces (mktemp, numbered names); $model_key is a path or nothing
  pack publish-signed "$W/targets.json" "$W/pack" "$W/repo" "$version" $roots \
    -- "$keys/rift-snapshot-publisher.pk8" "$keys/rift-timestamp-publisher.pk8" ${model_key:+-- "$model_key"}
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
