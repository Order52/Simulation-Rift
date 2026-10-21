#!/bin/sh
# Writes a test build's demo threat database (docs/architecture.md §13) to
# linux/intel-demo: a TUF repository of rift-pack's harmless demo pack and
# the root that verifies it. The manifest installs it, if present, to
# /app/share/rift/intel-demo, which the controller installs from at start.
#
# The signing keys are made in <key-dir>, which must be outside the
# repository, and are used once: this is a test database, never a release.
# Usage: demo-intel.sh <key-dir> (from the repository root)
set -eu
keys=$1
case "$(cd "$(dirname "$keys")" && pwd)/" in
  "$(pwd)"/*) echo "the keys must be outside the repository" >&2; exit 1 ;;
esac
out=linux/intel-demo
work=$keys/work
rm -rf "$out" "$work" "$keys/roles"
mkdir -p "$keys/roles" "$work/pack" "$work/datastore" "$out/repo"
cargo build --locked --release -p rift-pack
pack=target/release/rift-pack
"$pack" keys "$keys/roles"
"$pack" root "$keys/roles" "$out/root.json"
"$pack" demo "$work/pack"
"$pack" publish "$out/root.json" "$keys/roles" "$work/pack" "$out/repo" 1
cargo run --locked --release -q -p rift-update --example verify -- \
  "$out/root.json" "$out/repo" "$work/datastore"
