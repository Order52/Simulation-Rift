#!/bin/sh
# Checks the Android libraries that run in Rift's apps or their tests (every
# module's runtime classpaths in its gradle.lockfile) against OSV's
# advisories; any finding fails. Build tools in the lockfiles (Android Lint,
# the Kotlin compiler) are left out: they never ship, and their findings are
# reviewed by hand (docs/reports/dependencies.md).
#   sh android/scan-dependencies.sh <osv-scanner binary>
set -eu
scanner="$1"
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
set --
for lockfile in "$here"/*/gradle.lockfile; do
  module="$(basename "$(dirname "$lockfile")")"
  mkdir -p "$work/$module"
  # "group:name:version=configuration,…" lines whose configurations include a runtime classpath.
  grep -E '^[^#=]+=.*RuntimeClasspath' "$lockfile" > "$work/$module/gradle.lockfile"
  echo "$module: $(wc -l < "$work/$module/gradle.lockfile" | tr -d ' ') libraries on runtime classpaths"
  set -- "$@" --lockfile "$work/$module/gradle.lockfile"
done
"$scanner" scan source "$@"
