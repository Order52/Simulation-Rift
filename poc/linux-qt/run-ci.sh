#!/bin/sh
# PoC Q1 (Phase 5): runs the installed org.simulationrift.QtProbe Flatpak
# under the current display and session bus, and probes its engine
# processes from the host. Two cases:
#   sandbox    as shipped: every renderer must be sandboxed (host probe exit 0)
#   disabled   QTWEBENGINE_DISABLE_SANDBOX=1, the engine's escape hatch: the
#              host probe must report the renderers NOT sandboxed (exit 1;
#              the negative control for the check Rift will make)
# Exits nonzero unless both cases give the expected result.
# Usage (inside dbus-run-session and xvfb-run): sh run-ci.sh <out-dir>
set -u
here="$(cd "$(dirname "$0")" && pwd)"
out=$1
mkdir -p "$out"
python3 -I -m http.server --bind 127.0.0.1 8765 --directory "$here/page" > "$out/http.log" 2>&1 &
server=$!
trap 'kill $server 2>/dev/null' EXIT
rm -f "$out/unexpected"
sleep 1
for case in sandbox disabled; do
  env=""
  [ "$case" = disabled ] && env="--env=QTWEBENGINE_DISABLE_SANDBOX=1"
  # shellcheck disable=SC2086
  flatpak run $env org.simulationrift.QtProbe http://127.0.0.1:8765/ 15 > "$out/$case-app.txt" 2>&1 &
  app=$!
  i=0
  until grep -q "^probe: ready" "$out/$case-app.txt" || [ $i -ge 120 ]; do sleep 1; i=$((i + 1)); done
  python3 -I "$here/host-probe.py" > "$out/$case-host.txt" 2>&1
  verdict=$?
  wait $app
  appstatus=$?
  expected=0
  [ "$case" = disabled ] && expected=1
  [ $appstatus -eq 0 ] && [ $verdict -eq $expected ] || echo "$case" >> "$out/unexpected"
  echo "## $case: app exit $appstatus, host probe exit $verdict (expected $expected)"
  grep "^probe:" "$out/$case-app.txt"
  cat "$out/$case-host.txt"
  echo
done | tee "$out/summary.txt"
if [ -e "$out/unexpected" ]; then
  echo "unexpected result: $(tr '\n' ' ' < "$out/unexpected")" | tee -a "$out/summary.txt"
  exit 1
fi
