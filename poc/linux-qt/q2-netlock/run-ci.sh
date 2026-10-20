#!/bin/sh
# PoC Q2 (Phase 5): runs org.simulationrift.QtNetLock in both cases and
# probes the engine's processes from the host while the page is open.
#   proxy   the page must load through the controller (app exit 0), every
#           direct attempt from the sub-sandbox must be blocked, and the
#           renderers must still be sandboxed by the engine (host probe 0)
#   direct  without the proxy the engine must fail to load the page (exit 3)
# Exits nonzero unless both cases give the expected result.
# Usage (inside dbus-run-session and xvfb-run): sh run-ci.sh <out-dir>
set -u
here="$(cd "$(dirname "$0")" && pwd)"
out=$1
mkdir -p "$out"
rm -f "$out/unexpected"
python3 -I -m http.server --bind 127.0.0.1 8765 --directory "$here/../page" > "$out/http.log" 2>&1 &
server=$!
trap 'kill $server 2>/dev/null' EXIT
sleep 1
fail() { echo "$1" >> "$out/unexpected"; echo "UNEXPECTED: $1"; }
for case in proxy direct; do
  flatpak run org.simulationrift.QtNetLock "$case" 15 > "$out/$case-app.txt" 2>&1 &
  app=$!
  i=0
  until grep -q "^probe: ready" "$out/$case-app.txt" || [ $i -ge 150 ]; do sleep 1; i=$((i + 1)); done
  python3 -I "$here/../host-probe.py" > "$out/$case-host.txt" 2>&1
  verdict=$?
  wait $app
  appstatus=$?
  echo "## $case: app exit $appstatus, host probe exit $verdict"
  grep -E "^(probe|host|controller):" "$out/$case-app.txt"
  cat "$out/$case-host.txt"
  if grep -q ": REACHED" "$out/$case-app.txt"; then fail "$case: the sub-sandbox reached the network"; fi
  if [ "$case" = proxy ]; then
    [ $appstatus -eq 0 ] || fail "proxy: page did not load (exit $appstatus)"
    grep -q "^controller: allowed GET http://rift-probe.test:8765/" "$out/$case-app.txt" || fail "proxy: no request reached the controller"
    [ $verdict -eq 0 ] || fail "proxy: renderers not sandboxed by the engine (host probe exit $verdict)"
  else
    [ $appstatus -eq 3 ] || fail "direct: expected a failed load (exit 3), got $appstatus"
  fi
  echo
done | tee "$out/summary.txt"
if [ -e "$out/unexpected" ]; then
  cat "$out/unexpected" >> "$out/summary.txt"
  exit 1
fi
