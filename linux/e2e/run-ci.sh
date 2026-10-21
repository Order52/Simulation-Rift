#!/bin/sh
# End-to-end test of the Linux app (docs/architecture.md §9) in Flatpak.
#   intel    the demo threat database is installed, its rules compiled by
#            a worker that reported seccomp and Landlock
#   page     a public page loads through the controller's proxy; seen from
#            the host, the browser host has no network and every renderer
#            is sandboxed by the engine; SIGTERM destroys the session and
#            the browser's files
#   loopback a loopback address goes to the controller's proxy (Chromium's
#            implicit bypass is removed), which refuses it: nothing loads,
#            and nothing reaches the local server
#   download a download is refused to the engine, re-fetched by the controller
#            into quarantine, and scanned by a confined worker, which finds
#            the demo database's marker in it
#   ui       driven through accessibility while that file is quarantined:
#            create the vault, preview the file, keep it, open and cancel
#            the export warning, export it through the file chooser portal
#            (the app has no filesystem access of its own), allow a local
#            host, lock, refuse a wrong passphrase, unlock, delete
#            (ui-check.py); the exported copy holds the downloaded bytes
#   crash    killing the browser host ends and destroys the session
#   recover  killing the controller leaves no browser host running, and the
#            next start destroys the session it left
#   switch   the engine's sandbox switch in the app's environment does not
#            give an unsandboxed page
# Exits nonzero if anything unexpected happened.
# Usage: xvfb-run -a dbus-run-session -- sh run-ci.sh <out-dir> (the bus
# must start inside the display, so that the portal it activates knows it)
set -u
here=$(cd "$(dirname "$0")" && pwd)
out=$1
mkdir -p "$out"
rm -f "$out/unexpected"
app=org.simulationrift.Rift
appdir=$HOME/.var/app/$app
page=https://example.com/

# The accessibility bus, for ui-check.py (also started on demand).
[ -x /usr/libexec/at-spi-bus-launcher ] && /usr/libexec/at-spi-bus-launcher --launch-immediately > /dev/null 2>&1 &
python3 -I -m http.server --bind 127.0.0.1 8765 --directory "$here" > "$out/local-server.log" 2>&1 &
server=$!
trap 'kill $server 2>/dev/null' EXIT
sleep 1

fail() { echo "$1" >> "$out/unexpected"; echo "UNEXPECTED: $1"; }
# count <file> <pattern>
count() { grep -c -- "$2" "$1" 2>/dev/null || true; }
# wait_count <file> <pattern> <n> <seconds>: true once it occurs n times
wait_count() {
  i=0
  until [ "$(count "$1" "$2")" -ge "$3" ] || [ $i -ge "$4" ]; do sleep 1; i=$((i + 1)); done
  [ "$(count "$1" "$2")" -ge "$3" ]
}
# launch <case> <address> [flatpak run options]
launch() {
  name=$1 address=$2
  shift 2
  flatpak run "$@" $app "$address" > "$out/$name.log" 2>&1 &
  runner=$!
}
# finish: SIGTERM the controller (it destroys the session), then its status
finish() {
  pid=$(pgrep -x rift | head -1)
  [ -n "$pid" ] && kill -TERM "$pid"
  wait $runner
  status=$?
}
# clean <case>: no browser host left, no browser files, no session left
clean() {
  sleep 1
  if pgrep -x rift-browser > /dev/null || pgrep -x QtWebEngineProc > /dev/null; then
    fail "$1: a browser process is still running"
  fi
  left=$(find "$appdir/sandbox" -mindepth 1 -maxdepth 1 2>/dev/null)
  [ -z "$left" ] || fail "$1: browser files left: $left"
  # rift-core keeps each generation's directory in sessions/sessions.
  sessions=$(find "$appdir/data/rift/sessions/sessions" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
  [ -z "$sessions" ] || fail "$1: session directories left: $sessions"
}
loaded() { wait_count "$out/$1.log" "^rift-browser: page loaded" 2 "$2"; }

{
  echo "## page"
  launch page "$page"
  wait_count "$out/page.log" "^rift: demo threat database .* installed" 1 120 \
    || fail "intel: the demo threat database was not installed"
  if loaded page 150; then
    sudo -n python3 -I "$here/host-check.py" > "$out/page-host.txt" 2>&1
    verdict=$?
    cat "$out/page-host.txt"
    [ $verdict -eq 0 ] || fail "page: host check exit $verdict"
  else
    fail "page: the page did not load"
  fi
  finish
  grep -E "^rift(-browser)?:" "$out/page.log"
  [ $status -eq 0 ] || fail "page: controller exit $status"
  grep -q "^rift: session [0-9]*: renderer sandboxed" "$out/page.log" || fail "page: no renderer check"
  # The window's QML loads without a warning (they name the file and line).
  if grep -q "Main.qml:[0-9]" "$out/page.log"; then fail "page: the window's QML has errors"; fi
  grep -q "^rift: session [0-9]*: proxy allowed [1-9]" "$out/page.log" || fail "page: nothing went through the proxy"
  grep -q "^rift: session [0-9]* destroyed" "$out/page.log" || fail "page: the session was not destroyed"
  clean page
  echo

  echo "## loopback"
  launch loopback http://127.0.0.1:8765/
  wait_count "$out/loopback.log" "^rift-browser: page did not load" 1 150 || fail "loopback: no refusal seen"
  sleep 5
  finish
  grep -E "^rift(-browser)?:" "$out/loopback.log"
  [ "$(count "$out/loopback.log" "^rift-browser: page loaded")" -le 1 ] || fail "loopback: a page loaded"
  grep -q "^rift: session [0-9]*: proxy allowed 0, refused [1-9]" "$out/loopback.log" \
    || fail "loopback: the proxy did not refuse it"
  if grep -q "GET" "$out/local-server.log"; then fail "loopback: a request reached the local server"; fi
  clean loopback
  echo

  echo "## download"
  # httpbin echoes the query into the body and sends it as an attachment.
  launch download "https://httpbin.org/response-headers?Content-Disposition=attachment%3B%20filename%3Ddemo.txt&marker=RIFT-DEMO-MARKER" \
    --env=QT_LINUX_ACCESSIBILITY_ALWAYS_ON=1
  exported=$HOME/rift-e2e-export.txt
  rm -f "$exported"
  if wait_count "$out/download.log" "^rift: session [0-9]*: a download was quarantined" 1 150; then
    echo "### ui"
    python3 -I -B "$here/ui-check.py" --export "$exported" > "$out/ui.txt" 2>&1 || fail "ui: $(tail -1 "$out/ui.txt")"
    cat "$out/ui.txt"
  else
    fail "download: nothing was quarantined"
  fi
  finish
  grep -E "^rift(-browser)?:" "$out/download.log"
  grep -q "a download was quarantined; scan: \(Known malicious\|Suspicious\)" "$out/download.log" \
    || fail "download: the scan did not find the demo marker"
  grep -q "^rift: vault: kept a [0-9]*-byte file" "$out/download.log" || fail "ui: nothing was kept"
  grep -q "^rift: vault locked" "$out/download.log" || fail "ui: the vault was not locked"
  kept=$(sed -n 's/^rift: vault: kept a \([0-9]*\)-byte file$/\1/p' "$out/download.log" | head -1)
  grep -q "^rift: vault: exported a ${kept:-x}-byte file" "$out/download.log" || fail "ui: no export of the kept file"
  if [ -f "$exported" ] && [ "$(wc -c < "$exported")" -eq "${kept:-0}" ] && grep -q RIFT-DEMO-MARKER "$exported"; then
    echo "exported copy: $(wc -c < "$exported") bytes, with the marker"
  else
    fail "ui: the exported copy is missing or differs"
  fi
  rm -f "$exported"
  clean download
  echo

  echo "## crash"
  launch crash "$page"
  loaded crash 150 || fail "crash: the page did not load"
  pkill -KILL -x rift-browser
  wait_count "$out/crash.log" "^rift: session [0-9]* destroyed" 1 30 || fail "crash: the session was not destroyed"
  clean crash
  finish
  grep -E "^rift(-browser)?:" "$out/crash.log"
  [ $status -eq 0 ] || fail "crash: controller exit $status"
  echo

  echo "## recover"
  launch recover "$page"
  loaded recover 150 || fail "recover: the page did not load"
  kill -KILL "$(pgrep -x rift | head -1)"
  wait $runner
  sleep 10
  if pgrep -x rift-browser > /dev/null; then fail "recover: the browser host outlived the controller"; fi
  echo "left after the kill: $(find "$appdir/sandbox" -mindepth 1 -maxdepth 1 2>/dev/null | tr '\n' ' ')"
  launch recover-next "$page"
  wait_count "$out/recover-next.log" "^rift: session [0-9]* from an earlier run destroyed" 1 60 \
    || fail "recover: the earlier session was not destroyed"
  loaded recover-next 150 || fail "recover: the next page did not load"
  finish
  grep -E "^rift(-browser)?:" "$out/recover.log" "$out/recover-next.log"
  clean recover
  echo

  echo "## switch"
  launch switch "$page" --env=QTWEBENGINE_DISABLE_SANDBOX=1 --env=QTWEBENGINE_CHROMIUM_FLAGS=--no-sandbox
  i=0
  until grep -q "refusing to start" "$out/switch.log" || [ "$(count "$out/switch.log" "^rift-browser: page loaded")" -ge 2 ] || [ $i -ge 150 ]; do
    sleep 1
    i=$((i + 1))
  done
  if grep -q "refusing to start" "$out/switch.log"; then
    echo "the switch reached the browser host, which refused to start"
  elif [ "$(count "$out/switch.log" "^rift-browser: page loaded")" -ge 2 ]; then
    echo "the switch did not reach the browser host; checking its renderers"
    sudo -n python3 -I "$here/host-check.py" > "$out/switch-host.txt" 2>&1 || fail "switch: host check failed"
    cat "$out/switch-host.txt"
  else
    fail "switch: neither refused nor loaded"
  fi
  finish
  grep -E "^rift(-browser)?:" "$out/switch.log"
  clean switch
  echo
} 2>&1 | tee "$out/summary.txt"

if [ -e "$out/unexpected" ]; then
  cat "$out/unexpected" >> "$out/summary.txt"
  exit 1
fi
