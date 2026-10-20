#!/bin/sh
# Runs the Android security tests on the one attached emulator or device and
# writes the evidence to <out-dir>:
#   android/run-tests.sh docs/reports/evidence/phase3-android-api36
# Installs the controller, the browser app and the outsider test app, and
# grants the controller and the outsider VPN consent (the system dialog a
# user would answer). Instrumented tests (SecurityTest) run inside the
# controller's main process. S13 and S14 need `adb root` (a debuggable
# emulator image), because they kill processes from outside, as a crash or
# the OS would, and read the browser app's files to cross-check its wipe.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:?usage: run-tests.sh <out-dir>}"
: "${ANDROID_HOME:=$HOME/Library/Android/sdk}"
adb="$ANDROID_HOME/platform-tools/adb"
pkg=org.simulationrift.app
browser=org.simulationrift.browser
outsider=org.simulationrift.outsider
port=8766
mkdir -p "$out"
out="$(cd "$out" && pwd)"

python3 -I "$here/fixtures/server.py" "$port" > "$out/fixture.log" 2>&1 &
server=$!
trap 'kill $server 2>/dev/null || true' EXIT
"$adb" reverse tcp:$port tcp:$port >/dev/null

{
  echo "android=$("$adb" shell getprop ro.build.version.release) sdk=$("$adb" shell getprop ro.build.version.sdk)"
  echo "security_patch=$("$adb" shell getprop ro.build.version.security_patch)"
  echo "device=$("$adb" shell getprop ro.product.model) abi=$("$adb" shell getprop ro.product.cpu.abi)"
  echo "page_size=$("$adb" shell getconf PAGE_SIZE)"
  "$adb" shell dumpsys webviewupdate | grep -E "Current WebView package" | sed 's/^ *//'
} | tr -d '\r' > "$out/device.txt"
cat "$out/device.txt"

# The controller first: it and the browser both define Rift's permission.
"$adb" install -r "$here/app/build/outputs/apk/debug/app-debug.apk" >/dev/null
"$adb" install -r "$here/browser/build/outputs/apk/debug/browser-debug.apk" >/dev/null
"$adb" install -r "$here/outsider/build/outputs/apk/debug/outsider-debug.apk" >/dev/null
"$adb" install -r "$here/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk" >/dev/null
"$adb" shell pm clear $pkg >/dev/null
"$adb" shell pm clear $browser >/dev/null
for p in $pkg $outsider; do "$adb" shell appops set $p ACTIVATE_VPN allow; done

# A slow emulator can show "System UI isn't responding" at boot, which covers
# every window the tests look at. Close such dialogs (SecurityTest does too,
# before each test) and keep a record of every ANR and crash in the run.
# The screen-reading steps below need the screen awake and open; the vault
# test (v3) sets and clears a screen-lock PIN, so dismiss any keyguard too.
close_dialogs() {
  "$adb" shell input keyevent KEYCODE_WAKEUP >/dev/null 2>&1 || true
  "$adb" shell wm dismiss-keyguard >/dev/null 2>&1 || true
  "$adb" shell am broadcast -a android.intent.action.CLOSE_SYSTEM_DIALOGS >/dev/null
}
"$adb" logcat -b events -d | tr -d '\r' | grep -E " am_(anr|crash) " > "$out/anr.txt" || true
"$adb" logcat -b events -c
close_dialogs

# RIFT_HOST_ONLY=1 skips the instrumented tests (to rerun S13/S14 alone).
if [ "${RIFT_HOST_ONLY:-0}" != 1 ]; then
  echo "== instrumented tests"
  "$adb" logcat -c
  # Process samples while the tests run, to show each isolated worker's
  # lifetime and parent (the app zygote) from outside the app.
  "$adb" shell 'while true; do t=$(date +%s.%N); ps -A -o USER,PID,PPID,NAME | grep simulationrift | sed "s/^/$t /"; sleep 0.2; done' \
    > "$out/processes.log" 2>/dev/null &
  sampler=$!
  "$adb" shell am instrument -w -r -e class $pkg.SecurityTest $pkg.test/androidx.test.runner.AndroidJUnitRunner \
    | tr -d '\r' > "$out/instrumentation.txt" || true
  { kill $sampler && wait $sampler; } 2>/dev/null || true
  "$adb" shell pkill -f "sleep 0.2" >/dev/null 2>&1 || true
  # Worker instances: name, user, first and last time seen, and whether the
  # parent was the app zygote.
  tr -d '\r' < "$out/processes.log" | awk '
    $5 ~ /_zygote$/ { zygote[$3] = 1 }
    $5 ~ /:((preview|probe)_[0-9]+|[A-Za-z.]+:worker_[0-9]+)$/ {
      n = $5; sub(/^org\.simulationrift\.app:(org\.simulationrift\.app\.)?/, "", n)
      if (!(n in first)) { first[n] = $1; user[n] = $2; parent[n] = $4; order[++count] = n }
      last[n] = $1
    }
    END {
      for (i = 1; i <= count; i++) {
        n = order[i]
        printf "%s user=%s from_app_zygote=%s seen_for_ms=%d\n", n, user[n], (parent[n] in zygote ? "yes" : "no"), (last[n] - first[n]) * 1000
      }
    }' > "$out/workers.txt"
  cat "$out/workers.txt"
  grep -E "^INSTRUMENTATION_STATUS: test=|^INSTRUMENTATION_STATUS_CODE" "$out/instrumentation.txt" \
    | paste - - | awk '{ sub("INSTRUMENTATION_STATUS: test=", ""); print }' \
    | awk '{ code=$NF; if (code == "1") next; print $1, (code == "0" ? "PASS" : "FAIL") }' > "$out/instrumented-results.txt"
  cat "$out/instrumented-results.txt"
  grep -E "^OK|^Tests run|FAILURES" "$out/instrumentation.txt" || true
  "$adb" logcat -d -s Rift:I RiftBrowser:I ActivityManager:I | tr -d '\r' \
    | grep -E " (Rift|RiftBrowser) *:|simulationrift" > "$out/logcat-instrumented.txt" || true
fi

# ---- Host-driven tests (root) -------------------------------------------------

if [ "$("$adb" shell id -u | tr -d '\r')" != 0 ]; then
  # adbd restarts as root; a busy emulator can take a while to come back,
  # and the request itself was once refused ("closed") right after the
  # instrumented run, so it is retried.
  for _ in 1 2 3; do "$adb" root >/dev/null 2>&1 && break; sleep 5; done
  i=0
  until [ "$("$adb" shell id -u 2>/dev/null | tr -d '\r')" = 0 ]; do
    i=$((i + 1))
    [ $i -lt 60 ] || { echo "adb root did not come back within 120 s" >&2; exit 1; }
    sleep 2
  done
fi
"$adb" reverse tcp:$port tcp:$port >/dev/null

# The renderer belongs to the browser app's UID.
browser_uid="$("$adb" shell cmd package list packages -U $browser | tr -d '\r' | sed -n "s/^package:$browser uid:\([0-9]*\).*/\1/p")"
app_user="u0a$((browser_uid - 10000))"

pid_of() { "$adb" shell pidof "$1" | tr -d '\r'; }

# The WebView renderer serving the browser app: an isolated process whose
# record names the browser's UID (u0aNNNiMM), not merely the newest renderer.
renderer_pid() {
  "$adb" shell dumpsys activity processes | tr -d '\r' \
    | sed -n "s/.*ProcessRecord{[0-9a-f]* \([0-9]*\):com\.google\.android\.webview:sandboxed_process[^/]*\/${app_user}i[0-9]*}.*/\1/p" | head -1
}

wait_log() { # pattern timeout_s
  i=0
  while [ $i -lt $(($2 * 4)) ]; do
    "$adb" logcat -d -s Rift:I | tr -d '\r' | grep -qE "$1" && return 0
    sleep 0.25
    i=$((i + 1))
  done
  return 1
}

open_link() {
  "$adb" shell am start -a android.intent.action.VIEW -d "$1" -n $pkg/.MainActivity >/dev/null
}

result() { echo "$1 $2${3:+ ($3)}" | tee -a "$out/host-results.txt"; }
: > "$out/host-results.txt"

# Taps the first node whose text (case-insensitive) or resource id is $2.
tap() { # text|id value
  "$adb" shell uiautomator dump /data/local/tmp/rift-ui.xml >/dev/null 2>&1 || return 1
  case $1 in text) match="text=\"$2\"" ;; id) match="resource-id=\"$2\"" ;; esac
  xy="$("$adb" shell cat /data/local/tmp/rift-ui.xml | tr -d '\r' | tr '>' '\n' | grep -iF "$match" | head -1 \
    | sed -n 's/.*bounds="\[\([0-9]*\),\([0-9]*\)\]\[\([0-9]*\),\([0-9]*\)\]".*/\1 \2 \3 \4/p' \
    | awk '{ print int(($1 + $3) / 2), int(($2 + $4) / 2) }')"
  [ -n "$xy" ] || return 1
  "$adb" shell input tap $xy
  sleep 1
}
# Scrolls the home screen by half the display's height. Fixed coordinates
# missed CI's smaller emulator screen, where S16d and S16f never scrolled.
scroll_down() {
  dims="$("$adb" shell wm size | tr -d '\r' | sed -n 's/.*: *\([0-9]*\)x\([0-9]*\)$/\1 \2/p' | tail -1)"
  w="${dims% *}" h="${dims#* }"
  "$adb" shell input swipe $((w / 2)) $((h * 3 / 4)) $((w / 2)) $((h / 4)) 300
}
# The same, retried while the screen settles (bounded).
tap_when() { i=0; until tap "$1" "$2"; do i=$((i + 1)); [ $i -lt 10 ] || return 1; sleep 1; done; }

echo "== S16d: import through the system folder picker"
# The user's path: the home screen's import button, Android's folder picker
# (DocumentsUI), and the one-time access grant. The folder holds the build's
# signed demo repository plus two files that are not part of it.
update=/sdcard/Download/rift-s16d
"$adb" shell rm -rf $update
"$adb" push "$here/app/build/generated-intel/intel-demo/repo" $update >/dev/null
"$adb" shell "echo x > $update/targets/.junk && echo x > $update/notes.txt"
"$adb" shell am force-stop $pkg
"$adb" logcat -c
"$adb" shell am start -n $pkg/.MainActivity >/dev/null
wait_log "session [0-9]+ active" 30 || true
close_dialogs
found=no
for _ in $(seq 20); do
  if tap id intel-import; then found=yes; break; fi
  scroll_down
  sleep 1
done
if [ $found = yes ] \
  && { tap text rift-s16d || { tap_when text Download && tap_when text rift-s16d; }; } \
  && tap_when text "use this folder" && tap_when text allow && wait_log "intel install:" 30; then
  line="$("$adb" logcat -d -s Rift:I | tr -d '\r' | grep -E "intel (import|install):" | sed 's/.*: intel/intel/' | tr '\n' ';')"
  case "$line" in
    *"copied 8 files, skipped 1"*"Installed demo-"*) result S16d PASS "$line" ;;
    *) result S16d FAIL "$line" ;;
  esac
else
  result S16d FAIL "could not drive the folder picker (import button found: $found)"
fi
"$adb" shell rm -rf $update

echo "== S16f: a clock behind the database is shown"
# Needs root (the step above S16d): the device clock is set two years back,
# then restored from the host's clock. The database from S16d is installed.
auto_time="$("$adb" shell settings get global auto_time | tr -d '\r')"
[ "$auto_time" = 0 ] || auto_time=1
"$adb" shell settings put global auto_time 0
"$adb" shell am force-stop $pkg
"$adb" shell date @$(($(date +%s) - 2 * 365 * 24 * 3600)) >/dev/null
"$adb" shell am start -n $pkg/.MainActivity >/dev/null
sleep 4
close_dialogs
seen=no
for _ in $(seq 20); do
  "$adb" shell uiautomator dump /data/local/tmp/rift-ui.xml >/dev/null 2>&1 \
    && "$adb" shell cat /data/local/tmp/rift-ui.xml | grep -q 'resource-id="intel-clock"' && { seen=yes; break; }
  scroll_down
  sleep 1
done
"$adb" shell date @$(date +%s) >/dev/null
"$adb" shell settings put global auto_time "${auto_time:-1}"
"$adb" shell am force-stop $pkg
if [ $seen = yes ]; then result S16f PASS "the clock warning was shown"; else result S16f FAIL "no clock warning with the clock two years back"; fi

echo "== S14: renderer crash"
"$adb" shell am force-stop $pkg
"$adb" logcat -c
open_link "http://localhost:$port/s1.html?test=s14"
wait_log "session [0-9]+ active" 15 || true
sleep 4
main_before="$(pid_of $pkg)"
browser_pid="$(pid_of $browser:web)"
renderer="$(renderer_pid)"
generation="$("$adb" logcat -d -s Rift:I | tr -d '\r' | sed -n 's/.*session \([0-9]*\) active.*/\1/p' | tail -1)"
echo "main=$main_before browser=$browser_pid renderer=$renderer generation=$generation" > "$out/s14.txt"
if [ -n "$renderer" ]; then
  "$adb" shell kill -SEGV "$renderer"
  if wait_log "session $((generation + 1)) active" 15; then
    main_after="$(pid_of $pkg)"
    "$adb" logcat -d -s Rift:I | tr -d '\r' | grep -E "renderer gone|disposed|active" >> "$out/s14.txt"
    echo "main_after=$main_after browser_after=$(pid_of $browser:web)" >> "$out/s14.txt"
    if [ "$main_after" = "$main_before" ]; then
      result S14 PASS "renderer killed; app alive (pid $main_after); session $generation torn down; $((generation + 1)) active"
    else
      result S14 FAIL "main process changed from $main_before to $main_after"
    fi
  else
    result S14 FAIL "no new session after renderer death"
  fi
else
  result S14 FAIL "renderer of $app_user not found"
fi

echo "== S13: kill during reset"
"$adb" shell am force-stop $pkg
"$adb" logcat -c
open_link "http://localhost:$port/seed.html"
wait_log "session [0-9]+ active" 15 || true
sleep 5
close_dialogs
generation="$("$adb" logcat -d -s Rift:I | tr -d '\r' | sed -n 's/.*session \([0-9]*\) active.*/\1/p' | tail -1)"
# The dump fails while the screen is not idle (a page still loading): retry, bounded.
tries=0
until "$adb" shell uiautomator dump /data/local/tmp/rift-ui.xml >/dev/null 2>&1; do
  tries=$((tries + 1))
  [ $tries -lt 5 ] || break
  sleep 2
done
bounds="$("$adb" shell cat /data/local/tmp/rift-ui.xml | tr -d '\r' | tr '>' '\n' | grep 'resource-id="reset"' | sed -n 's/.*bounds="\[\([0-9]*\),\([0-9]*\)\]\[\([0-9]*\),\([0-9]*\)\]".*/\1 \2 \3 \4/p' | head -1)"
main="$(pid_of $pkg)"
marker=/data/data/$pkg/files/rift/session.marker
if [ -n "$bounds" ] && [ -n "$main" ]; then
  set -- $bounds
  x=$((($1 + $3) / 2)); y=$((($2 + $4) / 2))
  # Tap Reset, then kill the controller as soon as the marker says RESETTING.
  "$adb" logcat -c
  # Bounded: if the tap never starts a reset, report that instead of spinning.
  "$adb" shell "input tap $x $y & end=\$((\$(date +%s) + 20)); while ! grep -q RESETTING $marker; do [ \$(date +%s) -lt \$end ] || { echo no reset within 20 s; cat $marker; exit 0; }; done; kill -9 $main; echo killed main $main; cat $marker" \
    | tr -d '\r' > "$out/s13.txt"
  # The restarted core recovers, which wipes the browser app again, before
  # presenting a session.
  "$adb" shell am start -n $pkg/.MainActivity >/dev/null
  if wait_log "recovered interrupted session $generation" 20; then
    sleep 1
    # Cross-check of the browser's own inventory (§15 step 4) from outside:
    # no file anywhere in the browser app.
    leftovers="$("$adb" shell "find /data/data/$browser /data/user_de/0/$browser /sdcard/Android/data/$browser -type f 2>/dev/null" | tr -d '\r')"
    {
      echo "generation=$generation"
      echo "after recovery: main=$(pid_of $pkg) browser=$(pid_of $browser:web)"
      "$adb" logcat -d -s Rift:I RiftBrowser:I ActivityManager:I | tr -d '\r' | grep -E "Rift|simulationrift" | grep -E "disposed|wiped|wipe|active|Start proc|has died|exiting"
      echo "after recovery: files in the browser app: ${leftovers:-none}"
    } >> "$out/s13.txt"
    if grep -q "RESETTING $generation" "$out/s13.txt" && [ -z "$leftovers" ]; then
      result S13 PASS "killed while RESETTING $generation; recovery wiped the browser app (no files) before session $((generation + 1)) started"
    else
      result S13 FAIL "marker or leftovers wrong; see s13.txt"
    fi
  else
    result S13 FAIL "no recovery logged"
  fi
else
  result S13 FAIL "could not find the Reset control or the main process"
fi

echo "== inventory"
"$adb" logcat -b events -d | tr -d '\r' | grep -E " am_(anr|crash) " >> "$out/anr.txt" || true
"$adb" shell "cd /data/data/$pkg && find . -type f | sort" | tr -d '\r' > "$out/inventory.txt"
"$adb" shell "cd /data/data/$browser && find . -type f | sort" | tr -d '\r' > "$out/inventory-browser.txt"
"$adb" unroot >/dev/null 2>&1 || true
echo "evidence in $out"
