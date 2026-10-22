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
# wait_log, result, close_dialogs, fault_step, passed, random_delay.
. "$here/test-lib.sh"

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

# Close dialogs a slow boot left (SecurityTest does too, before each test),
# and keep a record of every ANR and crash in the run.
"$adb" logcat -b events -d | tr -d '\r' | grep -E " am_(anr|crash) " > "$out/anr.txt" || true
"$adb" logcat -b events -c
close_dialogs

# RIFT_HOST_ONLY=1 skips the instrumented tests (to rerun the host-driven steps alone).
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
  # Status codes: 1 started, 0 passed, -4 skipped (an assumption: the fault
  # steps run only when run-tests.sh asks for them), anything else failed.
  grep -E "^INSTRUMENTATION_STATUS: test=|^INSTRUMENTATION_STATUS_CODE" "$out/instrumentation.txt" \
    | paste - - | awk '{ sub("INSTRUMENTATION_STATUS: test=", ""); print }' \
    | awk '{ code=$NF; if (code == "1") next; print $1, (code == "0" ? "PASS" : code == "-4" ? "SKIPPED" : "FAIL") }' > "$out/instrumented-results.txt"
  cat "$out/instrumented-results.txt"
  grep -E "^OK|^Tests run|FAILURES" "$out/instrumentation.txt" || true
  "$adb" logcat -d -s Rift:I RiftBrowser:I ActivityManager:I | tr -d '\r' \
    | grep -E " (Rift|RiftBrowser) *:|simulationrift" > "$out/logcat-instrumented.txt" || true
  # Screenshots some tests take of the trusted UI (w1).
  "$adb" pull /sdcard/Android/data/$pkg/files/evidence/. "$out/screens" >/dev/null 2>&1 || true
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

open_link() {
  "$adb" shell am start -a android.intent.action.VIEW -d "$1" -n $pkg/.MainActivity >/dev/null
}

: > "$out/host-results.txt"

# Taps the first node whose text (case-insensitive) or resource id is $2.
tap() { # text|id value
  # The dump's own message is kept: it says why a dump failed (for example
  # "could not get idle state"), which the failure records below include.
  "$adb" shell uiautomator dump /data/local/tmp/rift-ui.xml > "$out/last-dump.txt" 2>&1 || return 1
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
# A shown keyboard (a focused address field) covers the lower half, where
# the swipe starts, so the page stayed put (S16d, Phase 4). BACK is sent
# only while Android reports the keyboard shown; otherwise it would leave Rift.
scroll_down() {
  if "$adb" shell dumpsys input_method | tr -d '\r' | grep -q "mInputShown=true"; then
    "$adb" shell input keyevent KEYCODE_BACK
    sleep 1
  fi
  dims="$("$adb" shell wm size | tr -d '\r' | sed -n 's/.*: *\([0-9]*\)x\([0-9]*\)$/\1 \2/p' | tail -1)"
  w="${dims% *}" h="${dims#* }"
  "$adb" shell input swipe $((w / 2)) $((h * 3 / 4)) $((w / 2)) $((h / 4)) 300
}
# tap, but only once the node's centre is in the upper three quarters of the
# screen: a node at the bottom edge was found, and the tap landed on the
# navigation bar (S16d on API 36).
tap_upper() { # text|id value
  "$adb" shell uiautomator dump /data/local/tmp/rift-ui.xml > "$out/last-dump.txt" 2>&1 || return 1
  case $1 in text) match="text=\"$2\"" ;; id) match="resource-id=\"$2\"" ;; esac
  xy="$("$adb" shell cat /data/local/tmp/rift-ui.xml | tr -d '\r' | tr '>' '\n' | grep -iF "$match" | head -1 \
    | sed -n 's/.*bounds="\[\([0-9]*\),\([0-9]*\)\]\[\([0-9]*\),\([0-9]*\)\]".*/\1 \2 \3 \4/p' \
    | awk '{ print int(($1 + $3) / 2), int(($2 + $4) / 2) }')"
  [ -n "$xy" ] || return 1
  h="$("$adb" shell wm size | tr -d '\r' | sed -n 's/.*: *[0-9]*x\([0-9]*\)$/\1/p' | tail -1)"
  [ "${xy#* }" -le $((h * 3 / 4)) ] || return 1
  "$adb" shell input tap $xy
  sleep 1
}
# The same, retried while the screen settles (bounded).
tap_when() { i=0; until tap "$1" "$2"; do i=$((i + 1)); [ $i -lt 10 ] || return 1; sleep 1; done; }

# RIFT_FAULT_ONLY=1 skips S16d, S16f, S14, S13 and H1 (to rerun the fault rounds alone).
if [ "${RIFT_FAULT_ONLY:-0}" != 1 ]; then
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
  # The import button is on the Security tab (2.5).
  tap_when id tab-security || true
  found=no
  for _ in $(seq 20); do
    if tap_upper id intel-import; then found=yes; break; fi
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
    # What the screen showed, to tell a layout problem from a stuck screen.
    "$adb" exec-out screencap -p > "$out/s16d-screen.png" 2>/dev/null || true
    "$adb" shell cat /data/local/tmp/rift-ui.xml > "$out/s16d-ui.xml" 2>/dev/null || true
    result S16d FAIL "could not drive the folder picker (import button found: $found; last dump: $(tr -d '\r' < "$out/last-dump.txt" | tail -1))"
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
  tap_when id tab-security || true
  seen=no
  for _ in $(seq 20); do
    "$adb" shell uiautomator dump /data/local/tmp/rift-ui.xml >/dev/null 2>&1 \
      && "$adb" shell cat /data/local/tmp/rift-ui.xml | grep -q 'resource-id="intel-clock"' && { seen=yes; break; }
    scroll_down
    sleep 1
  done
  if [ $seen = no ]; then
    # As for S16d. Without S16d's database there is nothing to warn about.
    "$adb" exec-out screencap -p > "$out/s16f-screen.png" 2>/dev/null || true
    "$adb" shell cat /data/local/tmp/rift-ui.xml > "$out/s16f-ui.xml" 2>/dev/null || true
  fi
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
fi

# ---- Recents snapshot (Phase 7) -----------------------------------------------
# H1: the snapshot Android stores for the browser's task when it leaves the
# screen shows no page (setRecentsScreenshotEnabled(false), API 33+). Only
# root can read it. The controller's test h1 opens a striped page and waits;
# this takes a screenshot of the page (the control), presses Home, and hands
# the test both images to decode.
if [ "${RIFT_FAULT_ONLY:-0}" != 1 ]; then
  echo "== H1: the browser's recents snapshot"
  sdk="$("$adb" shell getprop ro.build.version.sdk | tr -d '\r')"
  if [ "$sdk" -lt 33 ]; then
    result H1 SKIPPED "API $sdk; the browser keeps recents snapshots out from API 33"
  else
    "$adb" logcat -c
    "$adb" shell am instrument -w -r -e class "$pkg.SecurityTest#h1_theRecentsSnapshotShowsNoPage" -e host h1 \
      $pkg.test/androidx.test.runner.AndroidJUnitRunner | tr -d '\r' > "$out/h1.txt" &
    runner=$!
    task="" why="the page was not shown"
    if wait_log "result h1: page shown" 90; then
      sleep 2
      task="$("$adb" shell dumpsys activity recents | tr -d '\r' \
        | sed -n "s/.*Recent #[0-9]*: Task{[0-9a-f]* #\([0-9]*\) type=standard A=[0-9]*:$browser}.*/\1/p" | head -1)"
      why="the browser's task is not in recents"
    fi
    snaps=/data/system_ce/0/snapshots
    if [ -n "$task" ]; then
      # Any snapshot from before this run is removed, so the one read is new.
      "$adb" shell rm -f "$snaps/$task.jpg" "$snaps/${task}_reduced.jpg" "$snaps/$task.proto"
      "$adb" shell screencap -p /data/local/tmp/rift-h1-page.png
      "$adb" shell input keyevent KEYCODE_HOME
      i=0
      until "$adb" shell test -s "$snaps/$task.jpg"; do
        i=$((i + 1))
        [ $i -lt 30 ] || break
        sleep 0.5
      done
      why="no snapshot stored for the browser's task $task"
    fi
    if [ -n "$task" ] && "$adb" shell test -s "$snaps/$task.jpg"; then
      why="the check failed"
      mkdir -p "$out/screens"
      "$adb" pull /data/local/tmp/rift-h1-page.png "$out/screens/h1-page-on-screen.png" >/dev/null
      "$adb" pull "$snaps/$task.jpg" "$out/screens/h1-recents-snapshot.jpg" >/dev/null
      owner="$("$adb" shell stat -c %u:%g /data/data/$pkg/files | tr -d '\r')"
      h1=/data/data/$pkg/files/h1
      # `ready` last: the test reads the images once it appears.
      "$adb" shell "mkdir -p $h1 && cp /data/local/tmp/rift-h1-page.png $h1/page.png && cp $snaps/$task.jpg $h1/snapshot.jpg \
        && rm /data/local/tmp/rift-h1-page.png && chown -R $owner $h1 && chmod -R go-rwx $h1 && restorecon -R $h1 >/dev/null \
        && touch $h1/ready && chown $owner $h1/ready && restorecon $h1/ready"
    fi
    wait $runner || true
    line="$("$adb" logcat -d -s Rift:I | tr -d '\r' | sed -n 's/.*result h1: //p' | tail -1)"
    if grep -q "^OK (1 test)" "$out/h1.txt"; then
      result H1 PASS "task $task: $line"
    else
      result H1 FAIL "${task:+task $task: }$why; $line; see h1.txt"
    fi
  fi
fi

# ---- Accessibility services (Phase 7) -----------------------------------------
# H4: an accessibility service that is not a tool for users with disabilities
# (the outsider's, as screen-reading malware is) reads nothing in Rift's
# windows (WindowGuard, API 34+). No instrumentation runs meanwhile, as
# UiAutomation would suppress the service. The outsider's own window is the
# control: the service must read it.
if [ "${RIFT_FAULT_ONLY:-0}" != 1 ]; then
  echo "== H4: a non-tool accessibility service reads nothing of Rift"
  sdk="$("$adb" shell getprop ro.build.version.sdk | tr -d '\r')"
  if [ "$sdk" -lt 34 ]; then
    result H4 SKIPPED "API $sdk; Rift's windows are kept from non-tool services from API 34"
  else
    services="$("$adb" shell settings get secure enabled_accessibility_services | tr -d '\r')"
    enabled="$("$adb" shell settings get secure accessibility_enabled | tr -d '\r')"
    "$adb" shell am force-stop $pkg
    "$adb" logcat -c
    "$adb" shell settings put secure enabled_accessibility_services $outsider/$outsider.OutsiderAccessibility
    "$adb" shell settings put secure accessibility_enabled 1
    sleep 3
    front() { "$adb" shell dumpsys window | tr -d '\r' | sed -n 's/.*mCurrentFocus=Window{[0-9a-f]* u0 \([^ }]*\)}.*/\1/p' | head -1; }
    # A fresh task: an outsider window still closing would take the intent
    # and close with it (H3 on CI).
    "$adb" shell am start --activity-clear-task -n $outsider/.OutsiderActivity --ez field true >/dev/null
    sleep 4
    shown="outsider: $(front)"
    "$adb" shell am start -n $pkg/.MainActivity >/dev/null
    wait_log "session [0-9]+ active" 30 || true
    sleep 4
    shown="$shown; home: $(front)"
    open_link "http://localhost:$port/sign-in.html"
    sleep 8
    shown="$shown; browser: $(front)"
    "$adb" shell input keyevent KEYCODE_HOME
    sleep 2
    if [ "$services" = null ] || [ -z "$services" ]; then
      "$adb" shell settings delete secure enabled_accessibility_services >/dev/null
    else
      "$adb" shell settings put secure enabled_accessibility_services "$services"
    fi
    "$adb" shell settings put secure accessibility_enabled "${enabled:-0}"
    "$adb" shell am force-stop $outsider
    { echo "in front: $shown"; "$adb" logcat -d -s rift-outsider-a11y:I | tr -d '\r'; } > "$out/h4.txt"
    read_rift="$(grep -cE "window org\.simulationrift\.(app|browser): [1-9][0-9]* texts" "$out/h4.txt" || true)"
    if ! grep -qE "window $outsider: [1-9][0-9]* texts:.*Outsider text" "$out/h4.txt"; then
      result H4 FAIL "the control failed: the service read nothing of the outsider's window; $shown; see h4.txt"
    elif ! echo "$shown" | grep -q "home: $pkg/" || ! echo "$shown" | grep -q "browser: $browser/"; then
      result H4 FAIL "Rift's windows were not in front: $shown"
    elif [ "$read_rift" != 0 ]; then
      result H4 FAIL "the service read Rift's windows $read_rift times; see h4.txt"
    else
      result H4 PASS "it read the outsider's window and nothing of Rift's home screen or browser ($shown)"
    fi
  fi
fi

# ---- Fault injection (Phase 7) ------------------------------------------------
# The controller is killed (SIGKILL, as the OS or a crash would) at a random
# moment while it installs the threat database (f3); after each kill, f4
# checks what is left. RIFT_FAULT_ROUNDS rounds (default 8); f-<step>-<round>.txt holds each step's output.

# Kills the controller once the step logged $1 (within $2 s), after a random delay below $3 ms.
kill_after() { # pattern timeout_s max_delay_ms
  wait_log "$1" "$2" || return 1
  delay="$(random_delay "$3")"
  sleep "$delay"
  "$adb" shell kill -9 "$(pid_of $pkg)" || return 1
}
# Appends this round's step results to fault.log (logcat is cleared each round).
save_fault_log() { "$adb" logcat -d -s Rift:I | tr -d '\r' | grep -E "result f[0-9]" >> "$out/fault.log" || true; }
: > "$out/fault.log"

rounds="${RIFT_FAULT_ROUNDS:-8}"
echo "== F3/F4: kill while installing the threat database ($rounds rounds)"
# The first round is killed after the install finished, which measures it;
# later rounds are killed at a random moment within that time.
round=1 failures=0 summary="" install_ms=3000
while [ $round -le $rounds ]; do
  "$adb" logcat -c
  fault_step f3_installUntilKilled install > "$out/f-install-$round.txt" &
  runner=$!
  if [ $round -eq 1 ]; then
    started=0
    # Killed once the install reported success, so F4 requires it installed.
    if wait_log "result f3: outcome after [0-9]* ms: Installed" 120; then
      install_ms="$("$adb" logcat -d -s Rift:I | tr -d '\r' | sed -n 's/.*result f3: outcome after \([0-9]*\) ms.*/\1/p' | tail -1)"
      delay=after-install expect=installed
      "$adb" shell kill -9 "$(pid_of $pkg)" && started=1
    fi
  else
    started=0 expect=either
    kill_after "result f3: installing" 120 "$install_ms" && started=1
  fi
  wait $runner || true
  if [ $started -eq 1 ]; then
    fault_step f4_theDatabaseIsWholeAfterTheKill check-intel expect "$expect" > "$out/f-check-intel-$round.txt"
    save_fault_log
    if passed "$out/f-check-intel-$round.txt"; then
      summary="$summary $round:killed-$delay"
    else
      failures=$((failures + 1)); summary="$summary $round:CHECK-FAILED"
    fi
  else
    failures=$((failures + 1)); summary="$summary $round:NOT-STARTED"
  fi
  round=$((round + 1))
done
if [ $failures -eq 0 ]; then result F4 PASS "$rounds kills while installing (one install: ${install_ms} ms);$summary"; else result F4 FAIL "$failures of $rounds rounds;$summary"; fi

echo "== F5/F6: a full disk"
# f5 prepares the database and a download, then logs "result f5:
# ready"; root fills /data up to what apps may use (df's Available). The
# blocks ext4 reserves for the system (resgid 1065) stay free, so Android
# itself keeps working. f5 tries Rift's writes on the full disk, then logs
# "free the space"; the filler is removed, f5 retries the cleanup, and f6
# checks what is left after a restart.
fill=/data/local/tmp/rift-fill
trap 'kill $server 2>/dev/null || true; "$adb" shell rm -f "$fill"-* >/dev/null 2>&1 || true' EXIT
# Kilobytes on /data that df counts as available to apps.
app_free_k() { "$adb" shell df -k /data | tr -d '\r' | awk 'NR == 2 { print $4 }'; }
"$adb" logcat -c
fault_step f5_aFullDiskFailsCleanly full > "$out/f-full.txt" &
runner=$!
filled=""
if wait_log "result f5: ready" 180; then
  # Others write meanwhile, so what is left is filled again (bounded). ext4
  # keeps a pool (16 MiB on the emulator) that df counts but no allocation
  # gets, so the disk is full once fallocate reports no space.
  n=1
  while [ $n -le 5 ] && "$adb" shell fallocate -l $(($(app_free_k) * 1024)) "$fill-$n" 2>> "$out/f-fill.txt"; do
    n=$((n + 1))
  done
  filled="df shows $(app_free_k) KiB available"
  wait_log "result f5: free the space" 120 || true
fi
"$adb" shell rm -f "$fill"-*
wait $runner || true
trap 'kill $server 2>/dev/null || true' EXIT
save_fault_log
outcomes="$(grep -E "result f5: (full|install|download|reset|after freeing)" "$out/fault.log" | sed 's/.*result f5: //' | tr '\n' ';')"
if [ -z "$filled" ]; then
  result F6 FAIL "f5 did not get ready; see f-full.txt"
else
  fault_step f6_wholeAfterTheFullDisk check-full > "$out/f-check-full.txt"
  save_fault_log
  if passed "$out/f-full.txt" && passed "$out/f-check-full.txt"; then
    result F6 PASS "filled, $filled; $outcomes"
  else
    result F6 FAIL "on the full disk: $(passed "$out/f-full.txt" && echo passed || echo FAILED); after: $(passed "$out/f-check-full.txt" && echo passed || echo FAILED); $outcomes"
  fi
fi

echo "== inventory"
"$adb" logcat -b events -d | tr -d '\r' | grep -E " am_(anr|crash) " >> "$out/anr.txt" || true
"$adb" shell "cd /data/data/$pkg && find . -type f | sort" | tr -d '\r' > "$out/inventory.txt"
"$adb" shell "cd /data/data/$browser && find . -type f | sort" | tr -d '\r' > "$out/inventory-browser.txt"
"$adb" unroot >/dev/null 2>&1 || true
echo "evidence in $out"
