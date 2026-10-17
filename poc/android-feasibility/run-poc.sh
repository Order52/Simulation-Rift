#!/bin/sh
# Runs Phase 0 PoCs A1–A7 against the one connected device/emulator and
# collects raw evidence into <out-dir>. Build first with ./build.sh.
# Usage: run-poc.sh <out-dir>
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
out="$1"
mkdir -p "$out"
: "${ANDROID_HOME:=$HOME/Library/Android/sdk}"
adb="$ANDROID_HOME/platform-tools/adb"
pkg=org.simulationrift.poc
apk="$here/app/build/outputs/apk/debug/app-debug.apk"

"$adb" wait-for-device
"$adb" root >/dev/null 2>&1 || true # google_apis images allow root for /proc inspection
"$adb" wait-for-device
{
  echo "device.api=$("$adb" shell getprop ro.build.version.sdk | tr -d '\r')"
  echo "device.release=$("$adb" shell getprop ro.build.version.release | tr -d '\r')"
  echo "device.abi=$("$adb" shell getprop ro.product.cpu.abi | tr -d '\r')"
  echo "device.page_size=$("$adb" shell getconf PAGE_SIZE | tr -d '\r')"
  echo "device.fingerprint=$("$adb" shell getprop ro.build.fingerprint | tr -d '\r')"
  echo "device.security_patch=$("$adb" shell getprop ro.build.version.security_patch | tr -d '\r')"
  echo "apk.bytes=$(wc -c < "$apk" | tr -d ' ')"
} > "$out/device.txt"

"$adb" install -r -g "$apk" >/dev/null
"$adb" shell pm clear "$pkg" >/dev/null
"$adb" reverse tcp:8765 tcp:8765 >/dev/null
python3 -I "$here/fixtures/server.py" 8765 2> "$out/server.log" &
server=$!
trap 'kill "$server" 2>/dev/null || true' EXIT
sleep 1

# run <result-name> <am start extras…>: launch one test and wait for its result.
run() {
  name="$1"
  shift
  "$adb" shell run-as "$pkg" rm -f "files/results/$name.txt"
  # No -W: on API 30 it never returns for an activity that finishes without
  # drawing. The result file is the completion signal.
  "$adb" shell am start -n "$pkg/.MainActivity" "$@" >/dev/null
  i=0
  while [ "$i" -lt 480 ]; do # 4 min: the lifecycle test waits on process deaths
    if "$adb" shell run-as "$pkg" test -f "files/results/$name.txt"; then
      "$adb" exec-out run-as "$pkg" cat "files/results/$name.txt" > "$out/$name.txt"
      return 0
    fi
    sleep 0.5
    i=$((i + 1))
  done
  echo "TIMEOUT waiting for $name" > "$out/$name.txt"
}

# --- A4–A7: isolated worker -------------------------------------------------
run worker --es test worker
for png in pdf_file pdf_memfd; do
  "$adb" exec-out run-as "$pkg" cat "files/results/$png.png" > "$out/$png.png" 2>/dev/null || true
done

# --- Worker lifecycle: cold start, signals, in-process timeout, stuck worker ---
run lifecycle --es test lifecycle
{
  echo "# isolated processes still running after the lifecycle test (PID USER NAME)"
  "$adb" shell ps -A -o PID,USER,NAME | grep -E " u0_i[0-9]+ .*$pkg" || echo "(none)"
} > "$out/lifecycle-leftovers.txt"

# --- A1: renderer sandbox, inspected from outside while the page is live ---
"$adb" shell run-as "$pkg" rm -f files/results/a1.txt
"$adb" shell am start -n "$pkg/.MainActivity" --es test browse --es mode a1 >/dev/null
sleep 5
{
  echo "# processes (PID USER LABEL NAME)"
  "$adb" shell ps -A -o PID,USER,LABEL,NAME | grep -E "sandboxed_process|$pkg" || true
  renderer="$("$adb" shell ps -A -o PID,NAME | grep sandboxed_process | tail -1 | awk '{print $1}')"
  echo "# renderer pid=$renderer /proc status"
  [ -n "$renderer" ] && "$adb" shell cat "/proc/$renderer/status" | grep -E '^(Uid|Seccomp|Seccomp_filters|NoNewPrivs|CapEff)' || true
} > "$out/a1-renderer.txt"
i=0
while [ "$i" -lt 60 ] && ! "$adb" shell run-as "$pkg" test -f files/results/a1.txt; do sleep 0.5; i=$((i + 1)); done
"$adb" exec-out run-as "$pkg" cat files/results/a1.txt > "$out/a1.txt" 2>/dev/null || echo TIMEOUT > "$out/a1.txt"

# --- A2: disposal ----------------------------------------------------------
run inventory-initial --es test inventory --es label initial
run a2-seed-round1 --es test browse --es mode a2-seed --es label round1
run a2-probe-same-session --es test browse --es mode a2-probe --es label same-session
run inventory-seeded --es test inventory --es label seeded
run reset-round1 --es test reset --es label round1
run inventory-after-reset --es test inventory --es label after-reset
run a2-probe-after-reset --es test browse --es mode a2-probe --es label after-reset
# Interrupted reset: the controller dies after killing :browser, before deleting.
run a2-seed-round2 --es test browse --es mode a2-seed --es label round2
"$adb" shell am start -n "$pkg/.MainActivity" --es test reset-crash >/dev/null
sleep 3
run inventory-after-crash --es test inventory --es label after-crash
run recover-round2 --es test recover --es label round2
run inventory-after-recovery --es test inventory --es label after-recovery
run a2-probe-after-recovery --es test browse --es mode a2-probe --es label after-recovery

# --- A3: download capture ------------------------------------------------------
run a3 --es test browse --es mode a3
"$adb" exec-out sh -c "logcat -d -s RiftPoC" > "$out/logcat.txt" 2>/dev/null || true
echo "evidence written to $out"
