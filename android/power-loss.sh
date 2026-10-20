#!/bin/sh
# Power-loss rounds (Phase 7), in the manner of F1–F4 in run-tests.sh: the
# emulator's qemu is killed (SIGKILL) at a random moment while the controller
# keeps files into the vault (P2) or installs the threat database (P4), and
# after a cold boot f2 or f4 checks what is left.
#   android/power-loss.sh <out-dir> <avd>
# Unlike a kill of the controller, this loses whatever the guest kernel had
# not yet handed to its disk, as a power cut would. The emulator's drives use
# qemu's cache=unsafe, which skips only the host's own fsync: each guest
# flush still writes qemu's caches (qcow2 metadata included) to the host, so
# what the guest flushed survives while the host keeps running.
#
# Needs the APKs built (android/build.sh), a debuggable image (adb root) and
# no emulator or device attached. Each round cold-boots the emulator (about a
# minute); RIFT_POWER_ROUNDS sets the rounds of each kind (default 4). The
# rounds change the AVD's data disk; copy it first to keep it as it was.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:?usage: power-loss.sh <out-dir> <avd>}"
avd="${2:?usage: power-loss.sh <out-dir> <avd>}"
: "${ANDROID_HOME:=$HOME/Library/Android/sdk}"
adb="$ANDROID_HOME/platform-tools/adb"
emulator="$ANDROID_HOME/emulator/emulator"
pkg=org.simulationrift.app
browser=org.simulationrift.browser
port=8766
rounds="${RIFT_POWER_ROUNDS:-4}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
. "$here/test-lib.sh"

if "$adb" get-state >/dev/null 2>&1; then
  echo "a device is attached; stop it first, as every round boots $avd" >&2
  exit 1
fi

python3 -I "$here/fixtures/server.py" "$port" > "$out/fixture.log" 2>&1 &
server=$!
trap 'kill $server 2>/dev/null || true' EXIT

# Cold-boots the emulator (no snapshot) and readies it for the controller.
boot() {
  "$emulator" -avd "$avd" -no-window -no-audio -no-boot-anim -no-snapshot >> "$out/emulator.log" 2>&1 &
  ready
}

# Waits for Android to finish booting, then readies it for the controller.
ready() {
  "$adb" wait-for-device
  i=0
  until [ "$("$adb" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; do
    i=$((i + 1))
    if [ $i -gt 150 ]; then echo "$avd did not boot; see emulator.log" >&2; exit 1; fi
    sleep 2
  done
  "$adb" root >/dev/null
  "$adb" wait-for-device
  "$adb" reverse tcp:$port tcp:$port >/dev/null
  close_dialogs
}

# The power cut: qemu gets SIGKILL, and adb loses the device.
cut_power() {
  pid="$(pgrep -f "qemu-system.*-avd $avd( |\$)" | head -1)"
  if [ -z "$pid" ]; then echo "no qemu process for $avd" >&2; exit 1; fi
  kill -9 "$pid"
  while kill -0 "$pid" 2>/dev/null; do sleep 0.2; done
  "$adb" wait-for-disconnect
}

boot
{
  echo "android=$("$adb" shell getprop ro.build.version.release) sdk=$("$adb" shell getprop ro.build.version.sdk)"
  echo "device=$("$adb" shell getprop ro.product.model) abi=$("$adb" shell getprop ro.product.cpu.abi)"
  echo "data=$("$adb" shell mount | grep ' /data ' | head -1)"
} | tr -d '\r' > "$out/device.txt"
cat "$out/device.txt"
"$adb" install -r "$here/app/build/outputs/apk/debug/app-debug.apk" >/dev/null
"$adb" install -r "$here/browser/build/outputs/apk/debug/browser-debug.apk" >/dev/null
"$adb" install -r "$here/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk" >/dev/null
"$adb" shell pm clear $pkg >/dev/null
"$adb" shell pm clear $browser >/dev/null
"$adb" shell appops set $pkg ACTIVATE_VPN allow
# Android writes its package list and app-op settings a while after a change,
# so a cut soon after this setup lost the installs (the first run). A clean
# reboot writes them.
"$adb" reboot
"$adb" wait-for-disconnect
ready
: > "$out/host-results.txt"
: > "$out/power.log"
# Appends the step results of the boot so far to power.log.
save_power_log() { "$adb" logcat -d -s Rift:I | tr -d '\r' | grep -E "result f[0-9]" >> "$out/power.log" || true; }

echo "== P1/P2: power cut while keeping into the vault ($rounds rounds)"
fault_step f0_prepareTheVault prepare > "$out/p-prepare.txt"
if passed "$out/p-prepare.txt"; then
  round=1 failures=0 summary=""
  while [ $round -le $rounds ]; do
    "$adb" logcat -c
    # Streamed, so the host holds every line logged before the cut.
    "$adb" logcat -s Rift:I > "$out/p-keep-log-$round.txt" 2>&1 &
    stream=$!
    fault_step f1_keepUntilKilled keep > "$out/p-keep-$round.txt" 2>&1 &
    runner=$!
    if wait_log "result f1: keeping from" 120; then
      delay="$(random_delay 3000)"
      sleep "$delay"
      cut_power
      wait $runner || true
      # The stream ends with the device; it is stopped in case it did not.
      sleep 1
      kill $stream 2>/dev/null || true
      wait $stream || true
      log="$(tr -d '\r' < "$out/p-keep-log-$round.txt")"
      from="$(echo "$log" | sed -n 's/.*result f1: keeping from \([0-9]*\).*/\1/p' | tail -1)"
      kept="$(echo "$log" | sed -n 's/.*result f1: kept \([0-9]*\).*/\1/p' | tail -1)"
      kept="${kept:-$from}"
      echo "round $round: cut ${delay}s in, $kept keeps seen" >> "$out/power.log"
      boot
      # A keep logged after the cut's moment could not reach the host: one more unseen.
      fault_step f2_theVaultIsWholeAfterTheKill check-vault kept "$kept" unseen 2 > "$out/p-check-vault-$round.txt"
      save_power_log
      if passed "$out/p-check-vault-$round.txt"; then
        summary="$summary $round:cut-${delay}s,kept-$kept"
      else
        failures=$((failures + 1)); summary="$summary $round:CHECK-FAILED"
      fi
    else
      wait $runner || true
      kill $stream 2>/dev/null || true
      failures=$((failures + 1)); summary="$summary $round:NOT-STARTED"
    fi
    round=$((round + 1))
  done
  if [ $failures -eq 0 ]; then result P2 PASS "$rounds power cuts while keeping;$summary"; else result P2 FAIL "$failures of $rounds rounds;$summary"; fi
else
  result P2 FAIL "the vault could not be prepared; see p-prepare.txt"
fi

echo "== P3/P4: power cut while installing the threat database ($rounds rounds)"
# The first round is cut as soon as the install reports success: the database
# must then be there after the boot. Later rounds are cut at a random moment
# in the first 1.5 s (one install takes about 0.3–1.2 s on the API 35 emulator).
round=1 failures=0 summary=""
while [ $round -le $rounds ]; do
  "$adb" logcat -c
  fault_step f3_installUntilKilled install > "$out/p-install-$round.txt" 2>&1 &
  runner=$!
  if [ $round -eq 1 ]; then
    started="$(wait_log "result f3: outcome after [0-9]* ms: Installed" 180 && echo yes || echo no)"
    delay=after-install expect=installed when="right after the install"
  else
    started="$(wait_log "result f3: installing" 120 && echo yes || echo no)"
    delay="$(random_delay 1500)" expect=either
    when="${delay}s into the install"
    sleep "$delay"
  fi
  if [ "$started" = yes ]; then
    cut_power
    wait $runner || true
    echo "round $round: cut $when" >> "$out/power.log"
    boot
    fault_step f4_theDatabaseIsWholeAfterTheKill check-intel expect "$expect" > "$out/p-check-intel-$round.txt"
    save_power_log
    if passed "$out/p-check-intel-$round.txt"; then
      summary="$summary $round:cut-${delay}"
    else
      failures=$((failures + 1)); summary="$summary $round:CHECK-FAILED"
    fi
  else
    wait $runner || true
    failures=$((failures + 1)); summary="$summary $round:NOT-STARTED"
  fi
  round=$((round + 1))
done
if [ $failures -eq 0 ]; then result P4 PASS "$rounds power cuts while installing;$summary"; else result P4 FAIL "$failures of $rounds rounds;$summary"; fi

"$adb" logcat -b events -d | tr -d '\r' | grep -E " am_(anr|crash) " > "$out/anr.txt" || true
"$adb" emu kill >/dev/null
echo "evidence in $out"
