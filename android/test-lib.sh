# Helpers shared by run-tests.sh and power-loss.sh (sourced, not run).
# The caller sets $adb, $pkg (the controller's package) and $out (the
# evidence directory).

# Waits until the controller's log has a line matching $1 (within $2 s).
wait_log() { # pattern timeout_s
  i=0
  while [ $i -lt $(($2 * 4)) ]; do
    "$adb" logcat -d -s Rift:I | tr -d '\r' | grep -qE "$1" && return 0
    sleep 0.25
    i=$((i + 1))
  done
  return 1
}

# Records a host-driven result: ID, PASS or FAIL, and the evidence.
result() { echo "$1 $2${3:+ ($3)}" | tee -a "$out/host-results.txt"; }

# A slow emulator can show "System UI isn't responding" at boot, which covers
# every window the tests look at. The screen must be awake and open; the
# vault test (v3) sets and clears a screen-lock PIN, so any keyguard goes too.
close_dialogs() {
  "$adb" shell input keyevent KEYCODE_WAKEUP >/dev/null 2>&1 || true
  "$adb" shell wm dismiss-keyguard >/dev/null 2>&1 || true
  "$adb" shell am broadcast -a android.intent.action.CLOSE_SYSTEM_DIALOGS >/dev/null
}

# Runs fault step $2 (test method $1) in the controller; extra `-e` pairs follow.
fault_step() { # method step [key value]…
  method=$1 step=$2
  shift 2
  extra=""
  while [ $# -ge 2 ]; do extra="$extra -e $1 $2"; shift 2; done
  "$adb" shell am instrument -w -r -e class "$pkg.SecurityTest#$method" -e fault "$step" $extra \
    $pkg.test/androidx.test.runner.AndroidJUnitRunner | tr -d '\r'
}
passed() { grep -q "^OK (1 test)" "$1"; }
# A uniformly random delay in [0, $1) milliseconds, as seconds for sleep.
random_delay() { od -An -N2 -tu2 /dev/urandom | awk -v max="$1" 'NR == 1 { printf "%.3f", ($1 % max) / 1000 }'; }
