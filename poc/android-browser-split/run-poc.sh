#!/bin/sh
# Runs the browser-split PoC on the one attached emulator and writes the
# evidence to <out-dir>. See README.md for what each step shows.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:?usage: run-poc.sh <out-dir>}"
: "${ANDROID_HOME:=$HOME/Library/Android/sdk}"
adb="$ANDROID_HOME/platform-tools/adb"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
C=org.simulationrift.poc.controller
B=org.simulationrift.poc.browser
O=org.simulationrift.poc.outsider

python3 -I "$here/fixtures/server.py" 8780 > "$out/fixture.log" 2>&1 &
server=$!
trap 'kill $server 2>/dev/null || true' EXIT
"$adb" reverse tcp:8780 tcp:8780 >/dev/null
{
  echo "android=$("$adb" shell getprop ro.build.version.release) sdk=$("$adb" shell getprop ro.build.version.sdk) abi=$("$adb" shell getprop ro.product.cpu.abi)"
  "$adb" shell dumpsys webviewupdate | grep -E "Current WebView package" | sed 's/^ *//'
} | tr -d '\r' > "$out/device.txt"
cat "$out/device.txt"

for app in controller browser outsider; do
  "$adb" uninstall "org.simulationrift.poc.$app" >/dev/null 2>&1 || true
  "$adb" install "$here/$app/build/outputs/apk/debug/$app-debug.apk" >/dev/null
done
"$adb" logcat -c

save() { "$adb" logcat -d -s POC:I | tr -d '\r' | grep -v "^-----" >> "$out/poc.log" || true; "$adb" logcat -c; }
step() { # step <name> <run>; waits for "<name> <run> done" (unique per call)
  name="$1"; run="$2"
  "$adb" shell am start -n "$C/.PocActivity" --es step "$name" --es run "$run" >/dev/null
  i=0
  until "$adb" logcat -d -s POC:I | grep -q "POC *: $name $run done"; do
    i=$((i + 1)); [ $i -gt 150 ] && { echo "timeout in $name" >&2; return 1; }
    sleep 0.2
  done
  save
}
page() { # page <mode> <run>; waits for the page's report
  "$adb" shell am start -n "$C/.PocActivity" --es step browse --es mode "$1" --es run "$2" >/dev/null
  i=0
  until grep -q "REPORT .*\"run\":\"$2\"" "$out/fixture.log"; do
    i=$((i + 1)); [ $i -gt 100 ] && { echo "no report for $2" >&2; return 1; }
    sleep 0.2
  done
  sleep 1
}
ps_browser() { echo "== ps $1"; "$adb" shell ps -A -o USER,PID,PPID,NAME | grep -E "simulationrift|USER" | tr -d '\r'; }

echo "== setup"
"$adb" shell am start -n "$C/.PocActivity" --es step setup --es run setup >/dev/null
i=0; until "$adb" logcat -d -s POC:I | grep -q "setup setup done"; do i=$((i+1)); [ $i -gt 100 ] && exit 1; sleep 0.2; done
ports="$("$adb" logcat -d -s POC:I | grep -o 'proxy port=[0-9]* authport=[0-9]*' | tr -d '\r')"
port="$(echo "$ports" | sed 's/.*port=\([0-9]*\) auth.*/\1/')"
authport="$(echo "$ports" | sed 's/.*authport=//')"
save

echo "== 1. baseline: no proxy"
page none baseline
ps_browser "while browsing" >> "$out/ps.log"
save
echo "== 2. wipe"
step wipe after-baseline
save
ps_browser "after wipe" >> "$out/ps.log"
"$adb" shell dumpsys package $B | grep -E "stopped=" | head -1 | tr -d '\r' >> "$out/ps.log"
echo "== 3. proxy with Chromium's implicit bypass rules"
page implicit implicit
save
step wipe after-implicit
save
echo "== 4. proxy, implicit rules removed"
page proxy proxy
save
step wipe after-proxy
save
echo "== 5. proxy with auth"
page auth auth
save
echo "== 6. wipe timing x10 (page open each time)"
n=1
while [ $n -le 10 ]; do
  page proxy "timing$n"
  step wipe "timing$n"
  n=$((n + 1))
done
save
echo "== 7. deny-all VPN for the browser UID, proxy with auth"
"$adb" shell appops set $C ACTIVATE_VPN allow
step vpn-on on
page auth vpn
sleep 3
save
"$adb" shell dumpsys connectivity | grep -E "VPN|tun" | head -5 | tr -d '\r' >> "$out/ps.log"
step wipe after-vpn
step vpn-off off
echo "== 8. outsider (another app, different signer)"
"$adb" shell am start -n "$O/.OutsiderActivity" --ei port "$port" --ei authport "$authport" >/dev/null
i=0; until "$adb" logcat -d -s POC:I | grep -q "outsider done"; do i=$((i+1)); [ $i -gt 100 ] && exit 1; sleep 0.2; done
save
"$adb" shell dumpsys package $B | grep -E "userId=|appId=" | head -2 | tr -d '\r' >> "$out/ps.log"
"$adb" shell dumpsys package $C | grep -E "userId=|appId=" | head -2 | tr -d '\r' >> "$out/ps.log"
echo "evidence in $out"
