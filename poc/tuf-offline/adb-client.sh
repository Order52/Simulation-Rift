#!/bin/sh
# Runs the tuf-offline client on the one attached Android device, so that
# run-scenarios.sh exercises the Android build of tough/aws-lc-rs (PoC X2):
#   run-scenarios.sh poc/tuf-offline/adb-client.sh
# Paths given to --root/--repo/--datastore/--expect are mirrored under $dev and
# pushed before each call. Other arguments (such as hostile target names like
# /etc/passwd) are passed through unchanged.
# Requires: RIFT_X2_BINARY = Android build of tuf-offline (cargo ndk ... -p tuf-offline).
set -eu
: "${ANDROID_HOME:=$HOME/Library/Android/sdk}"
adb="$ANDROID_HOME/platform-tools/adb"
dev=/data/local/tmp/rift-x2

if [ "$("$adb" shell "test -x $dev/tuf-offline && echo yes" | tr -d '\r')" != yes ]; then
  "$adb" shell mkdir -p "$dev" >/dev/null
  "$adb" push "${RIFT_X2_BINARY:?set RIFT_X2_BINARY to the Android tuf-offline binary}" "$dev/tuf-offline" >/dev/null 2>&1
  "$adb" shell chmod 755 "$dev/tuf-offline"
fi

command="$dev/tuf-offline"
mirror_next=no
for arg in "$@"; do
  if [ "$mirror_next" = yes ]; then
    if [ -e "$arg" ]; then
      "$adb" shell mkdir -p "'$dev$(dirname "$arg")'" >/dev/null
      "$adb" push "$arg" "$dev$(dirname "$arg")/" >/dev/null 2>&1
    fi
    arg="$dev$arg"
  fi
  case "$arg" in
    --root | --repo | --datastore | --expect) mirror_next=yes ;;
    *) mirror_next=no ;;
  esac
  command="$command '$arg'"
done
"$adb" shell "$command"
