#!/bin/sh
# Builds the native worker library (both ABIs) and the debug APK, then checks
# that every bundled .so is aligned for 16 KB page-size devices.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
: "${ANDROID_HOME:=$HOME/Library/Android/sdk}"
: "${ANDROID_NDK_HOME:=$(ls -d "$ANDROID_HOME"/ndk/* | sort -V | tail -1)}"
: "${JAVA_HOME:=/opt/homebrew/opt/openjdk@21}"
export ANDROID_HOME ANDROID_NDK_HOME JAVA_HOME

cd "$here/.."
cargo ndk -t arm64-v8a -t x86_64 -P 30 -o "$here/app/src/main/jniLibs" build --release -p android-native

readelf="$(ls "$ANDROID_NDK_HOME"/toolchains/llvm/prebuilt/*/bin/llvm-readelf | head -1)"
for so in "$here"/app/src/main/jniLibs/*/librift_poc_native.so; do
  align="$("$readelf" -lW "$so" | awk '$1 == "LOAD" { print $NF }' | sort -u | tr '\n' ' ')"
  echo "$(basename "$(dirname "$so")") $(wc -c < "$so" | tr -d ' ') bytes, LOAD alignment: $align"
  case "$align" in *0x1000*) echo "ERROR: 4 KB-aligned segment in $so" >&2; exit 1 ;; esac
done

cd "$here"
"${GRADLE:-./gradlew}" --quiet assembleDebug
ls -l app/build/outputs/apk/debug/app-debug.apk
