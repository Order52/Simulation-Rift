#!/bin/sh
# Builds rift-ffi (controller) and rift-worker-ffi (isolated worker) for both
# ABIs, generates their Kotlin bindings, builds the debug APK, and checks that
# every bundled .so is aligned for 16 KB pages.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
: "${ANDROID_HOME:=$HOME/Library/Android/sdk}"
: "${ANDROID_NDK_HOME:=$(ls -d "$ANDROID_HOME"/ndk/* | sort -V | tail -1)}"
: "${JAVA_HOME:=/opt/homebrew/opt/openjdk@21}"
export ANDROID_HOME ANDROID_NDK_HOME JAVA_HOME

cd "$here/.."
cargo ndk -t arm64-v8a -t x86_64 -P 30 -o "$here/app/src/main/jniLibs" build --release --locked -p rift-ffi -p rift-worker-ffi
# Bindings come from UniFFI's metadata in an unstripped host build of the same
# source (release stripping removes it). The generated code checks the API
# checksums against the Android library when it loads, so a mismatch fails.
cargo build --quiet --locked -p rift-ffi -p rift-worker-ffi
rm -rf "$here/app/build/generated-rift/kotlin"
for lib in rift_ffi rift_worker_ffi; do
  host_lib="$(ls target/debug/lib$lib.dylib target/debug/lib$lib.so 2>/dev/null | head -1)"
  cargo run --quiet --locked -p rift-ffi --features bindgen --bin uniffi-bindgen -- generate \
    --library "$host_lib" --language kotlin --no-format \
    --out-dir "$here/app/build/generated-rift/kotlin"
done

cd "$here"
# Only :browser code may use WebView: loading it in the main process creates
# app_webview/ outside any session (Phase 2, finding 12). A static check, so
# it catches direct use, not every path that might load the provider.
for f in $(grep -rlE 'android\.webkit|androidx\.webkit' app/src/main/kotlin app/src/debug/kotlin); do
  case "$(basename "$f")" in
    BrowserActivity.kt | WebViewSandbox.kt) ;;
    *) echo "ERROR: $f uses WebView outside :browser" >&2; exit 1 ;;
  esac
done
for f in $(grep -rl 'WebViewSandbox\.facts(' app/src/main/kotlin app/src/debug/kotlin); do
  [ "$(basename "$f")" = BrowserActivity.kt ] || { echo "ERROR: $f asks WebView for its facts outside :browser" >&2; exit 1; }
done
"${GRADLE:-./gradlew}" --quiet assembleDebug assembleDebugAndroidTest

# Every native library in the APK, including JNA's, must be 16 KB aligned (§8.1).
readelf="$(ls "$ANDROID_NDK_HOME"/toolchains/llvm/prebuilt/*/bin/llvm-readelf | head -1)"
apk=app/build/outputs/apk/debug/app-debug.apk
libs="$(mktemp -d)"
trap 'rm -rf "$libs"' EXIT
unzip -q -o "$apk" 'lib/*' -d "$libs"
for so in "$libs"/lib/*/*.so; do
  align="$("$readelf" -lW "$so" | awk '$1 == "LOAD" { print $NF }' | sort -u | tr '\n' ' ')"
  echo "$(basename "$(dirname "$so")")/$(basename "$so") $(wc -c < "$so" | tr -d ' ') bytes, LOAD alignment: $align"
  case "$align" in *0x1000\ *|*0x1000) echo "ERROR: 4 KB-aligned segment in $so" >&2; exit 1 ;; esac
done
ls -l "$apk"
