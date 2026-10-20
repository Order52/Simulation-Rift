#!/bin/sh
# Builds rift-ffi (controller) and rift-worker-ffi (isolated worker) for both
# ABIs, generates their Kotlin bindings, and builds the debug APKs: the
# controller (app), the browser (browser), and the outsider test app, which
# is signed with a throwaway key of its own. Checks that the controller has
# no WebView and that every bundled .so is aligned for 16 KB pages.
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

# Debug builds embed a signed demo threat database (Phase 3). The signing
# keys and the root stay outside the repository; only the public root and
# the signed repository go into the build directory.
keys="${RIFT_DEMO_KEYS:-${XDG_DATA_HOME:-$HOME/.local/share}/simulation-rift/demo-keys}"
intel="$here/app/build/generated-intel/intel-demo"
cargo build --quiet --locked -p rift-pack
pack_tool=target/debug/rift-pack
if [ ! -f "$keys/root.json" ]; then
  mkdir -p "$keys"
  chmod 700 "$keys"
  "$pack_tool" keys "$keys"
  "$pack_tool" root "$keys" "$keys/root.json"
fi
rm -rf "$intel" && mkdir -p "$intel/pack"
"$pack_tool" demo "$intel/pack" >/dev/null
# Minutes since the epoch: each build's release is newer than the last one.
"$pack_tool" publish "$keys/root.json" "$keys" "$intel/pack" "$intel/repo" "$(($(date +%s) / 60))" >/dev/null
cp "$keys/root.json" "$intel/root.json"
rm -rf "$intel/pack"

# The root that every build verifies imported updates against, when one is
# given: the public root.json of the production repository (its keys never
# come near this machine's builds). Without it, release builds cannot
# install updates and say so; debug builds fall back to the demo root.
production_root="$here/app/build/generated-intel-root/intel-root"
rm -rf "$production_root"
if [ -n "${RIFT_INTEL_ROOT:-}" ]; then
  mkdir -p "$production_root"
  cp "$RIFT_INTEL_ROOT" "$production_root/root.json"
fi

cd "$here"
# The controller never uses WebView (§8.4): only the browser app, under its
# own UID, may. A static check of the sources, then of the built code below.
if grep -rlE 'android\.webkit|androidx\.webkit' app/src bridge/src; then
  echo "ERROR: the controller or the bridge uses WebView" >&2; exit 1
fi
# The outsider's throwaway signing key (S24, S28), never committed.
mkdir -p build
[ -f build/outsider.jks ] || "$JAVA_HOME/bin/keytool" -genkeypair -keystore build/outsider.jks -storepass rift-outsider \
  -keypass rift-outsider -alias outsider -keyalg EC -groupname secp256r1 -validity 30 -dname "CN=Rift outsider test" >/dev/null 2>&1
"${GRADLE:-./gradlew}" --quiet assembleDebug assembleDebugAndroidTest :browser:testDebugUnitTest :app:testDebugUnitTest

# Every native library in the APK, including JNA's, must be 16 KB aligned (§8.1).
readelf="$(ls "$ANDROID_NDK_HOME"/toolchains/llvm/prebuilt/*/bin/llvm-readelf | head -1)"
apk=app/build/outputs/apk/debug/app-debug.apk
libs="$(mktemp -d)"
trap 'rm -rf "$libs"' EXIT
unzip -q -o "$apk" 'lib/*' 'classes*.dex' -d "$libs"
# No AndroidX WebView library at all, and no Rift class that touches
# android.webkit. (Unused androidx.core helpers name MimeTypeMap and
# WebView.findAddress; nothing of Rift's reaches them.)
dexdump="$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)/dexdump"
webkit="$(for dex in "$libs"/classes*.dex; do
  "$dexdump" -d "$dex" | LC_ALL=C awk '/Class descriptor/ { c = $4 } /Landroidx\/webkit\// || (/Landroid\/webkit\// && c ~ /Lorg\/simulationrift\//) { print c }'
done | sort -u)"
if [ -n "$webkit" ]; then
  echo "ERROR: WebView code in the controller APK: $webkit" >&2; exit 1
fi
for so in "$libs"/lib/*/*.so; do
  align="$("$readelf" -lW "$so" | awk '$1 == "LOAD" { print $NF }' | sort -u | tr '\n' ' ')"
  echo "$(basename "$(dirname "$so")")/$(basename "$so") $(wc -c < "$so" | tr -d ' ') bytes, LOAD alignment: $align"
  case "$align" in *0x1000\ *|*0x1000) echo "ERROR: 4 KB-aligned segment in $so" >&2; exit 1 ;; esac
done
ls -l "$apk" browser/build/outputs/apk/debug/browser-debug.apk outsider/build/outputs/apk/debug/outsider-debug.apk
