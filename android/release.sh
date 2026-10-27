#!/bin/sh
# Builds the release APK: one file, arm64, minified, signed.
#
# The sealed browser is built and signed first, then embedded in Rift's APK
# (docs/architecture.md §8.10), and Rift is signed with the same key: Android
# updates an app only to a build signed like it, and Rift installs the
# browser only if it carries Rift's own certificate.
#
# The signing key is made here once, in a directory outside the repository
# (RIFT_RELEASE_KEYS, default ~/.local/share/simulation-rift/release-keys,
# mode 700, the password in a mode 600 file beside the key). A key made by
# this script belongs to one person's device; a distributed release needs the
# key policy of docs/reports/key-policy.md. Never commit the directory. Whoever
# holds the key can sign updates for installs that trust it: keep a copy offline,
# because a lost key means the app has to be uninstalled to install another.
#
# Output: android/build/release/rift-<version>.apk (and its SHA-256).
#
# The weekly release workflow (.github/workflows/release.yml) sets
# RIFT_VERSION_NAME and RIFT_VERSION_CODE (otherwise gradle.properties' are
# used), RIFT_RELEASE_REQUIRE_KEY (never make a key: fail without one) and
# RIFT_RELEASE_CERT (the certificate's SHA-256 every release must carry).
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
: "${ANDROID_HOME:=$HOME/Library/Android/sdk}"
: "${JAVA_HOME:=/opt/homebrew/opt/openjdk@21}"
export ANDROID_HOME JAVA_HOME PATH="$JAVA_HOME/bin:$HOME/.cargo/bin:$PATH"
build_tools="$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)"
keys="${RIFT_RELEASE_KEYS:-${XDG_DATA_HOME:-$HOME/.local/share}/simulation-rift/release-keys}"
store="$keys/release.jks"
out="$here/build/release"

if [ ! -f "$store" ]; then
  if [ -n "${RIFT_RELEASE_REQUIRE_KEY:-}" ]; then
    echo "release: no signing key in $keys" >&2
    exit 1
  fi
  umask 077
  mkdir -p "$keys"
  chmod 700 "$keys"
  # 32 random bytes in hex: no characters that a shell or keytool treats specially.
  # One line with its newline: apksigner reads a password file by line.
  od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > "$keys/password"
  echo >> "$keys/password"
  chmod 600 "$keys/password"
  keytool -genkeypair -keystore "$store" -storepass:file "$keys/password" -keypass:file "$keys/password" \
    -alias rift -keyalg RSA -keysize 4096 -validity 9125 -dname "CN=Rift release" >/dev/null
  echo "release: made a new signing key in $keys (keep a copy offline; it is not in the repository)"
fi

version="${RIFT_VERSION_NAME:-$(sed -n 's/^rift.versionName=//p' "$here/gradle.properties")}"
props=""
[ -z "${RIFT_VERSION_NAME:-}" ] || props="-Prift.versionName=$RIFT_VERSION_NAME -Prift.versionCode=${RIFT_VERSION_CODE:?RIFT_VERSION_CODE is needed with RIFT_VERSION_NAME}"
rm -rf "$out"
mkdir -p "$out"
cd "$here"
./gradlew -q :browser:assembleRelease -Prift.abis=arm64-v8a $props
sign() { # unsigned signed
  "$build_tools/zipalign" -f 4 "$1" "$out/aligned.apk"
  "$build_tools/apksigner" sign --ks "$store" --ks-pass "file:$keys/password" --out "$2" "$out/aligned.apk"
  rm -f "$out/aligned.apk" "$2.idsig"
}
sign browser/build/outputs/apk/release/browser-release-unsigned.apk "$out/browser-signed.apk"
./gradlew -q :app:assembleRelease -Prift.abis=arm64-v8a -Prift.signedBrowserApk="$out/browser-signed.apk" $props
sign app/build/outputs/apk/release/app-release-unsigned.apk "$out/rift-$version.apk"
# The same app for stores (IzzyOnDroid), whose updates replace Rift's own (§8.11).
./gradlew -q :app:assembleRelease -Prift.abis=arm64-v8a -Prift.signedBrowserApk="$out/browser-signed.apk" -Prift.store=true $props
sign app/build/outputs/apk/release/app-release-unsigned.apk "$out/rift-store-$version.apk"

# The two apps must carry the same certificate, or the install would be refused.
# The first signer's digest, whichever way this apksigner labels it ("Signer #1",
# or "Signer (minSdkVersion=…, maxSdkVersion=…)" for each SDK range).
cert() { "$build_tools/apksigner" verify --print-certs "$1" | sed -n 's/.*[Ss]igner.* certificate SHA-256 digest: //p' | head -1; }
[ "$(cert "$out/rift-$version.apk")" = "$(cert "$out/browser-signed.apk")" ] || { echo "release: Rift and its browser are signed differently" >&2; exit 1; }
# An update signed by another key would not install over the last release.
[ -z "${RIFT_RELEASE_CERT:-}" ] || [ "$(cert "$out/rift-$version.apk")" = "$RIFT_RELEASE_CERT" ] || {
  echo "release: not signed with the release certificate: found '$(cert "$out/rift-$version.apk")' ($(basename "$build_tools")), expected $RIFT_RELEASE_CERT" >&2
  "$build_tools/apksigner" verify --print-certs "$out/rift-$version.apk" | grep -i 'certificate SHA-256' >&2
  exit 1
}
"$build_tools/apksigner" verify --min-sdk-version 30 "$out/rift-$version.apk"
# Nothing of a debug build: no debuggable flag, no test workers.
manifest="$("$build_tools/aapt2" dump xmltree --file AndroidManifest.xml "$out/rift-$version.apk")"
if echo "$manifest" | grep -qE 'debuggable|ProbeWorkerService|FilterCheckingPreviewService|HangingScanService|HangingPreviewService|CrashingPreviewService|OversizedPreviewService|GarbagePreviewService|ReplayingPreviewService|NoSeccompPreviewService|UnconfinedPreviewService'; then
  echo "release: the manifest holds debug components" >&2
  exit 1
fi
[ "$(cert "$out/rift-store-$version.apk")" = "$(cert "$out/rift-$version.apk")" ] || { echo "release: the store build is signed differently" >&2; exit 1; }
"$build_tools/apksigner" verify --min-sdk-version 30 "$out/rift-store-$version.apk"
(cd "$out" && shasum -a 256 "rift-$version.apk" | tee "rift-$version.apk.sha256")
(cd "$out" && shasum -a 256 "rift-store-$version.apk" > "rift-store-$version.apk.sha256")
echo "release: $out/rift-$version.apk ($(du -h "$out/rift-$version.apk" | cut -f1)), certificate $(cert "$out/rift-$version.apk")"
