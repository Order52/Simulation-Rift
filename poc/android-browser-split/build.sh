#!/bin/sh
# Builds the three PoC apps. The outsider is signed with a throwaway key
# generated here, under build/ (ignored by git), so it is a different signer.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
: "${ANDROID_HOME:=$HOME/Library/Android/sdk}"
: "${JAVA_HOME:=/opt/homebrew/opt/openjdk@21}"
export ANDROID_HOME JAVA_HOME
cd "$here"
mkdir -p build
[ -f build/outsider.jks ] || "$JAVA_HOME/bin/keytool" -genkeypair -keystore build/outsider.jks -storepass poc-outsider \
  -keypass poc-outsider -alias outsider -keyalg EC -groupname secp256r1 -validity 30 -dname "CN=Rift PoC outsider" >/dev/null 2>&1
"${GRADLE:-./gradlew}" --quiet assembleDebug
ls -l */build/outputs/apk/debug/*.apk
