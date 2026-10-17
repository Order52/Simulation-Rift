#!/bin/sh
# PoC X2 scenarios: publish TUF repositories with tuftool, then check that the
# tough-based client accepts the valid one and rejects every attack variant.
# Usage: run-scenarios.sh <path-to-tuf-offline-binary> [tuftool]
set -eu
client="$1"
tuftool="${2:-tuftool}"
wrk="$(mktemp -d)"
trap 'rm -rf "$wrk"' EXIT
failures=0

# --- maintainer side: keys, root, repository v1 -----------------------------
make_root() { # $1 = dir
  mkdir -p "$1/keys"
  "$tuftool" root init "$1/root.json"
  "$tuftool" root expire "$1/root.json" 'in 52 weeks'
  for role in root snapshot targets timestamp; do
    "$tuftool" root set-threshold "$1/root.json" "$role" 1
  done
  "$tuftool" root gen-rsa-key "$1/root.json" "$1/keys/key.pem" --role root
  for role in snapshot targets timestamp; do
    "$tuftool" root add-key "$1/root.json" -k "$1/keys/key.pem" --role "$role"
  done
  "$tuftool" root sign "$1/root.json" -k "$1/keys/key.pem"
}
publish() { # $1 = cmd (create|update) $2 = version $3 = outdir $4 = timestamp expiry
  extra=""
  [ "$1" = update ] && extra="--metadata-url file://$3/metadata"
  # shellcheck disable=SC2086
  "$tuftool" "$1" --root "$wrk/root/root.json" --key "$wrk/root/keys/key.pem" \
    --add-targets "$wrk/input" \
    --targets-expires 'in 3 weeks' --targets-version "$2" \
    --snapshot-expires 'in 3 weeks' --snapshot-version "$2" \
    --timestamp-expires "$4" --timestamp-version "$2" \
    --outdir "$3" $extra
}

make_root "$wrk/root" >/dev/null
mkdir -p "$wrk/input"
head -c 65536 /dev/urandom > "$wrk/input/pack.bin"
publish create 1 "$wrk/repo" 'in 1 week' >/dev/null
cp -R "$wrk/repo" "$wrk/repo-v1"
cp "$wrk/input/pack.bin" "$wrk/pack-v1.bin"

# --- client side --------------------------------------------------------------
echo "| scenario | expected | client output | result |"
echo "|---|---|---|---|"
check() { # $1 = scenario, $2 = expected (OK|REJECTED), rest = client args
  name="$1"; expected="$2"; shift 2
  out="$("$client" "$@" 2>&1 || true)"
  case "$out" in
    "$expected"*) verdict=pass ;;
    *) verdict="**FAIL**"; failures=$((failures + 1)) ;;
  esac
  printf '| %s | %s | `%s` | %s |\n' "$name" "$expected" "$(printf '%s' "$out" | tr '|' '/' | cut -c1-160)" "$verdict"
}
load() { # $1 = repo, $2 = datastore, $3 = root
  echo load --root "${3:-$wrk/root/root.json}" --repo "$1" --datastore "$2"
}

# shellcheck disable=SC2046
check "valid repository + target" OK $(load "$wrk/repo" "$wrk/ds-valid") --target pack.bin --expect "$wrk/pack-v1.bin"

cp -R "$wrk/repo" "$wrk/repo-tamper-target"
target_file="$(ls "$wrk"/repo-tamper-target/targets/*pack.bin)"
printf 'X' | dd of="$target_file" bs=1 seek=100 conv=notrunc 2>/dev/null
# shellcheck disable=SC2046
check "target bytes modified" REJECTED $(load "$wrk/repo-tamper-target" "$wrk/ds-t1") --target pack.bin --expect "$wrk/pack-v1.bin"

cp -R "$wrk/repo" "$wrk/repo-tamper-meta"
targets_meta="$(ls "$wrk"/repo-tamper-meta/metadata/*.targets.json)"
sed -i.bak 's/"expires": *"[^"]*"/"expires": "2099-01-01T00:00:00Z"/' "$targets_meta" && rm -f "$targets_meta.bak"
# shellcheck disable=SC2046
check "targets.json modified (unsigned)" REJECTED $(load "$wrk/repo-tamper-meta" "$wrk/ds-t2")

# shellcheck disable=SC2046
check "rollback: load v1 into fresh store" OK $(load "$wrk/repo" "$wrk/ds-rollback")
head -c 65536 /dev/urandom > "$wrk/input/pack.bin"
publish update 2 "$wrk/repo" 'in 1 week' >/dev/null
# shellcheck disable=SC2046
check "rollback: update to v2" OK $(load "$wrk/repo" "$wrk/ds-rollback") --target pack.bin --expect "$wrk/input/pack.bin"
# shellcheck disable=SC2046
check "rollback: replay v1 after v2 was trusted" REJECTED $(load "$wrk/repo-v1" "$wrk/ds-rollback")

publish create 1 "$wrk/repo-expired" "$(date -u -v-1d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '-1 day' +%Y-%m-%dT%H:%M:%SZ)" >/dev/null 2>&1 \
  || echo "| expired timestamp | REJECTED | tuftool refused to publish expired metadata | n/a |"
if [ -d "$wrk/repo-expired" ]; then
  # shellcheck disable=SC2046
  check "expired timestamp" REJECTED $(load "$wrk/repo-expired" "$wrk/ds-exp")
fi

make_root "$wrk/other-root" >/dev/null
# shellcheck disable=SC2046
check "repository signed by an untrusted root" REJECTED $(load "$wrk/repo" "$wrk/ds-other" "$wrk/other-root/root.json")

cp -R "$wrk/repo" "$wrk/repo-oversize"
ts="$wrk/repo-oversize/metadata/timestamp.json"
# Whitespace keeps the JSON (and its canonical signature) valid, isolating the size limit.
{ head -c 1 "$ts"; head -c 20000 /dev/zero | tr '\0' ' '; tail -c +2 "$ts"; } > "$ts.new" && mv "$ts.new" "$ts"
# shellcheck disable=SC2046
check "timestamp.json above 16 KiB limit" REJECTED $(load "$wrk/repo-oversize" "$wrk/ds-big")

# shellcheck disable=SC2046
check "target not listed in metadata" REJECTED $(load "$wrk/repo" "$wrk/ds-valid") --target missing.bin --expect "$wrk/pack-v1.bin"
# Informational: how tough itself treats hostile names (normalizes, does not reject).
for name in ../../etc/passwd a/../../escape /etc/passwd; do
  printf '| tough TargetName %s (informational) | — | `%s` | info |\n' "$name" "$("$client" target-name "$name" 2>&1 || true)"
done
# Rift's staging policy: only allowlisted, already-normalized flat names.
check "Rift policy: ../../etc/passwd" REJECTED rift-target-policy ../../etc/passwd
check "Rift policy: a/../../escape" REJECTED rift-target-policy a/../../escape
check "Rift policy: /etc/passwd" REJECTED rift-target-policy /etc/passwd
check "Rift policy: ./url-hashes.bin" REJECTED rift-target-policy ./url-hashes.bin
check "Rift policy: unknown.bin" REJECTED rift-target-policy unknown.bin
check "Rift policy: url-hashes.bin" OK rift-target-policy url-hashes.bin

echo
echo "failures: $failures"
[ "$failures" -eq 0 ]
