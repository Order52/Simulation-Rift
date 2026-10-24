#!/bin/sh
# The production key ceremony (docs/reports/key-ceremony.md): the offline
# steps of docs/reports/key-policy.md, one command each, with checks. Every
# command but `rehearse` refuses to run while the machine has a network
# route; keys are written only to the drive given, never inside git.
#
#   sh tools/rift-pack/ceremony.sh key <root|targets|snapshot|timestamp> <name> <drive-dir>
#   sh tools/rift-pack/ceremony.sh policy <policy.json> <expires> <root.pub.json>x3 <targets.pub.json>x2 <snapshot.pub.json> <timestamp.pub.json>
#   sh tools/rift-pack/ceremony.sh draft <policy.json> <root.json>
#   sh tools/rift-pack/ceremony.sh sign <root.json> <key.pk8> [<previous-root.json>]
#   sh tools/rift-pack/ceremony.sh check <root.json> [<previous-root.json>]
#   sh tools/rift-pack/ceremony.sh sign-targets <targets.json> <root.json> <key.pk8>   each release
#   sh tools/rift-pack/ceremony.sh rehearse <empty-scratch-dir>   the whole ceremony and a release, with throwaway keys
#
# RIFT_PACK names a rift-pack binary (on the offline machine, one built
# beforehand: cargo build --release --locked -p rift-pack); otherwise it is
# built here.
set -eu

die() { echo "ceremony: $*" >&2; exit 1; }

pack_tool() {
  if [ -n "${RIFT_PACK:-}" ]; then
    "$RIFT_PACK" "$@"
  else
    cargo run --quiet --locked --release -p rift-pack -- "$@"
  fi
}

# Offline keys are made and used only on a machine with no network.
offline() {
  [ "${RIFT_CEREMONY_REHEARSAL:-0}" = 1 ] && return 0
  if command -v ip >/dev/null 2>&1; then
    [ -z "$(ip route show default 2>/dev/null)" ] || die "this machine has a default route; disconnect it (Wi-Fi off, cable out) first"
  elif route -n get default >/dev/null 2>&1; then
    die "this machine has a default route; disconnect it (Wi-Fi off, cable out) first"
  fi
}

fingerprint() { shasum -a 256 "$1" | cut -d' ' -f1; }

cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  key)
    [ $# = 3 ] || die "usage: key <role> <name> <drive-dir>"
    role="$1" name="$2" drive="$3"
    case "$role" in root | targets) offline ;; snapshot | timestamp) ;; *) die "role is root, targets, snapshot or timestamp" ;; esac
    case "$name" in *[!a-z0-9-]* | "") die "name: lower-case letters, digits and -" ;; esac
    [ -d "$drive" ] || die "$drive is not a directory (mount the drive first)"
    key="$drive/rift-$role-$name.pk8" pub="$drive/rift-$role-$name.pub.json"
    [ ! -e "$key" ] || die "$key already exists; a key is never overwritten"
    pack_tool key "$key"
    pack_tool public "$key" "$pub"
    echo "private key: $key (stays on this drive)"
    echo "public half: $pub (hand this over), SHA-256 $(fingerprint "$pub")"
    echo "Write down the key ID and the SHA-256 above; the policy's author reads them back to you."
    ;;
  policy)
    [ $# = 9 ] || die "usage: policy <policy.json> <expires> <root.pub.json>x3 <targets.pub.json>x2 <snapshot.pub.json> <timestamp.pub.json>"
    out="$1" expires="$2"; shift 2
    case "$expires" in [0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T00:00:00Z) ;; *) die "expires: YYYY-MM-DDT00:00:00Z, at most 365 days away" ;; esac
    for f in "$@"; do [ -f "$f" ] || die "$f: no such public key"; done
    printf '{\n  "version": 1,\n  "expires": "%s",\n  "root": {"threshold": 2, "keys": ["%s", "%s", "%s"]},\n  "targets": {"threshold": 2, "keys": ["%s", "%s"]},\n  "snapshot": {"threshold": 1, "keys": ["%s"]},\n  "timestamp": {"threshold": 1, "keys": ["%s"]}\n}\n' \
      "$expires" "$@" > "$out"
    echo "policy written to $out:"; cat "$out"
    for f in "$@"; do echo "  $(fingerprint "$f")  $f"; done
    ;;
  draft)
    [ $# = 2 ] || die "usage: draft <policy.json> <root.json>"
    offline
    pack_tool root-draft "$1" "$2"
    echo "Each root holder now checks the key IDs in $2 against their own before signing."
    ;;
  sign)
    [ $# = 2 ] || [ $# = 3 ] || die "usage: sign <root.json> <key.pk8> [<previous-root.json>]"
    offline
    pack_tool root-sign "$@"
    pack_tool root-check "$1" ${3:+"$3"} || echo "(not yet at its threshold: the next holder signs)"
    ;;
  check)
    [ $# = 1 ] || [ $# = 2 ] || die "usage: check <root.json> [<previous-root.json>]"
    pack_tool root-check "$@"
    ;;
  sign-targets)
    [ $# = 3 ] || die "usage: sign-targets <targets.json> <root.json> <key.pk8>"
    offline
    pack_tool targets-sign "$@"
    ;;
  rehearse)
    [ $# = 1 ] || die "usage: rehearse <empty-scratch-dir>"
    dir="$1"; mkdir -p "$dir"
    [ -z "$(ls -A "$dir")" ] || die "$dir is not empty"
    self="$0"
    export RIFT_CEREMONY_REHEARSAL=1
    if [ -z "${RIFT_PACK:-}" ]; then
      cargo build --quiet --locked --release -p rift-pack -p rift-update --examples
      RIFT_PACK="$(pwd)/target/release/rift-pack"; export RIFT_PACK
    fi
    # Seven drives, one key each, as seven holders would have.
    for k in root:a root:b root:c targets:a targets:b snapshot:publisher timestamp:publisher; do
      mkdir "$dir/drive-${k%%:*}-${k#*:}"
      sh "$self" key "${k%%:*}" "${k#*:}" "$dir/drive-${k%%:*}-${k#*:}" > /dev/null
    done
    pub() { echo "$dir/drive-$1-$2/rift-$1-$2.pub.json"; }
    key() { echo "$dir/drive-$1-$2/rift-$1-$2.pk8"; }
    expires="$(date -u -v+364d +%Y-%m-%dT00:00:00Z 2>/dev/null || date -u -d '+364 days' +%Y-%m-%dT00:00:00Z)"
    sh "$self" policy "$dir/policy.json" "$expires" "$(pub root a)" "$(pub root b)" "$(pub root c)" \
      "$(pub targets a)" "$(pub targets b)" "$(pub snapshot publisher)" "$(pub timestamp publisher)" > /dev/null
    sh "$self" draft "$dir/policy.json" "$dir/root-1.json" > /dev/null
    echo "== one root signature: short of 2 of 3"
    sh "$self" sign "$dir/root-1.json" "$(key root a)"
    echo "== the second"
    sh "$self" sign "$dir/root-1.json" "$(key root b)"
    echo "== a release, signed 2 of 2 offline, published with the online keys"
    mkdir "$dir/pack"
    pack_tool demo "$dir/pack" > /dev/null
    pack_tool targets-draft "$dir/pack" 1 "$dir/targets-1.json"
    sh "$self" sign-targets "$dir/targets-1.json" "$dir/root-1.json" "$(key targets a)"
    sh "$self" sign-targets "$dir/targets-1.json" "$dir/root-1.json" "$(key targets b)"
    pack_tool publish-signed "$dir/targets-1.json" "$dir/pack" "$dir/repo" 1 "$dir/root-1.json" -- \
      "$(key snapshot publisher)" "$(key timestamp publisher)"
    echo "== an offline key handed to the publishing step is refused"
    if pack_tool publish-signed "$dir/targets-1.json" "$dir/pack" "$dir/repo-x" 2 "$dir/root-1.json" -- \
      "$(key root c)" "$(key timestamp publisher)" 2>&1; then die "an offline key was accepted"; fi
    echo "== the app's own verifier"
    target="$(dirname "$RIFT_PACK")/examples/verify"
    "$target" "$dir/root-1.json" "$dir/repo" "$dir/datastore"
    rm -f "$dir"/drive-*/*.pk8
    echo "rehearsal passed; its throwaway private keys are deleted"
    ;;
  *)
    sed -n '2,16p' "$0" >&2
    exit 2
    ;;
esac
