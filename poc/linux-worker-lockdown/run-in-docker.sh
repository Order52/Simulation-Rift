#!/bin/sh
# Reproduces PoC L2/L3 inside a Linux container as an unprivileged user,
# under Docker's default seccomp profile. Usage: ./run-in-docker.sh [image]
set -eu
image="${1:-rust:1.99-bookworm}"
poc_root="$(cd "$(dirname "$0")/.." && pwd)"

docker volume create rift-cargo-registry >/dev/null
docker run --rm -v "$poc_root":/src -v rift-cargo-registry:/usr/local/cargo/registry \
  -w /src -e CARGO_TARGET_DIR=/src/target/docker-linux "$image" \
  sh -c 'cargo build --release --quiet -p linux-worker-lockdown && cp target/docker-linux/release/linux-worker-lockdown /tmp/l2 && chmod 755 /tmp/l2 && su nobody -s /bin/sh -c "
    echo \"kernel: \$(uname -r) arch: \$(uname -m) uid: \$(id -u)\"; echo;
    status=0
    for mode in none fd-only ro-dir strict; do /tmp/l2 controller --mode \$mode || status=1; done
    exit \$status"'
