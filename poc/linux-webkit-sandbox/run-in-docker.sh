#!/bin/sh
# PoC L1 (native-package path): WebKitGTK 6.0 on Fedora under Xvfb.
# Three cases (usage: ./run-in-docker.sh):
#   default     Docker's default seccomp profile blocks the user namespaces
#               bubblewrap needs: WebKit must refuse to start (fail closed).
#   unmasked    seccomp/AppArmor unconfined and /proc unmasked, so bubblewrap
#               can work: the probe must verify a confined web process.
#   disabled    as unmasked, but the sandbox is switched off with WebKit's
#               escape hatch: the probe must report NOT confined (negative
#               control for Rift's check).
set -u
here="$(cd "$(dirname "$0")" && pwd)"
image=rift-l1-webkit
docker build -q -t "$image" - <<'DOCKERFILE' >/dev/null
FROM fedora:44
RUN dnf -y -q install webkitgtk6.0 python3-gobject gobject-introspection gtk4 xorg-x11-server-Xvfb xorg-x11-xauth bubblewrap xdg-dbus-proxy dbus-daemon && dnf clean all
RUN useradd -m rift
USER rift
DOCKERFILE
unmasked="--security-opt seccomp=unconfined --security-opt apparmor=unconfined --security-opt systempaths=unconfined"
for case in default unmasked disabled; do
  echo "## case: $case"
  opt=""; env=""
  [ "$case" != default ] && opt="$unmasked"
  [ "$case" = disabled ] && env="-e WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=1"
  # shellcheck disable=SC2086
  docker run --rm $opt $env -v "$here":/probe:ro "$image" \
    sh -c 'dbus-run-session -- xvfb-run -a python3 -I /probe/probe.py > /tmp/out 2>&1; s=$?
      grep -E "^(webkit|web processes|pid |\(not part|verdict|probe could not)|bwrap:|ERROR|Aborted" /tmp/out; exit $s'
  status=$?
  case $status in
    0) meaning="sandbox verified, browsing allowed" ;;
    1) meaning="sandbox not verified, browsing refused" ;;
    2) meaning="probe could not run (environment)" ;;
    134) meaning="WebKit aborted at startup (fail closed)" ;;
    *) meaning="unexpected" ;;
  esac
  echo "probe exit status: $status ($meaning)"
  echo
done
