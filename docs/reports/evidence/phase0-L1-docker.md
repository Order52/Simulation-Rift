# Evidence: PoC L1 — WebKitGTK 6.0 sandbox detection (Docker)

Command: `poc/linux-webkit-sandbox/run-in-docker.sh` (Fedora 44 image, WebKitGTK 2.54.1, Xvfb, Docker 29.7.2 on Apple silicon, kernel 7.0.12-linuxkit aarch64). Captured 2026-10-17T10:30Z. Unrelated Mesa/Vulkan warnings (no GPU in the container) are omitted.

The probe identifies web processes by `/proc/<pid>/comm`, never by command line: the first version matched the outer `bwrap` launcher, whose arguments include the web process path, and reported it as an unconfined web process.

| case | container settings | expected | observed |
|---|---|---|---|
| default | Docker default seccomp profile | WebKit refuses to run unsandboxed | **aborts at startup** (exit 134): `bwrap` cannot create namespaces |
| unmasked | seccomp, AppArmor and `/proc` masking off | sandbox verified | web process has NoNewPrivs=1, Seccomp=2, new user/mnt/pid/net namespaces: **browsing allowed** |
| disabled | as unmasked, plus `WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=1` | Rift's check refuses | web process has no seccomp and no new namespaces: **browsing refused** |

## Raw output

```
## case: default
bwrap: No permissions to create a new namespace, likely because the kernel does not allow non-privileged user namespaces. On e.g. debian this can be enabled with 'sysctl kernel.unprivileged_userns_clone=1'.
** (python3:22): ERROR **: 10:28:22.131: Failed to fully launch dbus-proxy: Child process exited with code 1
/usr/sbin/xvfb-run: line 181:    22 Aborted                    DISPLAY=:$SERVERNUM XAUTHORITY=$AUTHFILE "$@" 2>&1
probe exit status: 134 (WebKit aborted at startup (fail closed))

## case: unmasked
webkit version: 2.54.1
web processes: [122]
pid 122 (WebKitWebProces): NoNewPrivs=1 Seccomp=2 filters=1 new_namespaces=user,mnt,pid,net -> CONFINED
(not part of the verdict) pid 114 (WebKitNetworkPr): NoNewPrivs=0 Seccomp=0 filters=0 new_namespaces= -> NOT CONFINED
(not part of the verdict) pid 115 (bwrap): NoNewPrivs=1 Seccomp=0 filters=0 new_namespaces= -> NOT CONFINED
(not part of the verdict) pid 116 (bwrap): NoNewPrivs=1 Seccomp=2 filters=1 new_namespaces=user,mnt,pid,ipc -> CONFINED
(not part of the verdict) pid 117 (xdg-dbus-proxy): NoNewPrivs=1 Seccomp=2 filters=1 new_namespaces=user,mnt,pid,ipc -> CONFINED
(not part of the verdict) pid 120 (bwrap): NoNewPrivs=1 Seccomp=0 filters=0 new_namespaces= -> NOT CONFINED
(not part of the verdict) pid 121 (bwrap): NoNewPrivs=1 Seccomp=2 filters=1 new_namespaces=user,mnt,pid,net -> CONFINED
verdict: browsing allowed (sandbox verified)
probe exit status: 0 (sandbox verified, browsing allowed)

## case: disabled
webkit version: 2.54.1
web processes: [114]
pid 114 (WebKitWebProces): NoNewPrivs=0 Seccomp=0 filters=0 new_namespaces= -> NOT CONFINED
(not part of the verdict) pid 113 (WebKitNetworkPr): NoNewPrivs=0 Seccomp=0 filters=0 new_namespaces= -> NOT CONFINED
verdict: BROWSING REFUSED (sandbox not verified)
probe exit status: 1 (sandbox not verified, browsing refused)

```
