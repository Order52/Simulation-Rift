# Evidence: PoC L2/L3 — Linux worker lockdown (Docker)

Command: `poc/linux-worker-lockdown/run-in-docker.sh` (image rust:1.99-bookworm, Docker 29.7.2, Docker Desktop on Apple silicon). Captured 2026-10-17T08:16Z.

Note: in the `none` (negative-control) mode, `Seccomp=2` is Docker's own default profile applied to every container process; it is not Rift's filter (NoNewPrivs=0 confirms Rift's lockdown did not run).

kernel: 7.0.12-linuxkit arch: aarch64 uid: 65534

## mode `none`

- worker report: `READY lockdown=disabled (negative control)`
- /proc/56/status: NoNewPrivs=0 Seccomp=2

| probe | argument | expected | observed | result |
|---|---|---|---|---|
| `open_file` | `/tmp/rift-l2-55/canary-secret.txt` | allowed | ALLOWED opened | pass |
| `open_file` | `/etc/passwd` | allowed | ALLOWED opened | pass |
| `list_dir` | `/` | allowed | ALLOWED 20 entries | pass |
| `create_file` | `/tmp/rift-l2-55/created-by-worker` | allowed | ALLOWED created | pass |
| `socket_inet` | `` | allowed | ALLOWED created | pass |
| `socket_unix` | `` | allowed | ALLOWED created | pass |
| `spawn_process` | `` | allowed | ALLOWED ran: exit status: 0 | pass |
| `ptrace_parent` | `` | allowed | ALLOWED seized | pass |
| `signal_parent` | `` | allowed | ALLOWED signalled | pass |
| `mmap_exec` | `` | allowed | ALLOWED mapped executable page | pass |
| `alloc_mib` | `1024` | allowed | ALLOWED 1024 MiB committed | pass |
| `alloc_mib` | `64` | allowed | ALLOWED 64 MiB committed | pass |
| `read_input` | `` | allowed | ALLOWED 300000 bytes checksum=f4b48b8e72cf2ca1 (checksum matches) | pass |
| `memfd_output` | `` | allowed | ALLOWED 1048576 bytes sealed; post-seal write denied (EPERM: Operation not permitted) / controller: seals verified, content verified, controller write denied (Operation not permitted (os error 1)) | pass |

## mode `fd-only`

- worker report: `READY landlock=fully-enforced seccomp=on`
- /proc/59/status: NoNewPrivs=1 Seccomp=2

| probe | argument | expected | observed | result |
|---|---|---|---|---|
| `open_file` | `/tmp/rift-l2-58/canary-secret.txt` | denied | DENIED EPERM: Operation not permitted | pass |
| `open_file` | `/etc/passwd` | denied | DENIED EPERM: Operation not permitted | pass |
| `list_dir` | `/` | denied | DENIED EPERM: Operation not permitted | pass |
| `create_file` | `/tmp/rift-l2-58/created-by-worker` | denied | DENIED EPERM: Operation not permitted | pass |
| `socket_inet` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `socket_unix` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `spawn_process` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `ptrace_parent` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `signal_parent` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `mmap_exec` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `alloc_mib` | `1024` | denied | DENIED allocation refused | pass |
| `alloc_mib` | `64` | allowed | ALLOWED 64 MiB committed | pass |
| `read_input` | `` | allowed | ALLOWED 300000 bytes checksum=f4b48b8e72cf2ca1 (checksum matches) | pass |
| `memfd_output` | `` | allowed | ALLOWED 1048576 bytes sealed; post-seal write denied (EPERM: Operation not permitted) / controller: seals verified, content verified, controller write denied (Operation not permitted (os error 1)) | pass |

## mode `ro-dir`

- worker report: `READY landlock=fully-enforced seccomp=on`
- /proc/61/status: NoNewPrivs=1 Seccomp=2
- read-only directory: `/usr/share/ImageMagick-6`

| probe | argument | expected | observed | result |
|---|---|---|---|---|
| `open_file` | `/tmp/rift-l2-60/canary-secret.txt` | denied | DENIED EACCES: Permission denied | pass |
| `open_file` | `/etc/passwd` | denied | DENIED EACCES: Permission denied | pass |
| `list_dir` | `/` | denied | DENIED EACCES: Permission denied | pass |
| `create_file` | `/tmp/rift-l2-60/created-by-worker` | denied | DENIED EPERM: Operation not permitted | pass |
| `socket_inet` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `socket_unix` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `spawn_process` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `ptrace_parent` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `signal_parent` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `mmap_exec` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `alloc_mib` | `1024` | denied | DENIED allocation refused | pass |
| `alloc_mib` | `64` | allowed | ALLOWED 64 MiB committed | pass |
| `read_input` | `` | allowed | ALLOWED 300000 bytes checksum=f4b48b8e72cf2ca1 (checksum matches) | pass |
| `memfd_output` | `` | allowed | ALLOWED 1048576 bytes sealed; post-seal write denied (EPERM: Operation not permitted) / controller: seals verified, content verified, controller write denied (Operation not permitted (os error 1)) | pass |
| `open_file` | `/usr/share/ImageMagick-6/english.xml` | allowed | ALLOWED opened | pass |

## mode `strict`

- worker report: `READY landlock=fully-enforced seccomp=on`
- reply to `socket_inet`: Err(ECONNRESET)
- worker exit: Ok(ExitStatus(unix_wait_status(31))) (signal Some(31), SIGSYS = 31)
- result: pass

