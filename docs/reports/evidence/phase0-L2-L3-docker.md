# Evidence: PoC L2/L3 — Linux worker lockdown (Docker)

Command: `CARGO_BUILD_JOBS=1 poc/linux-worker-lockdown/run-in-docker.sh` (image rust:1.99-bookworm, Docker 29.7.2, Docker Desktop on Apple silicon). Captured 2026-10-17T09:58Z. This run adds the `yara_scan` probe (YARA-X 1.21.0, Pulley interpreter) and the single-thread precondition.

Note: in the `none` (negative-control) mode, `Seccomp=2` is Docker's own default profile applied to every container process; it is not Rift's filter (NoNewPrivs=0 confirms Rift's lockdown did not run).

## Finding from the previous run: YARA-X timeouts start a thread

The first run with `yara_scan` called `Scanner::set_timeout`. In `fd-only` and `ro-dir` the worker then died with `failed to spawn thread: Operation not permitted`: YARA-X lazily starts a global heartbeat thread for timeouts, and the filter denies `clone`. The controller saw `ECONNRESET` and reported the probe as failed, so the failure was closed, not silent. Starting that thread before lockdown would have been worse: seccomp without TSYNC and Landlock confine only the calling thread. The fix:

- the Linux worker never uses in-process timeouts; the supervisor enforces deadlines;
- `lockdown::apply` refuses to run unless the process has exactly one thread;
- a regression test (`crates/rift-worker/tests/no_threads.rs`) checks that jobs start no threads.

See architecture §7.3.

kernel: 7.0.12-linuxkit arch: aarch64 uid: 65534

## mode `none`

- worker report: `READY lockdown=disabled (negative control)`
- /proc/100/status: NoNewPrivs=0 Seccomp=2

| probe | argument | expected | observed | result |
|---|---|---|---|---|
| `open_file` | `/tmp/rift-l2-99/canary-secret.txt` | allowed | ALLOWED opened | pass |
| `open_file` | `/etc/passwd` | allowed | ALLOWED opened | pass |
| `list_dir` | `/` | allowed | ALLOWED 20 entries | pass |
| `create_file` | `/tmp/rift-l2-99/created-by-worker` | allowed | ALLOWED created | pass |
| `socket_inet` | `` | allowed | ALLOWED created | pass |
| `socket_unix` | `` | allowed | ALLOWED created | pass |
| `spawn_process` | `` | allowed | ALLOWED ran: exit status: 0 | pass |
| `ptrace_parent` | `` | allowed | ALLOWED seized | pass |
| `signal_parent` | `` | allowed | ALLOWED signalled | pass |
| `mmap_exec` | `` | allowed | ALLOWED mapped executable page | pass |
| `alloc_mib` | `1024` | allowed | ALLOWED 1024 MiB committed | pass |
| `alloc_mib` | `64` | allowed | ALLOWED 64 MiB committed | pass |
| `read_input` | `` | allowed | ALLOWED 300000 bytes checksum=f4b48b8e72cf2ca1 (checksum matches) | pass |
| `yara_scan` | `` | allowed | ALLOWED yara.status=OK yara.matches=rift_demo_marker yara.bytes=39 yara.compile_ms=3.5 yara.scan_ms=0.0 yara.mib_per_s=2 | pass |
| `memfd_output` | `` | allowed | ALLOWED 1048576 bytes sealed; post-seal write denied (EPERM: Operation not permitted) / controller: seals verified, content verified, controller write denied (Operation not permitted (os error 1)) | pass |

## mode `fd-only`

- worker report: `READY landlock=fully-enforced seccomp=on`
- /proc/103/status: NoNewPrivs=1 Seccomp=2

| probe | argument | expected | observed | result |
|---|---|---|---|---|
| `open_file` | `/tmp/rift-l2-102/canary-secret.txt` | denied | DENIED EPERM: Operation not permitted | pass |
| `open_file` | `/etc/passwd` | denied | DENIED EPERM: Operation not permitted | pass |
| `list_dir` | `/` | denied | DENIED EPERM: Operation not permitted | pass |
| `create_file` | `/tmp/rift-l2-102/created-by-worker` | denied | DENIED EPERM: Operation not permitted | pass |
| `socket_inet` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `socket_unix` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `spawn_process` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `ptrace_parent` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `signal_parent` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `mmap_exec` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `alloc_mib` | `1024` | denied | DENIED allocation refused | pass |
| `alloc_mib` | `64` | allowed | ALLOWED 64 MiB committed | pass |
| `read_input` | `` | allowed | ALLOWED 300000 bytes checksum=f4b48b8e72cf2ca1 (checksum matches) | pass |
| `yara_scan` | `` | allowed | ALLOWED yara.status=OK yara.matches=rift_demo_marker yara.bytes=39 yara.compile_ms=2.1 yara.scan_ms=0.0 yara.mib_per_s=2 | pass |
| `memfd_output` | `` | allowed | ALLOWED 1048576 bytes sealed; post-seal write denied (EPERM: Operation not permitted) / controller: seals verified, content verified, controller write denied (Operation not permitted (os error 1)) | pass |

## mode `ro-dir`

- worker report: `READY landlock=fully-enforced seccomp=on`
- /proc/105/status: NoNewPrivs=1 Seccomp=2
- read-only directory: `/usr/share/ImageMagick-6`

| probe | argument | expected | observed | result |
|---|---|---|---|---|
| `open_file` | `/tmp/rift-l2-104/canary-secret.txt` | denied | DENIED EACCES: Permission denied | pass |
| `open_file` | `/etc/passwd` | denied | DENIED EACCES: Permission denied | pass |
| `list_dir` | `/` | denied | DENIED EACCES: Permission denied | pass |
| `create_file` | `/tmp/rift-l2-104/created-by-worker` | denied | DENIED EPERM: Operation not permitted | pass |
| `socket_inet` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `socket_unix` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `spawn_process` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `ptrace_parent` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `signal_parent` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `mmap_exec` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `alloc_mib` | `1024` | denied | DENIED allocation refused | pass |
| `alloc_mib` | `64` | allowed | ALLOWED 64 MiB committed | pass |
| `read_input` | `` | allowed | ALLOWED 300000 bytes checksum=f4b48b8e72cf2ca1 (checksum matches) | pass |
| `yara_scan` | `` | allowed | ALLOWED yara.status=OK yara.matches=rift_demo_marker yara.bytes=39 yara.compile_ms=2.3 yara.scan_ms=0.1 yara.mib_per_s=1 | pass |
| `memfd_output` | `` | allowed | ALLOWED 1048576 bytes sealed; post-seal write denied (EPERM: Operation not permitted) / controller: seals verified, content verified, controller write denied (Operation not permitted (os error 1)) | pass |
| `open_file` | `/usr/share/ImageMagick-6/english.xml` | allowed | ALLOWED opened | pass |

## mode `strict`

- worker report: `READY landlock=fully-enforced seccomp=on`
- reply to `socket_inet`: Err(ECONNRESET)
- worker exit: Ok(ExitStatus(unix_wait_status(31))) (signal Some(31), SIGSYS = 31)
- result: pass

