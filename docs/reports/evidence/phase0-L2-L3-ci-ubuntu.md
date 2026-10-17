# Evidence: PoCs L2/L3 — GitHub Actions, Ubuntu x86_64

Source: the `linux-worker-lockdown` job of CI run [39026743110](https://github.com/Order52/Simulation-Rift/actions/runs/39026743110) (commit `8444511`, 17 Oct 2026). Runner kernel `6.17.0-1022-azure` x86_64, LSMs `lockdown,capability,landlock,yama,apparmor,ima,evm`, unprivileged user. The tables below are the job's own output, with the git-cleanup log lines removed.

Result: 45 of 46 probes pass. The exception is the negative control `ptrace_parent` in mode `none`, which is **inconclusive**: Yama already blocks attaching to the parent on this runner, so this run cannot show that the lockdown (rather than Yama) is what blocks ptrace. The Docker run on aarch64 shows it ([phase0-L2-L3-docker.md](phase0-L2-L3-docker.md)). In `fd-only` and `ro-dir` the lockdown denies ptrace either way.

## Output

## mode `none`
- worker report: `READY lockdown=disabled (negative control)`
- /proc/5829/status: NoNewPrivs=0 Seccomp=0
| probe | argument | expected | observed | result |
| `open_file` | `/tmp/rift-l2-5827/canary-secret.txt` | allowed | ALLOWED opened | pass |
| `open_file` | `/etc/passwd` | allowed | ALLOWED opened | pass |
| `list_dir` | `/` | allowed | ALLOWED 27 entries | pass |
| `create_file` | `/tmp/rift-l2-5827/created-by-worker` | allowed | ALLOWED created | pass |
| `socket_inet` | `` | allowed | ALLOWED created | pass |
| `socket_unix` | `` | allowed | ALLOWED created | pass |
| `spawn_process` | `` | allowed | ALLOWED ran: exit status: 0 | pass |
| `ptrace_parent` | `` | allowed | DENIED EPERM: Operation not permitted | inconclusive (environment already blocks it) |
| `signal_parent` | `` | allowed | ALLOWED signalled | pass |
| `mmap_exec` | `` | allowed | ALLOWED mapped executable page | pass |
| `alloc_mib` | `1024` | allowed | ALLOWED 1024 MiB committed | pass |
| `alloc_mib` | `64` | allowed | ALLOWED 64 MiB committed | pass |
| `read_input` | `` | allowed | ALLOWED 300000 bytes checksum=f4b48b8e72cf2ca1 (checksum matches) | pass |
| `yara_scan` | `` | allowed | ALLOWED yara.status=OK yara.matches=rift_demo_marker yara.bytes=39 yara.compile_ms=3.9 yara.scan_ms=0.0 yara.mib_per_s=1 | pass |
| `memfd_output` | `` | allowed | ALLOWED 1048576 bytes sealed; post-seal write denied (EPERM: Operation not permitted) / controller: seals verified, content verified, controller write denied (Operation not permitted (os error 1)) | pass |
## mode `fd-only`
- worker report: `READY landlock=fully-enforced seccomp=on`
- /proc/5835/status: NoNewPrivs=1 Seccomp=2
| probe | argument | expected | observed | result |
| `open_file` | `/tmp/rift-l2-5833/canary-secret.txt` | denied | DENIED EPERM: Operation not permitted | pass |
| `open_file` | `/etc/passwd` | denied | DENIED EPERM: Operation not permitted | pass |
| `list_dir` | `/` | denied | DENIED EPERM: Operation not permitted | pass |
| `create_file` | `/tmp/rift-l2-5833/created-by-worker` | denied | DENIED EPERM: Operation not permitted | pass |
| `socket_inet` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `socket_unix` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `spawn_process` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `ptrace_parent` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `signal_parent` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `mmap_exec` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `alloc_mib` | `1024` | denied | DENIED allocation refused | pass |
| `alloc_mib` | `64` | allowed | ALLOWED 64 MiB committed | pass |
| `read_input` | `` | allowed | ALLOWED 300000 bytes checksum=f4b48b8e72cf2ca1 (checksum matches) | pass |
| `yara_scan` | `` | allowed | ALLOWED yara.status=OK yara.matches=rift_demo_marker yara.bytes=39 yara.compile_ms=4.3 yara.scan_ms=0.0 yara.mib_per_s=1 | pass |
| `memfd_output` | `` | allowed | ALLOWED 1048576 bytes sealed; post-seal write denied (EPERM: Operation not permitted) / controller: seals verified, content verified, controller write denied (Operation not permitted (os error 1)) | pass |
## mode `ro-dir`
- worker report: `READY landlock=fully-enforced seccomp=on`
- /proc/5840/status: NoNewPrivs=1 Seccomp=2
- read-only directory: `/usr/share`
| probe | argument | expected | observed | result |
| `open_file` | `/tmp/rift-l2-5838/canary-secret.txt` | denied | DENIED EACCES: Permission denied | pass |
| `open_file` | `/etc/passwd` | denied | DENIED EACCES: Permission denied | pass |
| `list_dir` | `/` | denied | DENIED EACCES: Permission denied | pass |
| `create_file` | `/tmp/rift-l2-5838/created-by-worker` | denied | DENIED EPERM: Operation not permitted | pass |
| `socket_inet` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `socket_unix` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `spawn_process` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `ptrace_parent` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `signal_parent` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `mmap_exec` | `` | denied | DENIED EPERM: Operation not permitted | pass |
| `alloc_mib` | `1024` | denied | DENIED allocation refused | pass |
| `alloc_mib` | `64` | allowed | ALLOWED 64 MiB committed | pass |
| `read_input` | `` | allowed | ALLOWED 300000 bytes checksum=f4b48b8e72cf2ca1 (checksum matches) | pass |
| `yara_scan` | `` | allowed | ALLOWED yara.status=OK yara.matches=rift_demo_marker yara.bytes=39 yara.compile_ms=4.8 yara.scan_ms=0.0 yara.mib_per_s=1 | pass |
| `memfd_output` | `` | allowed | ALLOWED 1048576 bytes sealed; post-seal write denied (EPERM: Operation not permitted) / controller: seals verified, content verified, controller write denied (Operation not permitted (os error 1)) | pass |
| `open_file` | `/usr/share/dot.bashrc` | allowed | ALLOWED opened | pass |
## mode `strict`
- worker report: `READY landlock=fully-enforced seccomp=on`
- reply to `socket_inet`: Err(ECONNRESET)
- worker exit: Ok(ExitStatus(unix_wait_status(159))) (signal Some(31), SIGSYS = 31)
- result: pass
