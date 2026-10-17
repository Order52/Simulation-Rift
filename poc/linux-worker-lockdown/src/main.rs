//! PoC L2/L3 — Linux worker self-lockdown (docs/architecture.md §7.3, §9.3).
//!
//! The controller spawns this same binary as a worker connected by a
//! `SOCK_SEQPACKET` socketpair. The worker confines itself (fd hygiene,
//! rlimits, no_new_privs, Landlock, seccomp-bpf allowlist) and then answers
//! probe commands. The controller checks every probe against the expected
//! outcome and verifies confinement from outside via `/proc/<pid>/status`.
//!
//! Modes:
//! * `fd-only`  — production preview/scan policy: no filesystem at all.
//! * `ro-dir`   — PDF policy variant: read-only access beneath one directory.
//! * `strict`   — violations kill the worker (SIGSYS) instead of returning EPERM.
//! * `none`     — negative control: no lockdown, probes must succeed.

#[cfg(target_os = "linux")]
mod controller;
#[cfg(target_os = "linux")]
mod ipc;
#[cfg(target_os = "linux")]
mod lockdown;
#[cfg(target_os = "linux")]
mod probes;

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("worker") => probes::worker_main(&args[1..]),
        Some("controller") => controller::main(&args[1..]),
        _ => {
            eprintln!(
                "usage: linux-worker-lockdown controller --mode <fd-only|ro-dir|strict|none>"
            );
            std::process::ExitCode::from(2)
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("this proof of concept only runs on Linux");
    std::process::exit(2);
}
