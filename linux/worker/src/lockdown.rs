//! The worker's self-confinement (docs/architecture.md §8.6), as proven in
//! PoC L2 and inside Flatpak in Q4. Order matters: Landlock before seccomp
//! forbids its syscalls, and all of it before the first byte of untrusted
//! input is read. Any failure means the worker exits without reading input.

use std::collections::BTreeMap;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};

use landlock::{ABI, Access, AccessFs, AccessNet, Ruleset, RulesetAttr, RulesetStatus, Scope};
use rift_protocol::LandlockStatus;
use rustix::process::{Resource, Rlimit, setrlimit};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

/// Room for a 100 MiB scan input, YARA-X's compiled rules and an image
/// decode bounded at 256 MiB.
const ADDRESS_SPACE_LIMIT: u64 = 1024 * 1024 * 1024;
/// The backstop: the controller kills the worker at each job's deadline.
const CPU_SECONDS_LIMIT: u64 = 30;
/// Bounds the pixel memfd (16384 × 16384 is refused before this).
const FILE_SIZE_LIMIT: u64 = 256 * 1024 * 1024;
const OPEN_FILES_LIMIT: u64 = 16;

/// Applies every layer and returns Landlock's status. The channel `keep` is
/// the only descriptor above stderr that survives.
pub fn apply(keep: BorrowedFd<'_>) -> Result<LandlockStatus, String> {
    require_single_thread()?;
    close_inherited_fds(keep.as_raw_fd())?;
    set_rlimits()?;
    rustix::thread::set_no_new_privs(true).map_err(|e| format!("no_new_privs: {e}"))?;
    let landlock = apply_landlock()?;
    apply_seccomp()?;
    Ok(landlock)
}

/// seccomp (without TSYNC) and Landlock confine only the calling thread, so
/// any other thread would stay unconfined.
fn require_single_thread() -> Result<(), String> {
    let threads = std::fs::read_dir("/proc/self/task")
        .map_err(|e| format!("list threads: {e}"))?
        .count();
    if threads == 1 {
        Ok(())
    } else {
        Err(format!(
            "{threads} threads exist; lockdown requires exactly one"
        ))
    }
}

fn close_inherited_fds(keep: RawFd) -> Result<(), String> {
    // Collected first: the directory iterator holds a descriptor of its own.
    let fds: Vec<RawFd> = std::fs::read_dir("/proc/self/fd")
        .map_err(|e| format!("list fds: {e}"))?
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
        .collect();
    for fd in fds.into_iter().filter(|&fd| fd > 2 && fd != keep) {
        // EBADF is expected for the iterator's own, already-closed descriptor.
        match nix::unistd::close(fd) {
            Ok(()) | Err(nix::errno::Errno::EBADF) => {}
            Err(e) => return Err(format!("close fd {fd}: {e}")),
        }
    }
    Ok(())
}

fn set_rlimits() -> Result<(), String> {
    let limits = [
        (Resource::As, ADDRESS_SPACE_LIMIT),
        (Resource::Cpu, CPU_SECONDS_LIMIT),
        (Resource::Fsize, FILE_SIZE_LIMIT),
        (Resource::Nofile, OPEN_FILES_LIMIT),
        (Resource::Nproc, 0),
        (Resource::Core, 0),
    ];
    for (resource, value) in limits {
        let limit = Rlimit {
            current: Some(value),
            maximum: Some(value),
        };
        setrlimit(resource, limit).map_err(|e| format!("setrlimit {resource:?}: {e}"))?;
    }
    Ok(())
}

/// No filesystem access and no TCP at all; abstract sockets and signals are
/// scoped to this process.
fn apply_landlock() -> Result<LandlockStatus, String> {
    let abi = ABI::V6;
    let err = |e: landlock::RulesetError| format!("landlock: {e}");
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(err)?
        .handle_access(AccessNet::from_all(abi))
        .map_err(err)?
        .scope(Scope::from_all(abi))
        .map_err(err)?
        .create()
        .map_err(err)?
        .restrict_self()
        .map_err(err)?;
    match status.ruleset {
        RulesetStatus::FullyEnforced => Ok(LandlockStatus::FullyEnforced),
        // Older kernels lack newer rights; the filesystem rules still hold.
        RulesetStatus::PartiallyEnforced => Ok(LandlockStatus::PartiallyEnforced),
        RulesetStatus::NotEnforced => Err("landlock is not supported by this kernel".into()),
    }
}

/// Calls the standard library makes on its own and copes with failing:
/// `available_parallelism` (which the regex engine behind YARA-X's compiler
/// asks once) reads cgroup files and the CPU affinity, and falls back to a
/// default when it cannot. These fail with EACCES instead of killing the
/// worker; Landlock refuses every path anyway.
const REFUSED: [i64; 2] = [libc::SYS_openat, libc::SYS_sched_getaffinity];

/// Two filters. The first makes the calls in [`REFUSED`] fail; the second
/// kills the process on anything not in its allowlist. The kernel applies
/// the strictest answer of all filters, so a refused call is neither
/// allowed nor fatal. The first is applied first, while the second does
/// not yet forbid seccomp(2).
fn apply_seccomp() -> Result<(), String> {
    let arch: TargetArch = std::env::consts::ARCH
        .try_into()
        .map_err(|e| format!("seccomp arch: {e:?}"))?;
    let refused = SeccompFilter::new(
        REFUSED.into_iter().map(|nr| (nr, Vec::new())).collect(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EACCES.unsigned_abs()),
        arch,
    )
    .map_err(|e| format!("seccomp filter: {e}"))?;
    let mut allowed = allowlist()?;
    for nr in REFUSED {
        allowed.insert(nr, Vec::new());
    }
    let allowlist = SeccompFilter::new(
        allowed,
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        arch,
    )
    .map_err(|e| format!("seccomp filter: {e}"))?;
    for filter in [refused, allowlist] {
        let program: BpfProgram = filter
            .try_into()
            .map_err(|e| format!("seccomp compile: {e:?}"))?;
        seccompiler::apply_filter(&program).map_err(|e| format!("seccomp apply: {e}"))?;
    }
    Ok(())
}

fn allowlist() -> Result<BTreeMap<i64, Vec<SeccompRule>>, String> {
    let unconditional = [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_pread64,
        libc::SYS_lseek,
        libc::SYS_close,
        libc::SYS_fstat,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_brk,
        libc::SYS_futex,
        libc::SYS_sched_yield,
        libc::SYS_getrandom,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigprocmask,
        libc::SYS_sigaltstack,
        libc::SYS_recvmsg,
        libc::SYS_sendmsg,
        libc::SYS_memfd_create,
        libc::SYS_ftruncate,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ];
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = unconditional
        .into_iter()
        .map(|nr| (nr, Vec::new()))
        .collect();

    // Memory may be mapped or re-protected, but never executable: the worker
    // runs no JIT (YARA-X uses the Pulley interpreter).
    let prot_exec = u64::from(libc::PROT_EXEC.unsigned_abs());
    rules.insert(
        libc::SYS_mmap,
        vec![rule(2, SeccompCmpOp::MaskedEq(prot_exec), 0)?],
    );
    rules.insert(
        libc::SYS_mprotect,
        vec![rule(2, SeccompCmpOp::MaskedEq(prot_exec), 0)?],
    );

    // fcntl only for sealing and descriptor flags.
    let fcntl_cmds = [
        libc::F_ADD_SEALS,
        libc::F_GET_SEALS,
        libc::F_GETFD,
        libc::F_SETFD,
        libc::F_GETFL,
    ];
    rules.insert(
        libc::SYS_fcntl,
        fcntl_cmds
            .into_iter()
            .map(|cmd| rule(1, SeccompCmpOp::Eq, u64::from(cmd.unsigned_abs())))
            .collect::<Result<_, _>>()?,
    );

    // Signals only to itself (abort() uses tgkill on its own pid).
    rules.insert(
        libc::SYS_tgkill,
        vec![rule(0, SeccompCmpOp::Eq, std::process::id().into())?],
    );
    Ok(rules)
}

fn rule(arg: u8, op: SeccompCmpOp, value: u64) -> Result<SeccompRule, String> {
    let condition = SeccompCondition::new(arg, SeccompCmpArgLen::Dword, op, value)
        .map_err(|e| format!("seccomp condition: {e}"))?;
    SeccompRule::new(vec![condition]).map_err(|e| format!("seccomp rule: {e}"))
}
