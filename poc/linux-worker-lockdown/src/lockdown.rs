//! The worker's self-confinement sequence. Order matters: Landlock must be
//! applied before seccomp forbids the Landlock syscalls, and everything must
//! happen before the first byte of untrusted input is read.

use std::collections::BTreeMap;
use std::os::fd::RawFd;
use std::path::PathBuf;

use landlock::{
    ABI, Access, AccessFs, AccessNet, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    Scope, path_beneath_rules,
};
use nix::sys::resource::{Resource, setrlimit};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

pub enum FsPolicy {
    /// No filesystem access at all; the worker uses only passed descriptors.
    None,
    /// Read-only access beneath one directory (e.g. fonts for PDF rendering).
    ReadOnlyBeneath(PathBuf),
}

pub struct Options {
    pub fs: FsPolicy,
    /// Kill the process on a forbidden syscall instead of returning EPERM.
    pub kill_on_violation: bool,
    /// The IPC socket — the only descriptor that survives.
    pub keep_fd: RawFd,
}

const ADDRESS_SPACE_LIMIT: u64 = 512 * 1024 * 1024;
const CPU_SECONDS_LIMIT: u64 = 15;
/// Bounds memfd output (4 Mpx RGBA = 16 MiB) while forbidding large writes.
const FILE_SIZE_LIMIT: u64 = 32 * 1024 * 1024;
const OPEN_FILES_LIMIT: u64 = 16;

/// Applies every layer; returns a human-readable report or the first failure.
/// Any error means the worker must exit without touching input (fail closed).
pub fn apply(opts: &Options) -> Result<String, String> {
    close_inherited_fds(opts.keep_fd)?;
    set_rlimits()?;
    nix::sys::prctl::set_no_new_privs().map_err(|e| format!("no_new_privs: {e}"))?;
    let landlock = apply_landlock(&opts.fs)?;
    apply_seccomp(opts)?;
    Ok(format!("landlock={landlock} seccomp=on"))
}

fn close_inherited_fds(keep: RawFd) -> Result<(), String> {
    // Collect first: the directory iterator itself holds a descriptor.
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
        (Resource::RLIMIT_AS, ADDRESS_SPACE_LIMIT),
        (Resource::RLIMIT_CPU, CPU_SECONDS_LIMIT),
        (Resource::RLIMIT_FSIZE, FILE_SIZE_LIMIT),
        (Resource::RLIMIT_NOFILE, OPEN_FILES_LIMIT),
        (Resource::RLIMIT_NPROC, 0),
        (Resource::RLIMIT_CORE, 0),
    ];
    for (resource, value) in limits {
        setrlimit(resource, value, value).map_err(|e| format!("setrlimit {resource:?}: {e}"))?;
    }
    Ok(())
}

fn apply_landlock(fs: &FsPolicy) -> Result<&'static str, String> {
    let abi = ABI::V6;
    let err = |e: landlock::RulesetError| format!("landlock: {e}");
    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(err)?
        .handle_access(AccessNet::from_all(abi))
        .map_err(err)?
        .scope(Scope::from_all(abi))
        .map_err(err)?
        .create()
        .map_err(err)?;
    if let FsPolicy::ReadOnlyBeneath(dir) = fs {
        ruleset = ruleset
            .add_rules(path_beneath_rules([dir], AccessFs::from_read(abi)))
            .map_err(err)?;
    }
    let status = ruleset.restrict_self().map_err(err)?;
    match status.ruleset {
        RulesetStatus::FullyEnforced => Ok("fully-enforced"),
        // Older kernels lack newer access rights; filesystem rules still hold.
        RulesetStatus::PartiallyEnforced => Ok("partially-enforced"),
        RulesetStatus::NotEnforced => Err("landlock is not supported by this kernel".into()),
    }
}

fn apply_seccomp(opts: &Options) -> Result<(), String> {
    let arch: TargetArch = std::env::consts::ARCH
        .try_into()
        .map_err(|e| format!("seccomp arch: {e:?}"))?;
    let violation = if opts.kill_on_violation {
        SeccompAction::KillProcess
    } else {
        SeccompAction::Errno(libc::EPERM as u32)
    };
    let filter = SeccompFilter::new(allowlist(&opts.fs)?, violation, SeccompAction::Allow, arch)
        .map_err(|e| format!("seccomp filter: {e}"))?;
    let program: BpfProgram = filter
        .try_into()
        .map_err(|e| format!("seccomp compile: {e:?}"))?;
    seccompiler::apply_filter(&program).map_err(|e| format!("seccomp apply: {e}"))
}

fn allowlist(fs: &FsPolicy) -> Result<BTreeMap<i64, Vec<SeccompRule>>, String> {
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
    let prot_exec = libc::PROT_EXEC as u64;
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
            .map(|cmd| rule(1, SeccompCmpOp::Eq, cmd as u64))
            .collect::<Result<_, _>>()?,
    );

    // Signals only to ourselves (abort() uses tgkill on its own pid).
    rules.insert(
        libc::SYS_tgkill,
        vec![rule(0, SeccompCmpOp::Eq, std::process::id().into())?],
    );

    if let FsPolicy::ReadOnlyBeneath(_) = fs {
        // Landlock decides *where*; seccomp ensures read-only, non-creating opens.
        let write_or_create = (libc::O_ACCMODE | libc::O_CREAT | libc::O_TRUNC) as u64;
        rules.insert(
            libc::SYS_openat,
            vec![rule(2, SeccompCmpOp::MaskedEq(write_or_create), 0)?],
        );
        rules.insert(libc::SYS_getdents64, Vec::new());
    }
    Ok(rules)
}

fn rule(arg: u8, op: SeccompCmpOp, value: u64) -> Result<SeccompRule, String> {
    let condition = SeccompCondition::new(arg, SeccompCmpArgLen::Dword, op, value)
        .map_err(|e| format!("seccomp condition: {e}"))?;
    SeccompRule::new(vec![condition]).map_err(|e| format!("seccomp rule: {e}"))
}
