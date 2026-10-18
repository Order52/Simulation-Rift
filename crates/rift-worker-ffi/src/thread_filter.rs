//! Defence in depth for the Android worker (architecture §8.6): a seccomp
//! filter on the thread that parses untrusted input. `isolated_app` already
//! denies files and `AF_INET`, but still allows `AF_UNIX` sockets and
//! executable mappings, which ART needs process-wide. This filter denies
//! them, and process creation and tracing, on this thread only (no TSYNC),
//! so the runtime's other threads are unaffected.
//!
//! It is weaker than the Linux worker's allowlist: every thread shares one
//! address space, so code that has taken over the parser thread can still
//! corrupt the others. It is not reported as a boundary.

use std::collections::BTreeMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

/// Installs the filter on the calling thread. Filters stack and cannot be
/// removed, so installing it twice is harmless.
pub fn confine_current_thread() -> Result<(), String> {
    let arch: TargetArch = std::env::consts::ARCH
        .try_into()
        .map_err(|e| format!("unsupported architecture: {e:?}"))?;
    let filter = SeccompFilter::new(
        denied()?,
        SeccompAction::Allow,
        SeccompAction::Errno(u32::try_from(libc::EPERM).map_err(|e| e.to_string())?),
        arch,
    )
    .map_err(|e| format!("filter: {e}"))?;
    let program: BpfProgram = filter.try_into().map_err(|e| format!("compile: {e:?}"))?;
    // Sets no_new_privs for this thread first, as seccomp requires.
    seccompiler::apply_filter(&program).map_err(|e| format!("apply: {e}"))
}

fn denied() -> Result<BTreeMap<i64, Vec<SeccompRule>>, String> {
    let exec = u64::try_from(libc::PROT_EXEC).map_err(|e| e.to_string())?;
    let mut rules = BTreeMap::new();
    for call in [
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
    ] {
        rules.insert(call, Vec::new());
    }
    // Executable mappings: the protection argument is arg 2 of each call.
    for call in [libc::SYS_mmap, libc::SYS_mprotect, libc::SYS_pkey_mprotect] {
        rules.insert(call, vec![rule(2, SeccompCmpOp::MaskedEq(exec), exec)?]);
    }
    Ok(rules)
}

fn rule(arg: u8, op: SeccompCmpOp, value: u64) -> Result<SeccompRule, String> {
    let condition = SeccompCondition::new(arg, SeccompCmpArgLen::Dword, op, value)
        .map_err(|e| format!("condition: {e}"))?;
    SeccompRule::new(vec![condition]).map_err(|e| format!("rule: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockets_are_denied_on_the_confined_thread_only() {
        let confined = std::thread::spawn(|| {
            confine_current_thread().unwrap();
            let unix = std::os::unix::net::UnixDatagram::unbound().map(|_| ());
            let inet = std::net::UdpSocket::bind("127.0.0.1:0").map(|_| ());
            (unix, inet)
        })
        .join()
        .unwrap();
        for result in [confined.0, confined.1] {
            assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EPERM));
        }
        // Other threads, and new ones, are not filtered.
        assert!(std::os::unix::net::UnixDatagram::unbound().is_ok());
    }
}
