//! Worker side: lock down, then answer probe commands with `ALLOWED …` or
//! `DENIED <errno>`. Each probe attempts one capability a compromised parser
//! might want, so the controller can check the OS refuses it.

use std::fs::File;
use std::io::Read;
use std::num::NonZeroUsize;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd, RawFd};
use std::process::ExitCode;

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, SealFlag, fcntl};
use nix::sys::memfd::{MFdFlags, memfd_create};
use nix::sys::mman::{MapFlags, ProtFlags, mmap_anonymous, munmap};
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socket};
use nix::unistd::Pid;

use crate::ipc;
use crate::lockdown::{self, FsPolicy, Options};

/// Bytes written to the sealed output memfd; the controller checks them.
pub const OUTPUT_PATTERN: &[u8] = b"rift-sealed-output:";
pub const OUTPUT_LEN: usize = 1024 * 1024;

pub fn worker_main(args: &[String]) -> ExitCode {
    let (Some(fd), Some(mode)) = (flag(args, "--fd"), flag(args, "--mode")) else {
        return ExitCode::from(2);
    };
    let Ok(raw_fd) = fd.parse::<RawFd>() else {
        return ExitCode::from(2);
    };
    // SAFETY: the controller passed this inherited descriptor number on our
    // command line; it is open, and nothing else in this process uses it.
    let sock: OwnedFd = unsafe { std::os::fd::FromRawFd::from_raw_fd(raw_fd) };
    // Captured before lockdown: getppid is not on the allowlist.
    let parent = nix::unistd::getppid();

    let status = match mode.as_str() {
        "none" => Ok("lockdown=disabled (negative control)".to_owned()),
        "fd-only" | "strict" | "ro-dir" => {
            let fs = match (mode.as_str(), flag(args, "--ro-dir")) {
                ("ro-dir", Some(dir)) => FsPolicy::ReadOnlyBeneath(dir.into()),
                ("ro-dir", None) => return ExitCode::from(2),
                _ => FsPolicy::None,
            };
            let opts = Options {
                fs,
                kill_on_violation: mode == "strict",
                keep_fd: raw_fd,
            };
            lockdown::apply(&opts)
        }
        _ => return ExitCode::from(2),
    };
    let ready = match status {
        Ok(report) => format!("READY {report}"),
        Err(e) => format!("FAILED {e}"),
    };
    if ipc::send(sock.as_fd(), &ready, None).is_err() || ready.starts_with("FAILED") {
        // Fail closed: never process input without the full lockdown.
        return ExitCode::from(3);
    }

    loop {
        let Ok(msg) = ipc::recv(sock.as_fd()) else {
            return ExitCode::SUCCESS;
        };
        let (cmd, arg) = msg.text.split_once(' ').unwrap_or((msg.text.as_str(), ""));
        if cmd == "exit" {
            return ExitCode::SUCCESS;
        }
        let (reply, out_fd) = run(cmd, arg, parent, msg.fd);
        if ipc::send(sock.as_fd(), &reply, out_fd.as_ref().map(|f| f.as_fd())).is_err() {
            return ExitCode::from(4);
        }
    }
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
}

fn run(cmd: &str, arg: &str, parent: Pid, input: Option<OwnedFd>) -> (String, Option<OwnedFd>) {
    match cmd {
        "open_file" => (io(File::open(arg).map(|_| "opened".into())), None),
        "list_dir" => (
            io(std::fs::read_dir(arg).map(|d| format!("{} entries", d.count()))),
            None,
        ),
        "create_file" => (io(File::create(arg).map(|_| "created".into())), None),
        "socket_inet" => (
            sys(socket(
                AddressFamily::Inet,
                SockType::Stream,
                SockFlag::empty(),
                None,
            )
            .map(|_| "created".into())),
            None,
        ),
        "socket_unix" => (
            sys(socket(
                AddressFamily::Unix,
                SockType::Stream,
                SockFlag::empty(),
                None,
            )
            .map(|_| "created".into())),
            None,
        ),
        "spawn_process" => (
            io(std::process::Command::new("/bin/true")
                .status()
                .map(|s| format!("ran: {s}"))),
            None,
        ),
        // SEIZE (unlike ATTACH) does not stop the tracee, so a successful probe
        // cannot freeze the controller; the trace ends when the worker exits.
        "ptrace_parent" => (
            sys(
                nix::sys::ptrace::seize(parent, nix::sys::ptrace::Options::empty())
                    .map(|()| "seized".into()),
            ),
            None,
        ),
        "signal_parent" => (
            sys(nix::sys::signal::kill(parent, None).map(|()| "signalled".into())),
            None,
        ),
        "mmap_exec" => (sys(map_executable()), None),
        "alloc_mib" => (alloc(arg), None),
        "read_input" => (read_input(input), None),
        "memfd_output" => match sealed_output() {
            Ok((fd, report)) => (format!("ALLOWED {report}"), Some(fd)),
            Err(e) => (format!("DENIED {e}"), None),
        },
        _ => ("DENIED unknown-command".into(), None),
    }
}

fn io(result: std::io::Result<String>) -> String {
    match result {
        Ok(detail) => format!("ALLOWED {detail}"),
        Err(e) => match e.raw_os_error() {
            Some(code) => format!("DENIED {}", Errno::from_raw(code)),
            None => format!("DENIED {e}"),
        },
    }
}

fn sys(result: nix::Result<String>) -> String {
    match result {
        Ok(detail) => format!("ALLOWED {detail}"),
        Err(e) => format!("DENIED {e}"),
    }
}

fn map_executable() -> nix::Result<String> {
    let len = NonZeroUsize::new(4096).ok_or(Errno::EINVAL)?;
    // SAFETY: an anonymous private mapping that is never dereferenced and is
    // unmapped immediately; it aliases no existing memory.
    unsafe {
        let addr = mmap_anonymous(
            None,
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
            MapFlags::MAP_PRIVATE,
        )?;
        munmap(addr, len.get())?;
    }
    Ok("mapped executable page".into())
}

fn alloc(mib: &str) -> String {
    let Ok(mib) = mib.parse::<usize>() else {
        return "DENIED bad-argument".into();
    };
    let mut buf: Vec<u8> = Vec::new();
    match buf.try_reserve_exact(mib * 1024 * 1024) {
        Ok(()) => {
            buf.resize(mib * 1024 * 1024, 1);
            format!("ALLOWED {} MiB committed", buf.len() / (1024 * 1024))
        }
        Err(_) => "DENIED allocation refused".into(),
    }
}

fn read_input(input: Option<OwnedFd>) -> String {
    let Some(fd) = input else {
        return "DENIED no-descriptor".into();
    };
    let mut file = File::from(fd);
    let mut total = 0usize;
    let mut checksum = 0u64;
    let mut chunk = [0u8; 8192];
    loop {
        match file.read(&mut chunk) {
            Ok(0) => return format!("ALLOWED {total} bytes checksum={checksum:016x}"),
            Ok(n) => {
                total += n;
                checksum = chunk[..n].iter().fold(checksum, |h, &b| {
                    (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
                });
            }
            Err(e) => return io(Err(e)),
        }
    }
}

/// Produces output in a memfd and seals it so neither side can change it.
fn sealed_output() -> nix::Result<(OwnedFd, String)> {
    let fd = memfd_create(
        c"rift-output",
        MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING,
    )?;
    let mut payload = Vec::with_capacity(OUTPUT_LEN);
    while payload.len() < OUTPUT_LEN {
        payload.extend_from_slice(OUTPUT_PATTERN);
    }
    payload.truncate(OUTPUT_LEN);
    write_all(fd.as_fd(), &payload)?;
    let seals = SealFlag::F_SEAL_SHRINK
        | SealFlag::F_SEAL_GROW
        | SealFlag::F_SEAL_WRITE
        | SealFlag::F_SEAL_SEAL;
    fcntl(&fd, FcntlArg::F_ADD_SEALS(seals))?;
    let after = match nix::unistd::write(&fd, b"tamper") {
        Ok(_) => "post-seal write SUCCEEDED".to_owned(),
        Err(e) => format!("post-seal write denied ({e})"),
    };
    Ok((fd, format!("{OUTPUT_LEN} bytes sealed; {after}")))
}

fn write_all(fd: BorrowedFd<'_>, mut data: &[u8]) -> nix::Result<()> {
    while !data.is_empty() {
        let n = nix::unistd::write(fd, data)?;
        data = &data[n..];
    }
    Ok(())
}
