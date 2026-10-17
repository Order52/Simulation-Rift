//! Controller side: spawn a worker, verify its confinement from outside, run
//! every probe, and compare with the expected outcome for the mode.

use std::fs::File;
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::fs::FileExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};

use nix::fcntl::{FcntlArg, FdFlag, SealFlag, fcntl};
use nix::sys::socket::{AddressFamily, SockFlag, SockType, setsockopt, socketpair, sockopt};
use nix::sys::time::TimeVal;

use crate::ipc;
use crate::probes::{OUTPUT_LEN, OUTPUT_PATTERN};

#[derive(Clone, Copy, PartialEq)]
enum Expect {
    Allowed,
    Denied,
}

struct Probe {
    cmd: &'static str,
    arg: String,
    expect_locked: Expect,
    sends_input: bool,
}

struct Fixture {
    dir: PathBuf,
    canary: PathBuf,
    input: PathBuf,
    input_checksum: String,
    readable_file: Option<PathBuf>,
}

pub fn main(args: &[String]) -> ExitCode {
    let mode = args
        .iter()
        .position(|a| a == "--mode")
        .and_then(|i| args.get(i + 1))
        .map_or("fd-only", String::as_str);
    let fixture = match Fixture::create() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("fixture setup failed: {e}");
            return ExitCode::from(2);
        }
    };
    let ok = match mode {
        "strict" => run_strict(),
        "fd-only" | "ro-dir" | "none" => run_probes(mode, &fixture),
        _ => {
            eprintln!("unknown mode {mode}");
            false
        }
    };
    let _ = std::fs::remove_dir_all(&fixture.dir);
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

impl Fixture {
    fn create() -> std::io::Result<Self> {
        let dir = std::env::temp_dir().join(format!("rift-l2-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let canary = dir.join("canary-secret.txt");
        std::fs::write(
            &canary,
            b"vault-canary: this must never be readable by a worker\n",
        )?;
        let input = dir.join("input.bin");
        let data: Vec<u8> = (0..300_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
            .collect();
        File::create(&input)?.write_all(&data)?;
        let checksum = data.iter().fold(0u64, |h, &b| {
            (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
        });
        Ok(Self {
            canary,
            input,
            input_checksum: format!("{} bytes checksum={checksum:016x}", data.len()),
            readable_file: first_regular_file(Path::new("/usr/share"), 4),
            dir,
        })
    }
}

fn first_regular_file(dir: &Path, depth: u32) -> Option<PathBuf> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in &entries {
        let ty = entry.file_type().ok()?;
        if ty.is_file() && File::open(entry.path()).is_ok() {
            return Some(entry.path());
        }
    }
    if depth == 0 {
        return None;
    }
    entries
        .iter()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .find_map(|e| first_regular_file(&e.path(), depth - 1))
}

fn probes(mode: &str, fx: &Fixture) -> Vec<Probe> {
    let p = |cmd, arg: &str, expect_locked| Probe {
        cmd,
        arg: arg.to_owned(),
        expect_locked,
        sends_input: false,
    };
    let path = |p: &Path| p.display().to_string();
    let mut list = vec![
        p("open_file", &path(&fx.canary), Expect::Denied),
        p("open_file", "/etc/passwd", Expect::Denied),
        p("list_dir", "/", Expect::Denied),
        p(
            "create_file",
            &path(&fx.dir.join("created-by-worker")),
            Expect::Denied,
        ),
        p("socket_inet", "", Expect::Denied),
        p("socket_unix", "", Expect::Denied),
        p("spawn_process", "", Expect::Denied),
        p("ptrace_parent", "", Expect::Denied),
        p("signal_parent", "", Expect::Denied),
        p("mmap_exec", "", Expect::Denied),
        p("alloc_mib", "1024", Expect::Denied),
        p("alloc_mib", "64", Expect::Allowed),
        Probe {
            cmd: "read_input",
            arg: String::new(),
            expect_locked: Expect::Allowed,
            sends_input: true,
        },
        p("memfd_output", "", Expect::Allowed),
    ];
    if mode == "ro-dir"
        && let Some(file) = &fx.readable_file
    {
        list.push(p("open_file", &path(file), Expect::Allowed));
    }
    list
}

fn spawn_worker(mode: &str, extra: &[String]) -> Result<(Child, OwnedFd), String> {
    let (ours, theirs) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::empty(),
    )
    .map_err(|e| format!("socketpair: {e}"))?;
    fcntl(&ours, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).map_err(|e| format!("cloexec: {e}"))?;
    setsockopt(&ours, sockopt::ReceiveTimeout, &TimeVal::new(10, 0))
        .map_err(|e| format!("timeout: {e}"))?;
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let child = Command::new(exe)
        .arg("worker")
        .args(["--fd", &theirs.as_raw_fd().to_string(), "--mode", mode])
        .args(extra)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn: {e}"))?;
    drop(theirs);
    Ok((child, ours))
}

/// Reads NoNewPrivs and Seccomp mode from the worker's /proc status — an
/// external check that does not rely on the worker's own report.
fn proc_confinement(pid: u32) -> (String, String) {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let field = |name: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .map_or_else(|| "?".to_owned(), |v| v.trim().to_owned())
    };
    (field("NoNewPrivs:"), field("Seccomp:"))
}

fn run_probes(mode: &str, fx: &Fixture) -> bool {
    let extra: Vec<String> = match (mode, &fx.readable_file) {
        ("ro-dir", Some(file)) => {
            let dir = file
                .parent()
                .map(|d| d.display().to_string())
                .unwrap_or_default();
            vec!["--ro-dir".into(), dir]
        }
        ("ro-dir", None) => {
            eprintln!("no readable file found under /usr/share for ro-dir mode");
            return false;
        }
        _ => Vec::new(),
    };
    let (mut child, sock) = match spawn_worker(mode, &extra) {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("{e}");
            return false;
        }
    };
    let locked = mode != "none";
    let mut all_ok = true;

    let ready = ipc::recv(sock.as_fd())
        .map(|m| m.text)
        .unwrap_or_else(|e| format!("FAILED recv: {e}"));
    let (nnp, seccomp) = proc_confinement(child.id());
    println!("## mode `{mode}`\n");
    println!("- worker report: `{ready}`");
    println!(
        "- /proc/{}/status: NoNewPrivs={nnp} Seccomp={seccomp}",
        child.id()
    );
    if locked && (!ready.starts_with("READY") || nnp != "1" || seccomp != "2") {
        println!("- **FAIL: confinement not verified; no input sent (fail closed)**");
        let _ = child.kill();
        let _ = child.wait();
        return false;
    }
    if mode == "ro-dir"
        && let Some(dir) = fx.readable_file.as_deref().and_then(Path::parent)
    {
        println!("- read-only directory: `{}`", dir.display());
    }

    println!("\n| probe | argument | expected | observed | result |\n|---|---|---|---|---|");
    for probe in probes(mode, fx) {
        let input = probe.sends_input.then(|| File::open(&fx.input)).transpose();
        let input = match input {
            Ok(f) => f.map(OwnedFd::from),
            Err(e) => {
                eprintln!("open input: {e}");
                return false;
            }
        };
        let text = format!("{} {}", probe.cmd, probe.arg);
        let reply = ipc::send(sock.as_fd(), &text, input.as_ref().map(|f| f.as_fd()))
            .and_then(|()| ipc::recv(sock.as_fd()));
        let (observed, detail) = match reply {
            Ok(msg) => {
                let detail = if probe.cmd == "memfd_output" {
                    match msg.fd {
                        Some(fd) => format!("{} / controller: {}", msg.text, verify_sealed(fd)),
                        None => msg.text.clone(),
                    }
                } else if probe.cmd == "read_input" && msg.text.starts_with("ALLOWED") {
                    let matches = msg.text.ends_with(&fx.input_checksum);
                    format!(
                        "{} ({})",
                        msg.text,
                        if matches {
                            "checksum matches"
                        } else {
                            "CHECKSUM MISMATCH"
                        }
                    )
                } else {
                    msg.text.clone()
                };
                let observed = if msg.text.starts_with("ALLOWED") {
                    Expect::Allowed
                } else {
                    Expect::Denied
                };
                (observed, detail)
            }
            Err(e) => (Expect::Denied, format!("worker unreachable: {e}")),
        };
        let expected = match (locked, probe.expect_locked) {
            (true, e) => e,
            (false, _) => Expect::Allowed,
        };
        let integrity_ok = !detail.contains("MISMATCH")
            && !detail.contains("SUCCEEDED")
            && !detail.contains("FAIL");
        let verdict = match (observed == expected && integrity_ok, locked) {
            (true, _) => "pass",
            (false, true) => {
                all_ok = false;
                "**FAIL**"
            }
            // A control probe the environment already blocks cannot demonstrate anything.
            (false, false) => "inconclusive (environment already blocks it)",
        };
        let label = |e: Expect| {
            if e == Expect::Allowed {
                "allowed"
            } else {
                "denied"
            }
        };
        println!(
            "| `{}` | `{}` | {} | {} | {verdict} |",
            probe.cmd,
            probe.arg,
            label(expected),
            detail.replace('|', "/"),
        );
    }
    let _ = ipc::send(sock.as_fd(), "exit", None);
    let _ = child.wait();
    println!();
    all_ok
}

fn verify_sealed(fd: OwnedFd) -> String {
    let required = SealFlag::F_SEAL_WRITE | SealFlag::F_SEAL_GROW | SealFlag::F_SEAL_SHRINK;
    let seals = match fcntl(&fd, FcntlArg::F_GET_SEALS) {
        Ok(bits) => SealFlag::from_bits_truncate(bits),
        Err(e) => return format!("FAIL get seals: {e}"),
    };
    if !seals.contains(required) {
        return format!("FAIL seals incomplete: {seals:?}");
    }
    let file = File::from(fd);
    let mut content = vec![0u8; OUTPUT_LEN];
    if let Err(e) = file.read_exact_at(&mut content, 0) {
        return format!("FAIL read: {e}");
    }
    if !content.starts_with(OUTPUT_PATTERN) {
        return "FAIL content mismatch".into();
    }
    match file.write_at(b"tamper", 0) {
        Ok(_) => "FAIL controller could modify sealed output".into(),
        Err(e) => format!("seals verified, content verified, controller write denied ({e})"),
    }
}

/// With kill-on-violation, a forbidden syscall must terminate the worker
/// with SIGSYS rather than return an error the attacker could handle.
fn run_strict() -> bool {
    let (mut child, sock) = match spawn_worker("strict", &[]) {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("{e}");
            return false;
        }
    };
    println!("## mode `strict`\n");
    let ready = ipc::recv(sock.as_fd()).map(|m| m.text).unwrap_or_default();
    println!("- worker report: `{ready}`");
    let reply =
        ipc::send(sock.as_fd(), "socket_inet ", None).and_then(|()| ipc::recv(sock.as_fd()));
    let status = child.wait();
    let signal = status.as_ref().ok().and_then(|s| s.signal());
    println!("- reply to `socket_inet`: {:?}", reply.map(|m| m.text));
    println!(
        "- worker exit: {status:?} (signal {signal:?}, SIGSYS = {})",
        libc::SIGSYS
    );
    let ok = signal == Some(libc::SIGSYS);
    println!("- result: {}\n", if ok { "pass" } else { "**FAIL**" });
    ok
}
