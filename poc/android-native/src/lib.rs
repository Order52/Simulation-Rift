//! Native half of the Android feasibility app (PoC A5/A6).
//!
//! Loaded inside the `isolatedProcess` worker service. `probes` reports what
//! the process can reach at the syscall level; `yara_scan` compiles a rule
//! set with YARA-X (Pulley interpreter, no JIT) and scans one passed fd.

use std::fmt::Write as _;
use std::fs::File;
use std::io::Read;
use std::os::fd::FromRawFd;
use std::time::Instant;

use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jint, jstring};

/// Scans larger than this are refused rather than truncated.
const MAX_SCAN_BYTES: usize = 100 * 1024 * 1024;

/// Syscall-level confinement probes; returns `key=value` lines.
pub fn probes(canary: &str, tcp_port: u16) -> String {
    let mut out = String::new();
    // SAFETY: getuid/getpid have no preconditions.
    let (uid, pid) = unsafe { (libc::getuid(), libc::getpid()) };
    let _ = writeln!(out, "native.uid={uid}");
    let _ = writeln!(out, "native.pid={pid}");
    let _ = writeln!(
        out,
        "native.selinux={}",
        read_trimmed("/proc/self/attr/current")
    );
    for field in ["Seccomp:", "NoNewPrivs:", "CapEff:"] {
        let value = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix(field))
                    .map(|v| v.trim().to_owned())
            })
            .unwrap_or_else(|| "unreadable".into());
        let _ = writeln!(out, "native.status.{}={value}", field.trim_end_matches(':'));
    }
    let _ = writeln!(
        out,
        "native.open_canary={}",
        outcome(File::open(canary).map(|_| ()))
    );
    let _ = writeln!(
        out,
        "native.open_data_dir={}",
        outcome(std::fs::read_dir("/data/data").map(|_| ()))
    );
    let _ = writeln!(
        out,
        "native.open_sdcard={}",
        outcome(std::fs::read_dir("/sdcard").map(|_| ()))
    );
    let _ = writeln!(
        out,
        "native.socket_inet={}",
        errno_outcome(open_socket(libc::AF_INET))
    );
    let _ = writeln!(
        out,
        "native.socket_unix={}",
        errno_outcome(open_socket(libc::AF_UNIX))
    );
    let _ = writeln!(
        out,
        "native.tcp_connect_127.0.0.1:{tcp_port}={}",
        outcome(std::net::TcpStream::connect(("127.0.0.1", tcp_port)).map(|_| ()))
    );
    let _ = writeln!(out, "native.exec_page={}", errno_outcome(map_exec_page()));
    out
}

fn read_trimmed(path: &str) -> String {
    std::fs::read_to_string(path)
        .map(|s| s.trim_matches(char::from(0)).trim().to_owned())
        .unwrap_or_else(|e| format!("unreadable ({e})"))
}

fn outcome(result: std::io::Result<()>) -> String {
    match result {
        Ok(()) => "ALLOWED".into(),
        Err(e) => format!("DENIED ({e})"),
    }
}

fn errno_outcome(result: Result<(), i32>) -> String {
    match result {
        Ok(()) => "ALLOWED".into(),
        Err(code) => format!("DENIED ({})", std::io::Error::from_raw_os_error(code)),
    }
}

fn open_socket(domain: libc::c_int) -> Result<(), i32> {
    // SAFETY: plain socket(2) call; the descriptor is closed immediately.
    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
    }
    // SAFETY: `fd` was just returned by socket(2) and is owned here.
    unsafe { libc::close(fd) };
    Ok(())
}

fn map_exec_page() -> Result<(), i32> {
    // SAFETY: anonymous private mapping, never dereferenced, unmapped at once.
    unsafe {
        let addr = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if addr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
        }
        libc::munmap(addr, 4096);
    }
    Ok(())
}

/// Compiles `rules`, scans everything readable from `input`, and reports
/// matches plus timings. Errors are reported, never treated as "no match".
pub fn yara_scan(rules: &str, mut input: impl Read) -> String {
    let started = Instant::now();
    let compiled = match yara_x::compile(rules) {
        Ok(c) => c,
        Err(e) => return format!("yara.status=COMPILE_ERROR\nyara.error={e}\n"),
    };
    let compile_ms = started.elapsed().as_secs_f64() * 1e3;

    let mut data = Vec::new();
    if let Err(e) = input
        .by_ref()
        .take(MAX_SCAN_BYTES as u64 + 1)
        .read_to_end(&mut data)
    {
        return format!("yara.status=READ_ERROR\nyara.error={e}\n");
    }
    if data.len() > MAX_SCAN_BYTES {
        return "yara.status=TOO_LARGE\n".into();
    }

    let mut scanner = yara_x::Scanner::new(&compiled);
    scanner.set_timeout(std::time::Duration::from_secs(15));
    let scan_started = Instant::now();
    let results = match scanner.scan(&data) {
        Ok(r) => r,
        Err(e) => return format!("yara.status=SCAN_ERROR\nyara.error={e}\n"),
    };
    let scan_ms = scan_started.elapsed().as_secs_f64() * 1e3;
    let matched: Vec<&str> = results.matching_rules().map(|r| r.identifier()).collect();
    let mib_per_s = data.len() as f64 / (1024.0 * 1024.0) / (scan_ms / 1e3).max(1e-9);
    format!(
        "yara.status=OK\nyara.matches={}\nyara.bytes={}\nyara.compile_ms={compile_ms:.1}\nyara.scan_ms={scan_ms:.1}\nyara.mib_per_s={mib_per_s:.0}\n",
        matched.join(","),
        data.len(),
    )
}

fn to_jstring(env: &mut JNIEnv<'_>, text: String) -> jstring {
    env.new_string(text)
        .map_or(std::ptr::null_mut(), |s| s.into_raw())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_simulationrift_poc_Native_probes<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    canary: JString<'l>,
    tcp_port: jint,
) -> jstring {
    let canary: String = env.get_string(&canary).map(Into::into).unwrap_or_default();
    let port = u16::try_from(tcp_port).unwrap_or(0);
    let report = probes(&canary, port);
    to_jstring(&mut env, report)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_simulationrift_poc_Native_yaraScan<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    rules: JString<'l>,
    fd: jint,
) -> jstring {
    let rules: String = env.get_string(&rules).map(Into::into).unwrap_or_default();
    // Java keeps ownership of `fd` (ParcelFileDescriptor); scan a duplicate.
    // SAFETY: dup(2) on a descriptor the caller guarantees is open.
    let dup = unsafe { libc::dup(fd) };
    let report = if dup < 0 {
        format!(
            "yara.status=READ_ERROR\nyara.error={}\n",
            std::io::Error::last_os_error()
        )
    } else {
        // SAFETY: `dup` is a fresh descriptor owned exclusively by this File.
        yara_scan(&rules, unsafe { File::from_raw_fd(dup) })
    };
    to_jstring(&mut env, report)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: &str = r#"
        rule rift_demo_marker { strings: $a = "RIFT-DEMO-MALWARE-MARKER" condition: $a }
        rule rift_never { strings: $a = "this string is not in the input" condition: $a }
    "#;

    #[test]
    fn matches_marker_and_only_marker() {
        let input = b"padding RIFT-DEMO-MALWARE-MARKER padding".as_slice();
        let report = yara_scan(RULES, input);
        assert!(report.contains("yara.status=OK"), "{report}");
        assert!(
            report.contains("yara.matches=rift_demo_marker\n"),
            "{report}"
        );
    }

    #[test]
    fn invalid_rules_are_an_error_not_a_clean_result() {
        let report = yara_scan("rule broken {", b"x".as_slice());
        assert!(report.contains("yara.status=COMPILE_ERROR"), "{report}");
    }
}
