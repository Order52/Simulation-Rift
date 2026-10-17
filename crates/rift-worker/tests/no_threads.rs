//! The Linux worker's seccomp filter forbids `clone`, and a thread started
//! before lockdown would escape it. Jobs run with `Deadline::Supervisor` must
//! therefore never start a thread. This binary holds a single test so no other
//! test's threads disturb the count.
#![cfg(target_os = "linux")]

use std::io::{Cursor, Read};

use rift_protocol::{Confinement, Envelope, LandlockStatus, PROTOCOL_VERSION, Request, Response};
use rift_worker::{Deadline, Worker};
use sha2::{Digest, Sha256};

const RULES: &str = r#"rule marker { strings: $a = "RIFT-DEMO-MALWARE-MARKER" condition: $a }"#;

fn threads() -> std::io::Result<usize> {
    Ok(std::fs::read_dir("/proc/self/task")?.count())
}

fn run(worker: &mut Worker, body: Request, input: &[u8]) -> Response {
    let request = Envelope {
        version: PROTOCOL_VERSION,
        job_id: 1,
        generation: 1,
        body,
    };
    let mut input = Cursor::new(input);
    worker
        .handle(&request, Some(&mut input as &mut dyn Read))
        .response
        .body
}

#[test]
fn supervisor_deadline_jobs_start_no_threads() {
    let before = threads().unwrap();
    let mut worker = Worker::new(
        Confinement {
            seccomp: true,
            no_new_privs: true,
            landlock: LandlockStatus::FullyEnforced,
        },
        Deadline::Supervisor,
    );
    let digest: [u8; 32] = Sha256::digest(RULES.as_bytes()).into();
    let loaded = run(&mut worker, Request::LoadRules { digest }, RULES.as_bytes());
    assert_eq!(loaded, Response::RulesLoaded { rule_count: 1 });
    let scanned = run(
        &mut worker,
        Request::Scan {
            rules_digest: digest,
            max_matches: 8,
            deadline_ms: 5000,
        },
        b"xx RIFT-DEMO-MALWARE-MARKER xx",
    );
    assert!(matches!(scanned, Response::ScanResult { ref matches, .. } if matches.len() == 1));

    let mut png = Vec::new();
    image::RgbaImage::new(64, 64)
        .write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png)
        .unwrap();
    let decoded = run(
        &mut worker,
        Request::DecodeImage {
            max_width: 32,
            max_height: 32,
            deadline_ms: 5000,
        },
        &png,
    );
    assert!(matches!(decoded, Response::Bitmap(_)));

    assert_eq!(threads().unwrap(), before, "a job started a thread");
}
