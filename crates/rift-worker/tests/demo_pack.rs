//! S21: the demo pack's rules compile in the worker (the install check), and
//! the demo file and patterns give the expected findings with versions.
#![allow(clippy::unwrap_used)]

use std::io::{Cursor, Read};

use rift_core::scan::{self, Evidence, RuleScan, Status};
use rift_protocol::{
    Confinement, Envelope, LandlockStatus, PROTOCOL_VERSION, Request, Response, SCAN_ENGINE,
};
use rift_worker::{Deadline, Worker};
use sha2::{Digest, Sha256};

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
fn s21_demo_pack_rules_compile_and_match() {
    let dir = tempfile::tempdir().unwrap();
    let pack = rift_pack::write_demo_pack(dir.path(), jiff::Timestamp::now()).unwrap();
    let mut worker = Worker::new(
        Confinement {
            seccomp: false,
            no_new_privs: false,
            landlock: LandlockStatus::NotApplicable,
        },
        Deadline::InProcess,
    );

    // The install check: every rule the metadata describes was compiled.
    let loaded = run(
        &mut worker,
        Request::LoadRules {
            digest: pack.rules_digest,
        },
        &pack.rules_source,
    );
    let expected = u32::try_from(pack.metadata.rules.len()).unwrap();
    assert_eq!(
        loaded,
        Response::RulesLoaded {
            rule_count: expected
        }
    );

    let cases: [(&[u8], &[&str], Status); 3] = [
        (
            rift_pack::DEMO_FILE,
            &["rift_demo_marker"],
            Status::KnownMalicious,
        ),
        (
            b"xx RIFT-DEMO-HEX xx",
            &["rift_demo_hex"],
            Status::Suspicious,
        ),
        (b"an ordinary file", &[], Status::NotFlagged),
    ];
    for (content, rules, status) in cases {
        let Response::ScanResult { matches, truncated } = run(
            &mut worker,
            Request::Scan {
                rules_digest: pack.rules_digest,
                max_matches: 16,
                deadline_ms: 5_000,
            },
            content,
        ) else {
            panic!("scan failed");
        };
        let matched: Vec<String> = matches.into_iter().map(|m| m.rule).collect();
        assert_eq!(matched, rules);
        let verdict = scan::assess(&Evidence {
            object: Sha256::digest(content).into(),
            type_mismatch: None,
            pack: Some(&pack),
            rules: RuleScan::Completed { matched, truncated },
            engine: SCAN_ENGINE,
            now_unix: pack.metadata.created_unix,
        });
        assert_eq!(verdict.status, status, "{content:?}");
        assert!(verdict.demo);
    }
}

#[test]
fn scan_engine_names_the_locked_yara_x() {
    let lock =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock")).unwrap();
    let version = lock
        .split("[[package]]")
        .find(|p| p.contains("\nname = \"yara-x\"\n"))
        .and_then(|p| p.lines().find_map(|l| l.strip_prefix("version = \"")))
        .and_then(|v| v.strip_suffix('"'))
        .unwrap();
    assert_eq!(SCAN_ENGINE, format!("yara-x {version}"));
}
