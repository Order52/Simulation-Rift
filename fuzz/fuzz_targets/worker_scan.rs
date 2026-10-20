//! The worker scans every download with the installed rules (§12). Whatever
//! the bytes, the scan must answer with at most the requested number of
//! matches, naming only rules that exist, or with an error, and the controller
//! must accept the answer. The rules use the features a threat database may:
//! text, hex with jumps, regular expressions, wide strings and the hash and
//! math modules.
#![no_main]

use std::cell::RefCell;

use libfuzzer_sys::fuzz_target;
use rift_protocol::{
    Confinement, Envelope, LandlockStatus, PROTOCOL_VERSION, Request, Response, decode_response,
    encode,
};
use rift_worker::{Deadline, Worker};
use sha2::{Digest, Sha256};

const RULES: &str = r#"
import "hash"
import "math"

rule executable_header {
  strings:
    $mz = "MZ"
    $pe = { 4D 5A ?? ?? [0-8] 50 45 00 00 }
  condition:
    $mz at 0 or $pe
}

rule many_links {
  strings:
    $link = /https?:\/\/[a-z0-9.-]{3,40}\/[A-Za-z0-9_\/]{0,32}/ nocase
  condition:
    #link > 1
}

rule script_word {
  strings:
    $word = "powershell" wide ascii nocase
  condition:
    $word
}

rule dense {
  condition:
    filesize > 64 and math.entropy(0, filesize) > 7.0
}

rule empty_file {
  condition:
    hash.sha256(0, filesize) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
"#;
const NAMES: [&str; 5] = [
    "executable_header",
    "many_links",
    "script_word",
    "dense",
    "empty_file",
];

fn envelope(body: Request) -> Envelope<Request> {
    Envelope {
        version: PROTOCOL_VERSION,
        job_id: 1,
        generation: 1,
        body,
    }
}

thread_local! {
    // Compiling the rules takes far longer than one scan, so one worker holds them.
    static WORKER: RefCell<(Worker, [u8; 32])> = RefCell::new({
        let mut worker = Worker::new(
            Confinement {
                seccomp: false,
                no_new_privs: false,
                landlock: LandlockStatus::NotApplicable,
            },
            Deadline::Supervisor,
        );
        let digest: [u8; 32] = Sha256::digest(RULES).into();
        let mut source = RULES.as_bytes();
        let loaded = worker.handle(&envelope(Request::LoadRules { digest }), Some(&mut source));
        assert!(
            matches!(loaded.response.body, Response::RulesLoaded { rule_count: 5 }),
            "{:?}",
            loaded.response.body
        );
        (worker, digest)
    });
}

fuzz_target!(|data: &[u8]| {
    let Some((&max_matches, mut content)) = data.split_first() else {
        return;
    };
    let max_matches = u16::from(max_matches % 8);
    WORKER.with_borrow_mut(|(worker, digest)| {
        let request = envelope(Request::Scan {
            rules_digest: *digest,
            max_matches,
            deadline_ms: 1000,
        });
        let outcome = worker.handle(&request, Some(&mut content));
        let encoded = encode(&outcome.response).expect("the worker's answer encodes");
        let accepted = decode_response(&encoded, &request)
            .unwrap_or_else(|e| panic!("the controller refused {:?}: {e:?}", outcome.response.body));
        match accepted.get() {
            Response::ScanResult { matches, .. } => {
                assert!(matches.len() <= usize::from(max_matches));
                for found in matches {
                    assert!(NAMES.contains(&found.rule.as_str()), "{}", found.rule);
                }
            }
            Response::Error(_) => {}
            response => panic!("{response:?} answered a scan"),
        }
    });
});
