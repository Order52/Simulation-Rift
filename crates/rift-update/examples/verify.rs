//! Verifies an offline pack repository the way the app imports one, without
//! installing it: `cargo run -p rift-update --example verify -- <root.json> <repo-dir> <datastore-dir>`.

use std::path::Path;
use std::process::ExitCode;

use rift_core::pack::Pack;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [root, repo, datastore] = args.as_slice() else {
        eprintln!("usage: verify <root.json> <repo-dir> <datastore-dir>");
        return ExitCode::FAILURE;
    };
    let outcome = std::fs::read(root)
        .map_err(|e| format!("{root}: {e}"))
        .and_then(|root| {
            rift_update::verify_offline(&root, Path::new(repo), Path::new(datastore))
                .map_err(|e| e.to_string())
        })
        .and_then(|verified| {
            let pack = Pack::validate(verified.files.iter().map(|(n, b)| (*n, b.as_slice())))
                .map_err(|e| e.to_string())?;
            Ok(format!(
                "OK snapshot {} ({}), targets v{}, timestamp v{}, demo={}, {} file and {} URL indicators, {} rules",
                pack.metadata.snapshot,
                pack.digest.hex(),
                verified.targets_version,
                verified.timestamp_version,
                pack.metadata.demo,
                pack.files.len(),
                pack.urls.len(),
                pack.metadata.rules.len(),
            ))
        });
    match outcome {
        Ok(report) => {
            println!("{report}");
            ExitCode::SUCCESS
        }
        Err(reason) => {
            println!("REJECTED {reason}");
            ExitCode::FAILURE
        }
    }
}
