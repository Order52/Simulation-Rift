//! `rift-pack`: maintainer commands for intelligence packs. See the library docs.
//!
//! ```text
//! rift-pack keys <key-dir>                       one Ed25519 key per role (outside git)
//! rift-pack root <key-dir> <root.json> [version]  signed root, valid for 365 days
//! rift-pack demo <pack-dir>                       the harmless demo pack
//! rift-pack publish <root.json> <key-dir> <pack-dir> <repo-dir> <version>
//! ```

use std::num::NonZeroU64;
use std::path::Path;
use std::process::ExitCode;

use rift_pack::{Release, ToolError};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let arg = |i: usize| args.get(i).map(Path::new);
    let version = |i: usize| {
        args.get(i)
            .and_then(|v| v.parse::<u64>().ok())
            .and_then(NonZeroU64::new)
    };
    let now = jiff::Timestamp::now();
    let outcome: Result<String, ToolError> =
        match (args.first().map(String::as_str), arg(1), arg(2)) {
            (Some("keys"), Some(dir), None) => {
                rift_pack::generate_keys(dir).map(|()| "keys written".into())
            }
            (Some("root"), Some(keys), Some(out)) => {
                let expires = now
                    .checked_add(jiff::SignedDuration::from_hours(365 * 24))
                    .map_err(|e| ToolError::Tuf(e.to_string()));
                expires.and_then(|expires| {
                    rift_pack::init_root(keys, version(3).unwrap_or(NonZeroU64::MIN), expires, out)
                        .map(|()| format!("root written to {}", out.display()))
                })
            }
            (Some("demo"), Some(dir), None) => rift_pack::write_demo_pack(dir, now).map(|pack| {
                format!(
                    "demo pack {} ({})",
                    pack.metadata.snapshot,
                    pack.digest.hex()
                )
            }),
            (Some("publish"), Some(root), Some(keys)) => match (arg(3), arg(4), version(5)) {
                (Some(pack), Some(out), Some(v)) => Release::standard(v, now)
                    .and_then(|release| rift_pack::publish(root, keys, pack, out, &release))
                    .map(|()| format!("published version {v} to {}", out.display())),
                _ => Err(ToolError::Refused(
                    "usage: publish <root> <keys> <pack> <out> <version>".into(),
                )),
            },
            _ => Err(ToolError::Refused(
                "usage: rift-pack keys|root|demo|publish … (see the source header)".into(),
            )),
        };
    match outcome {
        Ok(report) => {
            println!("{report}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("rift-pack: {error}");
            ExitCode::FAILURE
        }
    }
}
