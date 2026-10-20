//! `rift-pack`: maintainer commands for intelligence packs. See the library docs.
//!
//! Development and tests (all role keys in one directory, 1-of-1):
//!
//! ```text
//! rift-pack keys <key-dir>                       one Ed25519 key per role (outside git)
//! rift-pack root <key-dir> <root.json> [version]  signed root, valid for 365 days
//! rift-pack demo <pack-dir>                       the harmless demo pack
//! rift-pack publish <root.json> <key-dir> <pack-dir> <repo-dir> <version>
//! ```
//!
//! Releases (docs/reports/key-policy.md), one key per holder:
//!
//! ```text
//! rift-pack key <key.pk8>                         one key (outside git)
//! rift-pack public <key.pk8> <key.pub.json>       its public half, to hand over
//! rift-pack root-draft <policy.json> <root.json>  an unsigned root from a policy
//! rift-pack root-sign <root.json> <key.pk8> [<previous-root.json>]
//! rift-pack root-check <root.json> [<previous-root.json>]
//! rift-pack targets-draft <pack-dir> <version> <targets.json>   valid for 90 days
//! rift-pack targets-sign <targets.json> <root.json> <key.pk8>
//! rift-pack publish-signed <targets.json> <pack-dir> <repo-dir> <version> <root.json>... -- <online-key.pk8>...
//! ```

use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use rift_pack::production::{self, OnlineRelease};
use rift_pack::{Release, ToolError};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match run(&args) {
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

fn version(raw: &str) -> Result<NonZeroU64, ToolError> {
    raw.parse::<u64>()
        .ok()
        .and_then(NonZeroU64::new)
        .ok_or_else(|| ToolError::Refused(format!("{raw:?} is not a version (1 or more)")))
}

fn days_from_now(days: i64) -> Result<jiff::Timestamp, ToolError> {
    jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_hours(days.saturating_mul(24)))
        .map_err(|e| ToolError::Tuf(e.to_string()))
}

fn run(args: &[&str]) -> Result<String, ToolError> {
    let now = jiff::Timestamp::now();
    match args {
        ["keys", dir] => rift_pack::generate_keys(Path::new(dir)).map(|()| "keys written".into()),
        ["root", keys, out, rest @ ..] if rest.len() <= 1 => {
            let v = rest.first().map(|v| version(v)).transpose()?;
            rift_pack::init_root(
                Path::new(keys),
                v.unwrap_or(NonZeroU64::MIN),
                days_from_now(365)?,
                Path::new(out),
            )
            .map(|()| format!("root written to {out}"))
        }
        ["demo", dir] => rift_pack::write_demo_pack(Path::new(dir), now).map(|pack| {
            format!(
                "demo pack {} ({})",
                pack.metadata.snapshot,
                pack.digest.hex()
            )
        }),
        ["publish", root, keys, pack, out, v] => {
            let v = version(v)?;
            let release = Release::standard(v, now)?;
            rift_pack::publish(
                Path::new(root),
                Path::new(keys),
                Path::new(pack),
                Path::new(out),
                &release,
            )
            .map(|()| format!("published version {v} to {out}"))
        }
        ["key", path] => {
            production::generate_key(Path::new(path)).map(|()| format!("key written to {path}"))
        }
        ["public", key, out] => production::export_public_key(Path::new(key), Path::new(out))
            .map(|id| format!("public key {id} written to {out}")),
        ["root-draft", policy, out] => production::draft_root(Path::new(policy), Path::new(out))
            .map(|()| format!("unsigned root written to {out}")),
        ["root-sign", root, key, previous @ ..] if previous.len() <= 1 => production::sign_root(
            Path::new(root),
            Path::new(key),
            previous.first().map(Path::new),
        )
        .map(|id| format!("{root} signed by key {id}")),
        ["root-check", root, previous @ ..] if previous.len() <= 1 => {
            production::check_root(Path::new(root), previous.first().map(Path::new))
        }
        ["targets-draft", pack, v, out] => {
            let v = version(v)?;
            production::draft_targets(Path::new(pack), v, days_from_now(90)?, Path::new(out)).map(
                |pack| {
                    format!(
                        "unsigned targets v{v} for {} written to {out}",
                        pack.digest.hex()
                    )
                },
            )
        }
        ["targets-sign", targets, root, key] => {
            production::sign_targets(Path::new(targets), Path::new(root), Path::new(key))
                .map(|id| format!("{targets} signed by key {id}"))
        }
        ["publish-signed", targets, pack, out, v, rest @ ..] => {
            let mut parts = rest.splitn(2, |a| *a == "--");
            let (roots, keys) = match (parts.next(), parts.next()) {
                (Some(roots), Some(keys)) if !roots.is_empty() && !keys.is_empty() => (roots, keys),
                _ => {
                    return Err(ToolError::Refused(
                        "publish-signed needs <root.json>... -- <online-key.pk8>...".into(),
                    ));
                }
            };
            let paths = |list: &[&str]| list.iter().map(PathBuf::from).collect::<Vec<_>>();
            let release = OnlineRelease {
                version: version(v)?,
                snapshot_expires: days_from_now(14)?,
                timestamp_expires: days_from_now(7)?,
            };
            production::publish_signed(
                &paths(roots),
                Path::new(targets),
                Path::new(pack),
                &paths(keys),
                &release,
                Path::new(out),
            )
            .map(|()| {
                format!(
                    "published snapshot and timestamp v{} to {out}",
                    release.version
                )
            })
        }
        _ => Err(ToolError::Refused(
            "usage: rift-pack keys|root|demo|publish|key|public|root-draft|root-sign|root-check|\
             targets-draft|targets-sign|publish-signed … (see the source header)"
                .into(),
        )),
    }
}
