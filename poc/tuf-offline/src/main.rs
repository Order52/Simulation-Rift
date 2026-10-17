//! PoC X2 — offline TUF verification with `tough` (docs/architecture.md §13.2).
//!
//! `tuf-offline load --root R --repo DIR --datastore DS [--target NAME --expect FILE]`
//! loads a repository through the filesystem transport, exactly as offline
//! import would, and prints `OK …` or `REJECTED …`.
//! `tuf-offline target-name NAME` reports whether tough accepts a target name.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use tough::{FilesystemTransport, IntoVec, Limits, RepositoryLoader, TargetName};
use url::Url;

/// Tight metadata limits: Rift's packs list a handful of targets, so anything
/// near tough's defaults (MiBs) indicates abuse rather than a real update.
const LIMITS: Limits = Limits {
    max_root_size: 64 * 1024,
    max_targets_size: 1024 * 1024,
    max_timestamp_size: 16 * 1024,
    max_snapshot_size: 64 * 1024,
    max_root_updates: 64,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .map(PathBuf::from)
    };
    let outcome = match args.first().map(String::as_str) {
        Some("load") => match (flag("--root"), flag("--repo"), flag("--datastore")) {
            (Some(root), Some(repo), Some(datastore)) => {
                let target = flag("--target").zip(flag("--expect"));
                load(&root, &repo, &datastore, target).await
            }
            _ => Err("missing --root/--repo/--datastore".to_owned()),
        },
        Some("target-name") => match args.get(1) {
            Some(name) => TargetName::new(name.as_str())
                .map(|n| format!("accepted as {:?}", n.resolved()))
                .map_err(|e| format!("{e}")),
            None => Err("missing name".to_owned()),
        },
        Some("rift-target-policy") => match args.get(1) {
            Some(name) => rift_staging_name(name).map(|n| format!("staged as {n:?}")),
            None => Err("missing name".to_owned()),
        },
        _ => Err("usage: tuf-offline load|target-name …".to_owned()),
    };
    match outcome {
        Ok(report) => {
            println!("OK {report}");
            ExitCode::SUCCESS
        }
        Err(reason) => {
            println!("REJECTED {}", reason.replace('\n', " "));
            ExitCode::FAILURE
        }
    }
}

/// Rift's rule for turning a repository target name into a staging file name.
/// tough *normalizes* `../x` to `x` and keeps absolute names absolute, so a
/// consumer joining `resolved()` onto a directory could escape it. Rift never
/// derives paths from repository names: only flat names from a fixed
/// allowlist are accepted, and the raw name must already be normalized.
fn rift_staging_name(raw: &str) -> Result<&'static str, String> {
    const PACK_FILES: [&str; 5] = [
        "url-hashes.bin",
        "file-hashes.bin",
        "rules.yar",
        "meta.json",
        "notices.txt",
    ];
    let name = TargetName::new(raw).map_err(|e| format!("{e}"))?;
    if name.resolved() != raw {
        return Err(format!("target name {raw:?} is not in normal form"));
    }
    PACK_FILES
        .into_iter()
        .find(|allowed| *allowed == raw)
        .ok_or_else(|| format!("target name {raw:?} is not a known pack file"))
}

async fn load(
    root: &Path,
    repo: &Path,
    datastore: &Path,
    target: Option<(PathBuf, PathBuf)>,
) -> Result<String, String> {
    let root_bytes = std::fs::read(root).map_err(|e| format!("read root: {e}"))?;
    let dir_url = |sub: &str| {
        let dir = std::fs::canonicalize(repo.join(sub)).map_err(|e| format!("{sub}: {e}"))?;
        Url::from_directory_path(dir).map_err(|()| format!("{sub}: not an absolute path"))
    };
    std::fs::create_dir_all(datastore).map_err(|e| format!("datastore: {e}"))?;

    let repository = RepositoryLoader::new(&root_bytes, dir_url("metadata")?, dir_url("targets")?)
        .transport(FilesystemTransport)
        .datastore(datastore)
        .limits(LIMITS)
        .load()
        .await
        .map_err(|e| format!("load: {e}"))?;

    let mut report = format!(
        "timestamp=v{} snapshot=v{} targets=v{}",
        repository.timestamp().signed.version,
        repository.snapshot().signed.version,
        repository.targets().signed.version,
    );
    if let Some((name, expect)) = target {
        let name =
            TargetName::new(name.to_string_lossy().into_owned()).map_err(|e| format!("{e}"))?;
        let stream = repository
            .read_target(&name)
            .await
            .map_err(|e| format!("read target: {e}"))?
            .ok_or_else(|| format!("target {name:?} not listed"))?;
        // tough verifies length and hash while streaming; an error here
        // means the bytes must not be used.
        let bytes = stream
            .into_vec()
            .await
            .map_err(|e| format!("target verification: {e}"))?;
        let expected = std::fs::read(&expect).map_err(|e| format!("expect file: {e}"))?;
        if bytes != expected {
            return Err("target content differs from expected file".to_owned());
        }
        report.push_str(&format!(
            "; target {} verified ({} bytes)",
            name.raw(),
            bytes.len()
        ));
    }
    Ok(report)
}
