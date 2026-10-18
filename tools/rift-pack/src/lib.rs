//! Maintainer tooling for intelligence packs (docs/architecture.md §13).
//!
//! - [`generate_keys`]: one Ed25519 key per TUF role, written outside any
//!   git work tree (private signing keys never go into source control).
//! - [`init_root`]: a signed `root.json` naming those keys (1-of-1 per role;
//!   a production key policy with offline root and targets keys is separate).
//! - [`write_demo_pack`]: the first-party demo pack. It is harmless: its
//!   indicators match only [`DEMO_FILE`] and a `.invalid` URL.
//! - [`publish`]: a signed repository (`metadata/`, `targets/`) for a pack.
//!
//! Every pack is validated with the app's own validator before it is written
//! or published, so the tool cannot produce a pack the app would refuse.

use std::fs;
use std::io::Write;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use aws_lc_rs::rand::SystemRandom;
use rift_core::intel::{FileTable, UrlTable};
use rift_core::pack::{self, Pack, PackError};
use rift_core::urlcanon;
use sha2::{Digest, Sha256};
use tough::editor::RepositoryEditor;
use tough::editor::signed::{PathExists, SignedRole};
use tough::key_source::{KeySource, LocalKeySource};
use tough::schema::{KeyHolder, RoleKeys, RoleType, Root, Signed};
use tough::sign::{Sign, parse_keypair};

/// The harmless file the demo pack's file indicator and marker rule match.
pub const DEMO_FILE: &[u8] = b"Simulation-Rift demo file. It is harmless. RIFT-DEMO-MARKER\n";
/// The demo pack's URL indicator. `.invalid` never resolves (RFC 6761).
pub const DEMO_URL: &str = "http://rift-demo.invalid/known-bad";
const DEMO_RULES: &str = r#"// Simulation-Rift demo rules. They match only Rift's own test content.
rule rift_demo_marker {
  strings:
    $marker = "RIFT-DEMO-MARKER"
  condition:
    $marker
}

rule rift_demo_hex {
  strings:
    $hex = { 52 49 46 54 2D 44 45 4D 4F 2D 48 45 58 }
  condition:
    $hex
}
"#;

/// File names of the role keys inside a key directory.
pub const ROLE_KEYS: [(RoleType, &str); 4] = [
    (RoleType::Root, "root.pk8"),
    (RoleType::Targets, "targets.pk8"),
    (RoleType::Snapshot, "snapshot.pk8"),
    (RoleType::Timestamp, "timestamp.pk8"),
];

#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    #[error("{path}: {error}")]
    Io {
        path: PathBuf,
        error: std::io::Error,
    },
    #[error("{0}")]
    Refused(String),
    #[error("signing: {0}")]
    Tuf(String),
    #[error("the pack is invalid: {0}")]
    Pack(#[from] PackError),
}

type Result<T> = std::result::Result<T, ToolError>;

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> ToolError + '_ {
    move |error| ToolError::Io {
        path: path.to_owned(),
        error,
    }
}

fn tuf(error: impl std::fmt::Display) -> ToolError {
    ToolError::Tuf(error.to_string())
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(io(Path::new("tokio runtime")))
}

/// Expiry and version of one release (§13.2: timestamp 7 d, snapshot 14 d,
/// targets 90 d).
#[derive(Debug, Clone, Copy)]
pub struct Release {
    pub version: NonZeroU64,
    pub timestamp_expires: jiff::Timestamp,
    pub snapshot_expires: jiff::Timestamp,
    pub targets_expires: jiff::Timestamp,
}

impl Release {
    pub fn standard(version: NonZeroU64, now: jiff::Timestamp) -> Result<Self> {
        let days = |d: i64| {
            now.checked_add(jiff::SignedDuration::from_hours(d.saturating_mul(24)))
                .map_err(tuf)
        };
        Ok(Self {
            version,
            timestamp_expires: days(7)?,
            snapshot_expires: days(14)?,
            targets_expires: days(90)?,
        })
    }
}

/// Refuses `dir` if it lies inside a git work tree.
pub fn refuse_inside_git(dir: &Path) -> Result<()> {
    let absolute = fs::canonicalize(dir).map_err(io(dir))?;
    if let Some(repo) = absolute.ancestors().find(|a| a.join(".git").exists()) {
        return Err(ToolError::Refused(format!(
            "{} is inside the git work tree at {}; keep signing keys out of source control",
            absolute.display(),
            repo.display()
        )));
    }
    Ok(())
}

/// Generates one Ed25519 key (PKCS#8) per role in `dir`, which must exist,
/// be outside any git work tree, and not already hold keys.
pub fn generate_keys(dir: &Path) -> Result<()> {
    refuse_inside_git(dir)?;
    let rng = SystemRandom::new();
    for (_, name) in ROLE_KEYS {
        let document = aws_lc_rs::signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| ToolError::Tuf("key generation failed".into()))?;
        let path = dir.join(name);
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path).map_err(io(&path))?;
        file.write_all(document.as_ref()).map_err(io(&path))?;
        file.sync_all().map_err(io(&path))?;
    }
    Ok(())
}

fn key_sources(dir: &Path) -> Vec<Box<dyn KeySource>> {
    ROLE_KEYS
        .iter()
        .map(|(_, name)| {
            Box::new(LocalKeySource {
                path: dir.join(name),
            }) as Box<dyn KeySource>
        })
        .collect()
}

/// Writes a signed root (version `version`) naming the keys in `keys`.
pub fn init_root(
    keys: &Path,
    version: NonZeroU64,
    expires: jiff::Timestamp,
    out: &Path,
) -> Result<()> {
    let mut root = Root {
        spec_version: "1.0.0".into(),
        consistent_snapshot: true,
        version,
        expires,
        keys: Default::default(),
        roles: Default::default(),
        _extra: Default::default(),
    };
    for (role, name) in ROLE_KEYS {
        let path = keys.join(name);
        let key = parse_keypair(&fs::read(&path).map_err(io(&path))?)
            .map_err(tuf)?
            .tuf_key();
        let id = key.key_id().map_err(tuf)?;
        root.keys.insert(id.clone(), key);
        root.roles.insert(
            role,
            RoleKeys {
                keyids: vec![id],
                threshold: NonZeroU64::MIN,
                _extra: Default::default(),
            },
        );
    }
    let root_key: Vec<Box<dyn KeySource>> = vec![Box::new(LocalKeySource {
        path: keys.join(ROLE_KEYS[0].1),
    })];
    let signed: SignedRole<Root> = runtime()?
        .block_on(SignedRole::new(
            root.clone(),
            &KeyHolder::Root(root),
            &root_key,
            &SystemRandom::new(),
        ))
        .map_err(tuf)?;
    fs::write(out, signed.buffer()).map_err(io(out))
}

/// Reads a root file written by [`init_root`] (for checks and tests).
pub fn read_root(path: &Path) -> Result<Signed<Root>> {
    serde_json::from_slice(&fs::read(path).map_err(io(path))?).map_err(tuf)
}

/// Writes the demo pack's four files into `dir` (which must exist).
pub fn write_demo_pack(dir: &Path, created: jiff::Timestamp) -> Result<Pack> {
    let created_unix = u64::try_from(created.as_second()).map_err(tuf)?;
    let metadata = serde_json::json!({
        "format": 1,
        "snapshot": format!("demo-{}", created.strftime("%Y%m%dT%H%M%SZ")),
        "created_unix": created_unix,
        "refresh_after_unix": created_unix.saturating_add(7 * 24 * 3600),
        "demo": true,
        "sources": [{"id": "rift-demo", "name": "Simulation-Rift demo data", "license": "CC0-1.0"}],
        "indicators": [
            {"id": "demo-file", "source": "rift-demo", "confidence": "high",
             "description": "Demo indicator: Simulation-Rift's harmless test file."},
            {"id": "demo-url", "source": "rift-demo", "confidence": "high",
             "description": "Demo indicator: a test address that never resolves."}
        ],
        "rules": [
            {"id": "rift_demo_marker", "source": "rift-demo", "confidence": "high",
             "description": "Demo rule: Simulation-Rift's test marker text."},
            {"id": "rift_demo_hex", "source": "rift-demo", "confidence": "low",
             "description": "Demo rule: a test byte pattern."}
        ],
        "notices": ["DEMO: not real coverage. These indicators match only Simulation-Rift's own test content."]
    });
    let url = urlcanon::canonicalize(DEMO_URL.as_bytes())
        .map_err(|e| ToolError::Refused(format!("demo URL: {e}")))?;
    let expression = url
        .expressions()
        .into_iter()
        .find(|e| e == "rift-demo.invalid/known-bad")
        .ok_or_else(|| ToolError::Refused("demo URL expression missing".into()))?;
    let files = [
        (
            pack::METADATA,
            serde_json::to_vec_pretty(&metadata).map_err(tuf)?,
        ),
        (
            pack::URL_TABLE,
            UrlTable::encode(vec![(urlcanon::expression_hash(&expression), 1)]).map_err(|e| {
                ToolError::Pack(PackError::Table {
                    name: pack::URL_TABLE,
                    error: e,
                })
            })?,
        ),
        (
            pack::FILE_TABLE,
            FileTable::encode(vec![(Sha256::digest(DEMO_FILE).into(), 0)]).map_err(|e| {
                ToolError::Pack(PackError::Table {
                    name: pack::FILE_TABLE,
                    error: e,
                })
            })?,
        ),
        (pack::RULES, DEMO_RULES.as_bytes().to_vec()),
    ];
    write_pack(dir, &files)
}

/// Validates `files` as a pack, then writes them into `dir`.
pub fn write_pack(dir: &Path, files: &[(&'static str, Vec<u8>)]) -> Result<Pack> {
    let pack = Pack::validate(files.iter().map(|(n, b)| (*n, b.as_slice())))?;
    for (name, bytes) in files {
        let path = dir.join(name);
        fs::write(&path, bytes).map_err(io(&path))?;
    }
    Ok(pack)
}

/// Publishes the pack in `pack_dir` as a signed repository in `out`
/// (`metadata/` and `targets/`), signed with the role keys in `keys`.
pub fn publish(
    root: &Path,
    keys: &Path,
    pack_dir: &Path,
    out: &Path,
    release: &Release,
) -> Result<()> {
    let files: Vec<(&'static str, Vec<u8>)> = pack::FILES
        .iter()
        .map(|name| {
            let path = pack_dir.join(name);
            fs::read(&path).map(|b| (*name, b)).map_err(io(&path))
        })
        .collect::<Result<_>>()?;
    Pack::validate(files.iter().map(|(n, b)| (*n, b.as_slice())))?;

    runtime()?.block_on(async {
        let mut editor = RepositoryEditor::new(root).await.map_err(tuf)?;
        editor
            .targets_version(release.version)
            .map_err(tuf)?
            .targets_expires(release.targets_expires)
            .map_err(tuf)?
            .snapshot_version(release.version)
            .snapshot_expires(release.snapshot_expires)
            .timestamp_version(release.version)
            .timestamp_expires(release.timestamp_expires);
        for name in pack::FILES {
            let (target_name, target) = RepositoryEditor::build_target(pack_dir.join(name))
                .await
                .map_err(tuf)?;
            editor.add_target(target_name, target).map_err(tuf)?;
        }
        let signed = editor.sign(&key_sources(keys)).await.map_err(tuf)?;
        signed.write(out.join("metadata")).await.map_err(tuf)?;
        signed
            .copy_targets(pack_dir, out.join("targets"), PathExists::Replace)
            .await
            .map_err(tuf)
    })
}
