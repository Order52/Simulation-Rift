//! Signed intelligence updates (docs/architecture.md §13.2, INV-10).
//!
//! A TUF repository is verified with `tough`: signatures and thresholds,
//! versions against the persisted trusted state (rollback), expiry, and the
//! length and hash of every target. Only the fixed pack files are read, by
//! name; nothing else a repository lists is fetched, and no filesystem path
//! is derived from a target name (Phase 0 finding, X2). The verified files
//! then go through [`SnapshotStore::install`], which validates the pack and
//! makes it current atomically.
//!
//! Offline import (a repository directory) and online updates use this
//! exact code path; only tough's transport differs. Online, tough fetches
//! through rift-core's own checked fetcher ([`CheckedTransport`]), so updates
//! add no second HTTP or TLS stack and obey INV-13 like downloads.

use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use rift_core::download::{self, DownloadError, DownloadPolicy};
use rift_core::pack::{self, Pack};
use rift_core::snapshot::{InstallCheck, SnapshotError, SnapshotStore};
use tough::schema::{Root, Signed};
use tough::{
    FilesystemTransport, IntoVec, Limits, RepositoryLoader, TargetName, Transport, TransportError,
    TransportErrorKind, TransportStream,
};
use url::Url;

/// Far below tough's defaults: a pack repository lists four small targets,
/// so metadata near the defaults (MiBs) means abuse, not a real update.
pub const LIMITS: Limits = Limits {
    max_root_size: 64 * 1024,
    max_targets_size: 1024 * 1024,
    max_timestamp_size: 16 * 1024,
    max_snapshot_size: 64 * 1024,
    max_root_updates: 64,
};

/// Why an update was refused, in terms a user can act on. The full error
/// (tough's, with paths and digests) is for the log only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Not signed by enough of the keys the trusted root names.
    Signature,
    /// Older than an update this device already trusted.
    Rollback,
    /// Signed metadata has expired, or the device clock moved backwards.
    Expired,
    /// A file differs from the hash or length its signed metadata states.
    Tampered,
    /// Metadata over the limits in [`LIMITS`], or a pack file over its limit.
    TooLarge,
    /// A file or field the update needs is missing or not well-formed.
    Damaged,
    /// The update or Rift's own state could not be read or written.
    Unreadable,
    /// The update server could not be reached, refused, or is not allowed (INV-13).
    Unreachable,
}

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("the update could not be verified: {detail}")]
    Verify { refusal: Refusal, detail: String },
    #[error("the update does not list {0}")]
    NotListed(&'static str),
    #[error("the update lists {name} as {length} bytes, over its limit of {limit}")]
    TooLarge {
        name: &'static str,
        length: u64,
        limit: usize,
    },
    #[error("the update could not be read: {0}")]
    Storage(String),
    #[error("{0:?} is not an http or https address of a directory")]
    Address(String),
    #[error(transparent)]
    Install(#[from] SnapshotError),
}

impl UpdateError {
    pub fn refusal(&self) -> Refusal {
        match self {
            Self::Verify { refusal, .. } => *refusal,
            Self::NotListed(_) => Refusal::Damaged,
            Self::TooLarge { .. } => Refusal::TooLarge,
            Self::Storage(_) => Refusal::Unreadable,
            Self::Address(_) => Refusal::Unreachable,
            Self::Install(SnapshotError::Io(_)) => Refusal::Unreadable,
            Self::Install(SnapshotError::Pack(pack::PackError::TooLarge { .. })) => {
                Refusal::TooLarge
            }
            Self::Install(_) => Refusal::Damaged,
        }
    }
}

/// Pack files from a verified repository, with the versions that vouched for them.
#[derive(Debug)]
pub struct Verified {
    pub files: Vec<(&'static str, Vec<u8>)>,
    pub targets_version: u64,
    pub timestamp_version: u64,
}

/// Verifies the repository at `repository` (with `metadata/` and `targets/`)
/// against `trusted_root`, recording what it trusted in `datastore` so a
/// later, older repository is refused.
pub fn verify_offline(
    trusted_root: &[u8],
    repository: &Path,
    datastore: &Path,
) -> Result<Verified, UpdateError> {
    let dir_url = |sub: &str| {
        let dir = std::fs::canonicalize(repository.join(sub))
            .map_err(|e| UpdateError::Storage(format!("{sub}: {e}")))?;
        Url::from_directory_path(dir)
            .map_err(|()| UpdateError::Storage(format!("{sub}: not an absolute path")))
    };
    let (metadata, targets) = (dir_url("metadata")?, dir_url("targets")?);
    block_on(verify(
        trusted_root,
        FilesystemTransport,
        metadata,
        targets,
        datastore,
    ))
}

/// Verifies the repository served at `metadata_url` and `targets_url`
/// (http or https directories) exactly as [`verify_offline`] does, fetched
/// through [`CheckedTransport`]. `local_hosts` are the host names the user
/// allowed to resolve to local addresses (INV-13); normally none.
pub fn verify_online(
    trusted_root: &[u8],
    metadata_url: &str,
    targets_url: &str,
    datastore: &Path,
    local_hosts: Vec<String>,
) -> Result<Verified, UpdateError> {
    let dir_url = |raw: &str| {
        let mut url = Url::parse(raw).map_err(|_| UpdateError::Address(raw.to_owned()))?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err(UpdateError::Address(raw.to_owned()));
        }
        if !url.path().ends_with('/') {
            let path = format!("{}/", url.path());
            url.set_path(&path);
        }
        Ok(url)
    };
    let (metadata, targets) = (dir_url(metadata_url)?, dir_url(targets_url)?);
    block_on(verify(
        trusted_root,
        CheckedTransport::new(local_hosts),
        metadata,
        targets,
        datastore,
    ))
}

/// tough is async; Rift drives one update at a time on a current-thread
/// runtime, so the blocking fetches in [`CheckedTransport`] stall nothing else.
fn block_on(
    update: impl Future<Output = Result<Verified, UpdateError>>,
) -> Result<Verified, UpdateError> {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|e| UpdateError::Storage(e.to_string()))?
        .block_on(update)
}

/// tough's transport over [`download::fetch`]: the same resolver checks,
/// per-hop redirects and bounded bodies as Rift's downloads, never a cookie.
/// Every byte it returns is still verified by tough before use.
#[derive(Debug, Clone)]
pub struct CheckedTransport {
    policy: DownloadPolicy,
}

impl CheckedTransport {
    pub fn new(local_hosts: Vec<String>) -> Self {
        Self {
            policy: DownloadPolicy {
                local_hosts,
                // The largest pack file (a 64 MiB table); tough's own limits
                // are lower for metadata and exact for targets.
                max_bytes: u64::try_from(pack::MAX_TABLE_BYTES).unwrap_or(u64::MAX),
                max_redirects: 5,
                connect_timeout: Duration::from_secs(20),
                response_timeout: Duration::from_secs(30),
                total_timeout: Duration::from_secs(5 * 60),
                // Signed metadata decides what is accepted, not the database it delivers.
                screen: None,
            },
        }
    }
}

const USER_AGENT: &str = "Rift-update";

#[async_trait]
impl Transport for CheckedTransport {
    async fn fetch(&self, url: Url) -> Result<TransportStream, TransportError> {
        // Updates are not cancelled midway; the policy's total timeout bounds each fetch.
        let never = AtomicBool::new(false);
        match download::fetch(
            url.as_str(),
            &self.policy,
            USER_AGENT,
            self.policy.max_bytes,
            &never,
        ) {
            Ok(bytes) => Ok(Box::pin(futures_util::stream::iter([Ok(Bytes::from(
                bytes,
            ))]))),
            // tough needs to know a file is absent (a root that has no successor).
            Err(DownloadError::Status(404 | 410)) => {
                Err(TransportError::new(TransportErrorKind::FileNotFound, url))
            }
            Err(e) => Err(TransportError::new_with_cause(
                TransportErrorKind::Other,
                url,
                e,
            )),
        }
    }
}

/// Verifies an offline repository and installs its pack as the current snapshot.
/// On any error the current snapshot is unchanged (S16).
pub fn import_offline(
    trusted_root: &[u8],
    repository: &Path,
    datastore: &Path,
    store: &SnapshotStore,
    check: &dyn InstallCheck,
) -> Result<Pack, UpdateError> {
    let verified = verify_offline(trusted_root, repository, datastore)?;
    let files = verified.files.iter().map(|(n, b)| (*n, b.as_slice()));
    Ok(store.install(files, check)?)
}

/// The newest root this device verified, saved in the datastore (§13.2).
///
/// tough walks forward from the root it is given and never reads back the
/// copy it keeps, so starting every update from the built-in root would let
/// a mirror undo a rotation: it hides the newer roots and signs with the
/// retired keys. Rift starts from the newer of the built-in root and this
/// one, and writes it atomically (tough's own copy is rewritten in place).
pub const TRUSTED_ROOT: &str = "trusted-root.json";

/// The root to start from: the saved one if it is newer than `built_in`.
/// A saved root that cannot be read or does not verify is refused, not
/// replaced by the built-in one, which could bring the retired keys back.
fn starting_root(built_in: &[u8], datastore: &Path) -> Result<(Vec<u8>, u64), UpdateError> {
    let version = |bytes: &[u8], what: &str| -> Result<u64, UpdateError> {
        let root: Signed<Root> = serde_json::from_slice(bytes)
            .map_err(|e| UpdateError::Storage(format!("{what}: {e}")))?;
        root.signed
            .verify_role(&root)
            .map_err(|e| UpdateError::Storage(format!("{what}: {e}")))?;
        Ok(root.signed.version.get())
    };
    let path = datastore.join(TRUSTED_ROOT);
    let saved = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((built_in.to_vec(), 0)),
        Err(e) => return Err(UpdateError::Storage(format!("the saved trusted root: {e}"))),
    };
    let saved_version = version(&saved, "the saved trusted root")?;
    // The built-in root is checked by tough; a newer one comes with an app update.
    let built_in_version = version(built_in, "the built-in root").unwrap_or(0);
    if saved_version > built_in_version {
        Ok((saved, saved_version))
    } else {
        Ok((built_in.to_vec(), saved_version))
    }
}

/// Temp file, fsync, rename, fsync the directory.
fn save_root(datastore: &Path, root: &Signed<Root>) -> Result<(), UpdateError> {
    let storage = |e: std::io::Error| UpdateError::Storage(format!("saving the trusted root: {e}"));
    let bytes = serde_json::to_vec(root).map_err(|e| UpdateError::Storage(e.to_string()))?;
    let temp = datastore.join(format!("{TRUSTED_ROOT}.tmp"));
    {
        let mut file = File::create(&temp).map_err(storage)?;
        file.write_all(&bytes).map_err(storage)?;
        file.sync_all().map_err(storage)?;
    }
    std::fs::rename(&temp, datastore.join(TRUSTED_ROOT)).map_err(storage)?;
    File::open(datastore)
        .and_then(|d| d.sync_all())
        .map_err(storage)
}

async fn verify(
    built_in_root: &[u8],
    transport: impl Transport + 'static,
    metadata: Url,
    targets: Url,
    datastore: &Path,
) -> Result<Verified, UpdateError> {
    std::fs::create_dir_all(datastore).map_err(|e| UpdateError::Storage(e.to_string()))?;
    let (trusted_root, saved_version) = starting_root(built_in_root, datastore)?;

    let repo = RepositoryLoader::new(&trusted_root, metadata, targets)
        .transport(transport)
        .datastore(datastore)
        .limits(LIMITS)
        .load()
        .await
        .map_err(|e| refused(&e, Stage::Metadata))?;
    // The whole metadata chain verified under this root: from now on it is
    // where updates start, even if a pack file below turns out bad.
    if repo.root().signed.version.get() > saved_version {
        save_root(datastore, repo.root())?;
    }

    let mut files = Vec::with_capacity(pack::FILES.len().saturating_add(pack::OPTIONAL.len()));
    let required = pack::FILES.iter().map(|name| (*name, true));
    for (name, needed) in required.chain(pack::OPTIONAL.iter().map(|name| (*name, false))) {
        let target = TargetName::new(name).map_err(|e| refused(&e, Stage::Metadata))?;
        let Some(listed) = repo.targets().signed.targets.get(&target) else {
            if needed {
                return Err(UpdateError::NotListed(name));
            }
            continue;
        };
        let limit = pack::size_limit(name).ok_or(UpdateError::NotListed(name))?;
        if listed.length > u64::try_from(limit).unwrap_or(u64::MAX) {
            return Err(UpdateError::TooLarge {
                name,
                length: listed.length,
                limit,
            });
        }
        // tough checks length and SHA-256 while streaming; an error means
        // none of these bytes may be used.
        let stream = repo
            .read_target(&target)
            .await
            .map_err(|e| refused(&e, Stage::Target))?
            .ok_or(UpdateError::NotListed(name))?;
        let bytes = stream
            .into_vec()
            .await
            .map_err(|e| refused(&e, Stage::Target))?;
        files.push((name, bytes));
    }
    Ok(Verified {
        files,
        targets_version: repo.targets().signed.version.get(),
        timestamp_version: repo.timestamp().signed.version.get(),
    })
}

/// Which part of the repository tough was reading when it failed.
#[derive(Clone, Copy)]
enum Stage {
    Metadata,
    /// A pack file, streamed against its signed length and hash: going over
    /// the length means the file was changed, not that a limit is too low.
    Target,
}

fn refused(error: &tough::error::Error, stage: Stage) -> UpdateError {
    UpdateError::Verify {
        refusal: classify(error, stage),
        detail: one_line(error),
    }
}

/// Walks the error's sources: tough reports a hash or length mismatch as
/// the cause of a transport error, so the innermost tough error decides.
fn classify(error: &tough::error::Error, stage: Stage) -> Refusal {
    use tough::error::Error as E;
    let mut found = Refusal::Damaged;
    let mut next: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(current) = next {
        if current.downcast_ref::<DownloadError>().is_some() {
            found = Refusal::Unreachable;
        }
        if let Some(e) = current.downcast_ref::<E>() {
            found = match e {
                E::VerifyMetadata { .. }
                | E::VerifyRoleMetadata { .. }
                | E::VerifyTrustedMetadata { .. } => Refusal::Signature,
                E::OlderMetadata { .. }
                | E::OlderSnapshotInTimestamp { .. }
                | E::SnapshotRoleRollback { .. } => Refusal::Rollback,
                E::ExpiredMetadata { .. } | E::SystemTimeSteppedBackward { .. } => Refusal::Expired,
                E::HashMismatch { .. } => Refusal::Tampered,
                E::MaxSizeExceeded { .. } | E::MaxUpdatesExceeded { .. } => match stage {
                    Stage::Metadata => Refusal::TooLarge,
                    Stage::Target => Refusal::Tampered,
                },
                E::DatastoreInit { .. }
                | E::DatastoreCreate { .. }
                | E::DatastoreOpen { .. }
                | E::DatastoreRemove { .. }
                | E::DatastoreSerialize { .. }
                | E::DirCreate { .. } => Refusal::Unreadable,
                _ => found,
            };
        }
        next = current.source();
    }
    found
}

fn one_line(error: &dyn std::fmt::Display) -> String {
    error.to_string().replace('\n', " ")
}
