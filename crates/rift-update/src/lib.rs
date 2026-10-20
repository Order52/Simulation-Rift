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
//! Offline import (a repository directory) uses this exact code path. An
//! online transport is not part of this crate yet.

use std::path::Path;

use rift_core::pack::{self, Pack};
use rift_core::snapshot::{InstallCheck, SnapshotError, SnapshotStore};
use tough::{FilesystemTransport, IntoVec, Limits, RepositoryLoader, TargetName};
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
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|e| UpdateError::Storage(e.to_string()))?;
    runtime.block_on(verify(trusted_root, repository, datastore))
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

async fn verify(
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
    std::fs::create_dir_all(datastore).map_err(|e| UpdateError::Storage(e.to_string()))?;

    let repo = RepositoryLoader::new(&trusted_root, dir_url("metadata")?, dir_url("targets")?)
        .transport(FilesystemTransport)
        .datastore(datastore)
        .limits(LIMITS)
        .load()
        .await
        .map_err(|e| refused(&e, Stage::Metadata))?;

    let mut files = Vec::with_capacity(pack::FILES.len());
    for name in pack::FILES {
        let target = TargetName::new(name).map_err(|e| refused(&e, Stage::Metadata))?;
        let listed = repo
            .targets()
            .signed
            .targets
            .get(&target)
            .ok_or(UpdateError::NotListed(name))?;
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
