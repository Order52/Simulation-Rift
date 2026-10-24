//! Installed intelligence snapshots (docs/architecture.md §13.1, INV-10).
//!
//! ```text
//! <root>/current                 the active pack's digest (64 hex digits)
//! <root>/snapshots/<digest>/     one directory per installed pack
//! <root>/staging/<random>/       an install in progress
//! ```
//!
//! Directories are named by the pack's own digest, never by anything a pack
//! says about itself. An install is made durable in staging, moved into
//! place, and only then made current by replacing the pointer (write, fsync,
//! rename). A crash at any point leaves either the old or the new pointer,
//! each naming a complete snapshot (S17). Every load validates the pack again
//! and checks its digest against the directory name.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::pack::{self, Pack, PackDigest, PackError};
use crate::store::{create_private_dir, create_private_file};

const CURRENT: &str = "current";
const CURRENT_TEMP: &str = "current.tmp";
const SNAPSHOTS: &str = "snapshots";
const STAGING: &str = "staging";

#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("storage: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Pack(#[from] PackError),
    #[error("the pack failed its install check: {0}")]
    Check(String),
    #[error("installed snapshot is damaged: {0}")]
    Damaged(String),
    #[cfg(test)]
    #[error("install interrupted (test)")]
    Interrupted,
}

/// Checks a validated pack before it may become current: the platform
/// compiles the rules in a worker and runs fixture lookups (§13.2).
pub trait InstallCheck {
    fn check(&self, pack: &Pack) -> Result<(), String>;
}

/// What opening the store cleaned up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OpenReport {
    /// Interrupted installs removed from staging.
    pub abandoned_installs: usize,
}

#[derive(Debug)]
pub struct SnapshotStore {
    root: PathBuf,
}

impl SnapshotStore {
    /// Opens (creating if needed) the store and removes interrupted installs.
    pub fn open(root: impl Into<PathBuf>) -> Result<(Self, OpenReport), SnapshotError> {
        let root = root.into();
        create_private_dir(&root.join(SNAPSHOTS))?;
        create_private_dir(&root.join(STAGING))?;
        let mut report = OpenReport::default();
        for entry in fs::read_dir(root.join(STAGING))? {
            fs::remove_dir_all(entry?.path())?;
            report.abandoned_installs = report.abandoned_installs.saturating_add(1);
        }
        match fs::remove_file(root.join(CURRENT_TEMP)) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        Ok((Self { root }, report))
    }

    /// The active pack, validated again, or `None` if none was ever installed.
    pub fn current(&self) -> Result<Option<Pack>, SnapshotError> {
        let pointer = match fs::read_to_string(self.root.join(CURRENT)) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let digest = pointer.strip_suffix('\n').unwrap_or(&pointer);
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(SnapshotError::Damaged(
                "the current pointer is malformed".into(),
            ));
        }
        let dir = self.root.join(SNAPSHOTS).join(digest);
        let mut files = Vec::with_capacity(pack::FILES.len());
        for name in pack::FILES {
            files.push((name, read_limited(&dir.join(name), name)?));
        }
        for name in pack::OPTIONAL {
            if dir.join(name).exists() {
                files.push((name, read_limited(&dir.join(name), name)?));
            }
        }
        let pack = Pack::validate(files.iter().map(|(n, b)| (*n, b.as_slice())))
            .map_err(|e| SnapshotError::Damaged(e.to_string()))?;
        if pack.digest.hex() != digest {
            return Err(SnapshotError::Damaged(
                "the pack's content does not match its directory".into(),
            ));
        }
        Ok(Some(pack))
    }

    /// Validates, checks and installs a pack, then makes it current. The
    /// previous snapshot is kept (scans pinned to it may still be running);
    /// older ones are removed.
    pub fn install<'a>(
        &self,
        files: impl IntoIterator<Item = (&'a str, &'a [u8])> + Clone,
        check: &dyn InstallCheck,
    ) -> Result<Pack, SnapshotError> {
        self.install_steps(files, check, |_| Ok(()))
    }

    fn install_steps<'a>(
        &self,
        files: impl IntoIterator<Item = (&'a str, &'a [u8])> + Clone,
        check: &dyn InstallCheck,
        after: impl Fn(StepMarker) -> Result<(), SnapshotError>,
    ) -> Result<Pack, SnapshotError> {
        let pack = Pack::validate(files.clone())?;
        check.check(&pack).map_err(SnapshotError::Check)?;
        let previous = self.current_digest();

        let hex = pack.digest.hex();
        let destination = self.root.join(SNAPSHOTS).join(&hex);
        if !destination.exists() {
            let staging = self.root.join(STAGING).join(random_name()?);
            create_private_dir(&staging)?;
            for (name, bytes) in files {
                // Names were checked by `validate`: only the fixed pack files.
                let mut file = create_private_file(&staging.join(name))?;
                file.write_all(bytes)?;
                file.sync_all()?;
            }
            File::open(&staging)?.sync_all()?;
            after(StepMarker::Staged)?;
            fs::rename(&staging, &destination)?;
            File::open(self.root.join(SNAPSHOTS))?.sync_all()?;
            after(StepMarker::Moved)?;
        }

        let temp = self.root.join(CURRENT_TEMP);
        let mut file = create_private_file(&temp)?;
        file.write_all(format!("{hex}\n").as_bytes())?;
        file.sync_all()?;
        drop(file);
        after(StepMarker::PointerWritten)?;
        fs::rename(&temp, self.root.join(CURRENT))?;
        File::open(&self.root)?.sync_all()?;

        let keep: Vec<String> = [Some(hex), previous.map(|d| d.hex())]
            .into_iter()
            .flatten()
            .collect();
        self.remove_others(&keep)?;
        Ok(pack)
    }

    fn current_digest(&self) -> Option<PackDigest> {
        // A damaged current pack is not worth keeping as "previous".
        self.current().ok().flatten().map(|p| p.digest)
    }

    fn remove_others(&self, keep: &[String]) -> Result<(), SnapshotError> {
        for entry in fs::read_dir(self.root.join(SNAPSHOTS))? {
            let entry = entry?;
            let name = entry.file_name();
            if !keep.iter().any(|k| name.to_str() == Some(k.as_str())) {
                fs::remove_dir_all(entry.path())?;
            }
        }
        Ok(())
    }
}

/// Points in an install where a test can stop it, as a crash would.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StepMarker {
    Staged,
    Moved,
    PointerWritten,
}

fn read_limited(path: &Path, name: &'static str) -> Result<Vec<u8>, SnapshotError> {
    let limit = pack::size_limit(name).unwrap_or(0);
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|e| SnapshotError::Damaged(format!("{name}: {e}")))?
        .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(SnapshotError::Damaged(format!(
            "{name} is over its size limit"
        )));
    }
    Ok(bytes)
}

fn random_name() -> Result<String, SnapshotError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::tests::{demo_rule, metadata, pack_files};

    struct Accept;
    impl InstallCheck for Accept {
        fn check(&self, _: &Pack) -> Result<(), String> {
            Ok(())
        }
    }
    struct Refuse;
    impl InstallCheck for Refuse {
        fn check(&self, _: &Pack) -> Result<(), String> {
            Err("rules did not compile".into())
        }
    }

    fn files(snapshot: &str) -> Vec<(&'static str, Vec<u8>)> {
        pack_files(
            &metadata(demo_rule()).replace("demo-1", snapshot),
            &[([1; 32], 0)],
        )
    }

    fn view<'a>(files: &'a [(&'static str, Vec<u8>)]) -> Vec<(&'static str, &'a [u8])> {
        files.iter().map(|(n, b)| (*n, b.as_slice())).collect()
    }

    fn snapshot_name(store: &SnapshotStore) -> Option<String> {
        store.current().unwrap().map(|p| p.metadata.snapshot)
    }

    #[test]
    fn a_model_is_installed_and_read_back() {
        use crate::urlmodel::{MIN_BITS, ModelParts, Suffixes, UrlModel};
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = SnapshotStore::open(dir.path()).unwrap();
        let model = UrlModel::encode(&ModelParts {
            bits: MIN_BITS,
            bias: 0.0,
            elevated: 0.5,
            high: 0.9,
            weights: vec![0.0; 1 << MIN_BITS],
            suffixes: Suffixes::default(),
            popular: Vec::new(),
            factors: None,
        })
        .unwrap();
        let mut with_model = files("with-model");
        with_model.push((pack::MODEL, model.clone()));
        let installed = store.install(view(&with_model), &Accept).unwrap();
        let current = store.current().unwrap().unwrap();
        assert_eq!(current.digest, installed.digest);
        assert_eq!(
            current.model.unwrap().digest_hex(),
            UrlModel::parse(&model).unwrap().digest_hex()
        );
        // The next pack has none, and none is read.
        store.install(view(&files("without")), &Accept).unwrap();
        assert!(store.current().unwrap().unwrap().model.is_none());
    }

    #[test]
    fn install_makes_a_pack_current_and_keeps_one_previous() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = SnapshotStore::open(dir.path()).unwrap();
        assert_eq!(snapshot_name(&store), None);
        for name in ["one", "two", "three"] {
            store.install(view(&files(name)), &Accept).unwrap();
            assert_eq!(snapshot_name(&store).as_deref(), Some(name));
        }
        assert_eq!(fs::read_dir(dir.path().join(SNAPSHOTS)).unwrap().count(), 2);
        // Reinstalling the current pack changes nothing.
        store.install(view(&files("three")), &Accept).unwrap();
        assert_eq!(snapshot_name(&store).as_deref(), Some("three"));
    }

    #[test]
    fn rejected_packs_leave_the_current_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = SnapshotStore::open(dir.path()).unwrap();
        store.install(view(&files("good")), &Accept).unwrap();

        let error = store.install(view(&files("bad")), &Refuse).unwrap_err();
        assert!(matches!(error, SnapshotError::Check(_)));
        let mut broken = files("broken");
        broken[1].1.truncate(10);
        assert!(matches!(
            store.install(view(&broken), &Accept),
            Err(SnapshotError::Pack(_))
        ));
        assert_eq!(snapshot_name(&store).as_deref(), Some("good"));
        assert_eq!(fs::read_dir(dir.path().join(SNAPSHOTS)).unwrap().count(), 1);
    }

    #[test]
    fn s17_interrupted_installs_leave_the_old_snapshot_and_are_cleaned() {
        for stop in [
            StepMarker::Staged,
            StepMarker::Moved,
            StepMarker::PointerWritten,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (store, _) = SnapshotStore::open(dir.path()).unwrap();
            store.install(view(&files("old")), &Accept).unwrap();
            let result = store.install_steps(view(&files("new")), &Accept, |step| {
                if step == stop {
                    Err(SnapshotError::Interrupted)
                } else {
                    Ok(())
                }
            });
            assert!(matches!(result, Err(SnapshotError::Interrupted)));
            drop(store);

            let (store, report) = SnapshotStore::open(dir.path()).unwrap();
            assert_eq!(snapshot_name(&store).as_deref(), Some("old"), "{stop:?}");
            assert_eq!(
                report.abandoned_installs,
                usize::from(stop == StepMarker::Staged)
            );
            assert!(!dir.path().join(CURRENT_TEMP).exists());
            // A later install of the same pack completes.
            store.install(view(&files("new")), &Accept).unwrap();
            assert_eq!(snapshot_name(&store).as_deref(), Some("new"));
        }
    }

    #[test]
    fn damaged_snapshots_are_refused_not_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = SnapshotStore::open(dir.path()).unwrap();
        let pack = store.install(view(&files("one")), &Accept).unwrap();
        let snapshot = dir.path().join(SNAPSHOTS).join(pack.digest.hex());

        // Same files, valid pack, but not the one the directory names.
        fs::write(
            snapshot.join(pack::RULES),
            "rule other { condition: true }\n",
        )
        .unwrap();
        assert!(matches!(store.current(), Err(SnapshotError::Damaged(_))));
        fs::remove_file(snapshot.join(pack::RULES)).unwrap();
        assert!(matches!(store.current(), Err(SnapshotError::Damaged(_))));

        for pointer in ["../../etc\n", "", &"A".repeat(64)] {
            fs::write(dir.path().join(CURRENT), pointer).unwrap();
            assert!(
                matches!(store.current(), Err(SnapshotError::Damaged(_))),
                "{pointer:?}"
            );
        }
    }
}
