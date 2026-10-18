//! Encrypted object store shared by session quarantine and the vault
//! (docs/architecture.md §11.1, §14).
//!
//! Lifecycle: `begin` → stream into a private `.part` file → `commit`
//! (finish the age stream, fsync, atomic rename to `objects/<id>.age`).
//! Anything not committed is deleted: dropping a [`PendingObject`] aborts it,
//! and `remove_abandoned` clears leftovers after a crash.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::transfer::SealingWriter;
use crate::vault::{self, ObjectId, Sealed, VaultError, VaultKey};

const OBJECTS: &str = "objects";
const PENDING: &str = "pending";

#[derive(Debug, Clone)]
pub struct ObjectStore {
    root: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredObject {
    pub id: ObjectId,
    pub sealed: Sealed,
}

impl ObjectStore {
    /// Opens (creating if needed) a store rooted at `root`.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, VaultError> {
        let root = root.into();
        for dir in [OBJECTS, PENDING] {
            create_private_dir(&root.join(dir))?;
        }
        Ok(Self { root })
    }

    /// Starts receiving an object of at most `limit` plaintext bytes.
    pub fn begin(
        &self,
        recipient: &age::x25519::Recipient,
        limit: u64,
    ) -> Result<PendingObject, VaultError> {
        let id = ObjectId::random()?;
        let part = self
            .root
            .join(PENDING)
            .join(format!("{}.part", id.to_hex()));
        let file = create_private_file(&part)?;
        let writer = SealingWriter::new(recipient, file, limit)?;
        Ok(PendingObject {
            id,
            part,
            destination: self.object_path(id),
            writer: Some(writer),
        })
    }

    /// Decrypts object `id` into `out`, verifying it against `expected`.
    /// On error the bytes written to `out` must be discarded.
    pub fn read(
        &self,
        id: ObjectId,
        key: &VaultKey,
        expected: &Sealed,
        out: impl Write,
    ) -> Result<(), VaultError> {
        let file = File::open(self.object_path(id))?;
        vault::open(key, io::BufReader::new(file), expected, out)
    }

    pub fn delete(&self, id: ObjectId) -> Result<(), VaultError> {
        match fs::remove_file(self.object_path(id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn contains(&self, id: ObjectId) -> bool {
        self.object_path(id).exists()
    }

    /// Deletes partial transfers left by a crash; returns how many were removed.
    pub fn remove_abandoned(&self) -> Result<usize, VaultError> {
        let mut removed = 0usize;
        for entry in fs::read_dir(self.root.join(PENDING))? {
            let path = entry?.path();
            if path.extension().is_some_and(|ext| ext == "part") {
                fs::remove_file(&path)?;
                removed = removed.saturating_add(1);
            }
        }
        Ok(removed)
    }

    fn object_path(&self, id: ObjectId) -> PathBuf {
        self.root.join(OBJECTS).join(format!("{}.age", id.to_hex()))
    }
}

/// An object being received. Write plaintext into it, then [`commit`](Self::commit).
#[derive(Debug)]
pub struct PendingObject {
    id: ObjectId,
    part: PathBuf,
    destination: PathBuf,
    writer: Option<SealingWriter<File>>,
}

impl PendingObject {
    pub fn id(&self) -> ObjectId {
        self.id
    }

    /// Finishes encryption, makes the bytes durable, and publishes the object
    /// atomically. Only a committed object is visible to readers.
    pub fn commit(mut self) -> Result<StoredObject, VaultError> {
        let writer = self
            .writer
            .take()
            .ok_or_else(|| io::Error::other("already finished"))?;
        let (sealed, file) = writer.finish_into_inner()?;
        file.sync_all()?;
        drop(file);
        fs::rename(&self.part, &self.destination)?;
        if let Some(dir) = self.destination.parent() {
            File::open(dir)?.sync_all()?;
        }
        Ok(StoredObject {
            id: self.id,
            sealed,
        })
    }
}

impl Write for PendingObject {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer
            .as_mut()
            .ok_or_else(|| io::Error::other("already finished"))?
            .write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.as_mut().map_or(Ok(()), Write::flush)
    }
}

impl Drop for PendingObject {
    fn drop(&mut self) {
        if self.writer.is_some() {
            // Not committed (error, limit exceeded, cancellation): discard.
            let _ = fs::remove_file(&self.part);
        }
    }
}

#[cfg(unix)]
pub(crate) fn create_private_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
pub(crate) fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)
}

pub(crate) fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, ObjectStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = ObjectStore::open(dir.path().join("quarantine")).unwrap();
        (dir, store)
    }

    #[test]
    fn commit_publishes_and_read_verifies() {
        let (_dir, store) = store();
        let key = VaultKey::generate();
        let mut pending = store.begin(&key.recipient(), 1 << 20).unwrap();
        let id = pending.id();
        assert!(!store.contains(id), "not visible before commit");
        pending.write_all(b"downloaded bytes").unwrap();
        let stored = pending.commit().unwrap();
        assert!(store.contains(id));
        let mut out = Vec::new();
        store
            .read(stored.id, &key, &stored.sealed, &mut out)
            .unwrap();
        assert_eq!(out, b"downloaded bytes");
    }

    #[test]
    fn exceeding_the_limit_leaves_nothing_behind() {
        let (dir, store) = store();
        let key = VaultKey::generate();
        let mut pending = store.begin(&key.recipient(), 10).unwrap();
        let id = pending.id();
        assert!(pending.write_all(b"more than ten bytes").is_err());
        drop(pending);
        assert!(!store.contains(id));
        let leftovers = fs::read_dir(dir.path().join("quarantine/pending"))
            .unwrap()
            .count();
        assert_eq!(leftovers, 0);
    }

    #[test]
    fn abandoned_parts_are_removed_after_a_crash() {
        let (_dir, store) = store();
        let key = VaultKey::generate();
        let mut pending = store.begin(&key.recipient(), 1 << 20).unwrap();
        pending.write_all(b"partial").unwrap();
        std::mem::forget(pending); // simulate a crash: no Drop, no commit
        assert_eq!(store.remove_abandoned().unwrap(), 1);
        assert_eq!(store.remove_abandoned().unwrap(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn files_and_directories_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, store) = store();
        let key = VaultKey::generate();
        let mut pending = store.begin(&key.recipient(), 1 << 20).unwrap();
        pending.write_all(b"x").unwrap();
        let stored = pending.commit().unwrap();
        let mode = |p: PathBuf| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(store.object_path(stored.id)), 0o600);
        assert_eq!(mode(dir.path().join("quarantine/objects")), 0o700);
    }

    #[test]
    fn reading_with_another_objects_record_fails() {
        let (_dir, store) = store();
        let key = VaultKey::generate();
        let put = |bytes: &[u8]| {
            let mut pending = store.begin(&key.recipient(), 1 << 20).unwrap();
            pending.write_all(bytes).unwrap();
            pending.commit().unwrap()
        };
        let a = put(b"object a");
        let b = put(b"object b");
        assert!(store.read(a.id, &key, &b.sealed, Vec::new()).is_err());
    }
}
