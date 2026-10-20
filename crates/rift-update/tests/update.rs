//! S16 (bad signature, hash, version, expiry) and offline import end to end,
//! against repositories signed by `rift-pack` with keys made for each test.
// The fixture helpers are test code too (clippy.toml covers only #[test] fns).
#![allow(clippy::unwrap_used)]

use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use rift_core::pack::Pack;
use rift_core::scan::{self, Evidence, RuleScan, Status};
use rift_core::snapshot::{InstallCheck, SnapshotStore};
use rift_pack::Release;
use rift_update::{Refusal, UpdateError};
use sha2::{Digest, Sha256};

struct Accept;
impl InstallCheck for Accept {
    fn check(&self, _: &Pack) -> Result<(), String> {
        Ok(())
    }
}

struct Refuse;
impl InstallCheck for Refuse {
    fn check(&self, _: &Pack) -> Result<(), String> {
        Err("rules did not compile in the worker".into())
    }
}

struct Fixture {
    dir: tempfile::TempDir,
    root: Vec<u8>,
    store: SnapshotStore,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        Self::with_keys(dir, "keys")
    }

    fn with_keys(dir: tempfile::TempDir, keys: &str) -> Self {
        let key_dir = dir.path().join(keys);
        std::fs::create_dir(&key_dir).unwrap();
        rift_pack::generate_keys(&key_dir).unwrap();
        let root_path = dir.path().join(format!("{keys}-root.json"));
        rift_pack::init_root(&key_dir, NonZeroU64::MIN, days(365), &root_path).unwrap();
        let root = std::fs::read(&root_path).unwrap();
        let (store, _) = SnapshotStore::open(dir.path().join("intel")).unwrap();
        Self { dir, root, store }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Publishes the demo pack as `version`, signed with `keys`, into a new directory.
    fn publish(&self, keys: &str, version: u64, release: Option<Release>) -> PathBuf {
        let pack = self.path(&format!("pack-{keys}-{version}"));
        std::fs::create_dir(&pack).unwrap();
        rift_pack::write_demo_pack(&pack, jiff::Timestamp::now()).unwrap();
        let repo = self.path(&format!("repo-{keys}-{version}"));
        let version = NonZeroU64::new(version).unwrap();
        let release =
            release.unwrap_or_else(|| Release::standard(version, jiff::Timestamp::now()).unwrap());
        rift_pack::publish(
            &self.path(&format!("{keys}-root.json")),
            &self.path(keys),
            &pack,
            &repo,
            &release,
        )
        .unwrap();
        repo
    }

    fn import(&self, repo: &Path, check: &dyn InstallCheck) -> Result<Pack, UpdateError> {
        rift_update::import_offline(&self.root, repo, &self.path("tuf"), &self.store, check)
    }

    fn current(&self) -> Option<String> {
        self.store.current().unwrap().map(|p| p.digest.hex())
    }
}

fn days(n: i64) -> jiff::Timestamp {
    jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_hours(n.saturating_mul(24)))
        .unwrap()
}

#[test]
fn offline_import_installs_a_verified_pack() {
    let f = Fixture::new();
    let pack = f.import(&f.publish("keys", 1, None), &Accept).unwrap();
    assert_eq!(f.current(), Some(pack.digest.hex()));
    assert!(pack.metadata.demo);

    // S21 through the installed pack: the demo file is found by its hash.
    let installed = f.store.current().unwrap().unwrap();
    let verdict = scan::assess(&Evidence {
        object: Sha256::digest(rift_pack::DEMO_FILE).into(),
        type_mismatch: None,
        pack: Some(&installed),
        rules: RuleScan::Completed {
            matched: vec!["rift_demo_marker".into()],
            truncated: false,
        },
        engine: "yara-x 1.21.0",
        now_unix: pack.metadata.created_unix,
    });
    assert_eq!(verdict.status, Status::KnownMalicious);
    assert_eq!(verdict.findings.len(), 2);
}

#[test]
fn s16_untrusted_signer_is_rejected() {
    let f = Fixture::new();
    let good = f.import(&f.publish("keys", 1, None), &Accept).unwrap();
    // A complete, self-consistent repository signed by other keys.
    let other = Fixture::with_keys(tempfile::tempdir().unwrap(), "other");
    let foreign = other.publish("other", 2, None);
    let error = f.import(&foreign, &Accept).unwrap_err();
    println!("result s16 untrusted signer: {error}");
    assert!(
        matches!(&error, UpdateError::Verify { refusal: Refusal::Signature, detail } if detail.contains("ignature")),
        "{error}"
    );
    assert_eq!(f.current(), Some(good.digest.hex()));
}

#[test]
fn s16_tampered_target_is_rejected() {
    let f = Fixture::new();
    let good = f.import(&f.publish("keys", 1, None), &Accept).unwrap();
    // Same length (the hash check) and appended bytes (the length check).
    for (version, tamper) in [(2u64, "same length"), (3, "appended")] {
        let repo = f.publish("keys", version, None);
        let rules = std::fs::read_dir(repo.join("targets"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.to_string_lossy().ends_with("rules.yar"))
            .unwrap();
        let mut bytes = std::fs::read(&rules).unwrap();
        if tamper == "appended" {
            bytes.extend_from_slice(b"rule injected { condition: true }\n");
        } else {
            let marker = bytes.windows(6).position(|w| w == b"MARKER").unwrap();
            bytes[marker] = b'N';
        }
        std::fs::write(&rules, bytes).unwrap();
        let error = f.import(&repo, &Accept).unwrap_err();
        println!("result s16 tampered target ({tamper}): {error}");
        assert_eq!(error.refusal(), Refusal::Tampered, "{error}");
        assert_eq!(f.current(), Some(good.digest.hex()));
    }
}

#[test]
fn s16_rollback_to_an_older_version_is_rejected() {
    let f = Fixture::new();
    let old = f.publish("keys", 1, None);
    f.import(&old, &Accept).unwrap();
    let new = f.import(&f.publish("keys", 2, None), &Accept).unwrap();
    let error = f.import(&old, &Accept).unwrap_err();
    println!("result s16 rollback: {error}");
    assert!(
        matches!(&error, UpdateError::Verify { refusal: Refusal::Rollback, detail } if detail.contains("version")),
        "{error}"
    );
    assert_eq!(f.current(), Some(new.digest.hex()));
}

#[test]
fn s16_expired_metadata_is_rejected() {
    let f = Fixture::new();
    let good = f.import(&f.publish("keys", 1, None), &Accept).unwrap();
    let version = NonZeroU64::new(2).unwrap();
    let mut release = Release::standard(version, jiff::Timestamp::now()).unwrap();
    release.timestamp_expires = days(-1);
    let error = f
        .import(&f.publish("keys", 2, Some(release)), &Accept)
        .unwrap_err();
    println!("result s16 expired: {error}");
    assert!(
        matches!(&error, UpdateError::Verify { refusal: Refusal::Expired, detail } if detail.contains("expired")),
        "{error}"
    );
    assert_eq!(f.current(), Some(good.digest.hex()));
}

#[test]
fn signed_packs_still_need_the_install_check() {
    let f = Fixture::new();
    let good = f.import(&f.publish("keys", 1, None), &Accept).unwrap();
    let error = f.import(&f.publish("keys", 2, None), &Refuse).unwrap_err();
    println!("result install check: {error}");
    assert!(matches!(error, UpdateError::Install(_)), "{error}");
    assert_eq!(error.refusal(), Refusal::Damaged);
    assert_eq!(f.current(), Some(good.digest.hex()));
}

#[test]
fn keys_are_refused_inside_a_git_work_tree() {
    let repo_keys = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(rift_pack::generate_keys(repo_keys).is_err());
}
