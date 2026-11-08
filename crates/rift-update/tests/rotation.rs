//! The production key policy (docs/reports/key-policy.md) against the
//! client: threshold roots, targets signed offline, root rotation by
//! cross-signing, and keys that a rotation retired. Every repository is made
//! with `rift_pack::production`, one key per holder, as a release would be.
// The fixture helpers are test code too (clippy.toml covers only #[test] fns).
#![allow(clippy::unwrap_used)]

use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use rift_core::pack::Pack;
use rift_core::snapshot::{InstallCheck, SnapshotStore};
use rift_pack::production::{self, OnlineRelease};
use rift_update::{Refusal, UpdateError};

struct Accept;
impl InstallCheck for Accept {
    fn check(&self, _: &Pack) -> Result<(), String> {
        Ok(())
    }
}

/// The holders of one generation of keys: root 2 of 3 and targets 2 of 2
/// (offline), snapshot and timestamp 1 of 1 (online).
const ROOT: [&str; 3] = ["root-a", "root-b", "root-c"];
const TARGETS: [&str; 2] = ["targets-a", "targets-b"];
const ONLINE: [&str; 2] = ["snapshot", "timestamp"];
/// The online key of the delegated model role (key-policy.md): its own key, in no root role.
const MODEL: &str = "model";

struct Maintainers {
    dir: tempfile::TempDir,
    /// The root built into the app.
    built_in: Vec<u8>,
    store: SnapshotStore,
}

impl Maintainers {
    /// Keys for generation `g`, and its root as version 1, signed by `signers`.
    fn new(g: &str, signers: &[&str]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = SnapshotStore::open(dir.path().join("intel")).unwrap();
        let mut m = Self {
            dir,
            built_in: Vec::new(),
            store,
        };
        m.keys(g);
        let root = m.draft(g, 1);
        m.sign(&root, g, signers, None);
        m.built_in = std::fs::read(&root).unwrap();
        m
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn key(&self, g: &str, holder: &str) -> PathBuf {
        self.path(&format!("{g}-{holder}.pk8"))
    }

    fn keys(&self, g: &str) {
        for holder in ROOT.iter().chain(&TARGETS).chain(&ONLINE).chain(&[MODEL]) {
            production::generate_key(&self.key(g, holder)).unwrap();
            production::export_public_key(
                &self.key(g, holder),
                &self.path(&format!("{g}-{holder}.pub.json")),
            )
            .unwrap();
        }
    }

    fn policy(&self, g: &str, version: u64) -> PathBuf {
        let keys = |holders: &[&str]| {
            holders
                .iter()
                .map(|h| format!("{g}-{h}.pub.json"))
                .collect::<Vec<_>>()
        };
        let policy = serde_json::json!({
            "version": version,
            "expires": days(365).to_string(),
            "root": {"threshold": 2, "keys": keys(&ROOT)},
            "targets": {"threshold": 2, "keys": keys(&TARGETS)},
            "snapshot": {"threshold": 1, "keys": keys(&ONLINE[..1])},
            "timestamp": {"threshold": 1, "keys": keys(&ONLINE[1..])},
        });
        let path = self.path(&format!("policy-{g}-{version}.json"));
        std::fs::write(&path, serde_json::to_vec_pretty(&policy).unwrap()).unwrap();
        path
    }

    /// An unsigned root of generation `g` as `version`.
    fn draft(&self, g: &str, version: u64) -> PathBuf {
        let root = self.path(&format!("root-v{version}-{g}.json"));
        production::draft_root(&self.policy(g, version), &root).unwrap();
        root
    }

    fn sign(&self, root: &Path, g: &str, holders: &[&str], previous: Option<&Path>) {
        for holder in holders {
            production::sign_root(root, &self.key(g, holder), previous).unwrap();
        }
    }

    /// The demo pack as release `version`, targets signed offline by `signers`
    /// of generation `g`, published with `g`'s online keys over `roots`.
    fn release(
        &self,
        roots: &[&Path],
        g: &str,
        signers: &[&str],
        version: u64,
    ) -> Result<PathBuf, rift_pack::ToolError> {
        let pack = self.path(&format!("pack-{g}-{version}"));
        std::fs::create_dir(&pack).unwrap();
        rift_pack::write_demo_pack(&pack, jiff::Timestamp::now()).unwrap();
        let version = NonZeroU64::new(version).unwrap();
        let targets = self.path(&format!("targets-{g}-{version}.json"));
        production::draft_targets(&pack, version, days(90), &targets).unwrap();
        let newest = roots.last().unwrap();
        for holder in signers {
            production::sign_targets(&targets, newest, &self.key(g, holder)).unwrap();
        }
        let repo = self.path(&format!("repo-{g}-{version}"));
        let roots: Vec<PathBuf> = roots.iter().map(|p| p.to_path_buf()).collect();
        let online: Vec<PathBuf> = ONLINE.iter().map(|h| self.key(g, h)).collect();
        let release = OnlineRelease {
            version,
            snapshot_expires: days(14),
            timestamp_expires: days(7),
        };
        production::publish_signed(&roots, &targets, &pack, &online, None, &release, &repo)?;
        Ok(repo)
    }

    /// As [`Self::release`], with `model` (a model file) delegated to generation
    /// `g`'s model key; `signing_key` is the key the publisher is given for it
    /// (the right one is `key(g, MODEL)`).
    fn release_with_model(
        &self,
        roots: &[&Path],
        g: &str,
        version: u64,
        model: &[u8],
        signing_key: &Path,
    ) -> Result<PathBuf, rift_pack::ToolError> {
        let pack = self.path(&format!("pack-model-{g}-{version}"));
        std::fs::create_dir(&pack).unwrap();
        rift_pack::write_demo_pack(&pack, jiff::Timestamp::now()).unwrap();
        std::fs::write(pack.join(rift_core::pack::MODEL), model).unwrap();
        let version = NonZeroU64::new(version).unwrap();
        let targets = self.path(&format!("targets-model-{g}-{version}.json"));
        production::draft_targets_delegating_model(
            &pack,
            version,
            days(90),
            &targets,
            &self.path(&format!("{g}-{MODEL}.pub.json")),
        )?;
        let newest = roots.last().unwrap();
        for holder in TARGETS {
            production::sign_targets(&targets, newest, &self.key(g, holder))?;
        }
        let repo = self.path(&format!("repo-model-{g}-{version}"));
        let roots: Vec<PathBuf> = roots.iter().map(|p| p.to_path_buf()).collect();
        let online: Vec<PathBuf> = ONLINE.iter().map(|h| self.key(g, h)).collect();
        let release = OnlineRelease {
            version,
            snapshot_expires: days(14),
            timestamp_expires: days(7),
        };
        production::publish_signed(
            &roots,
            &targets,
            &pack,
            &online,
            Some(signing_key),
            &release,
            &repo,
        )?;
        Ok(repo)
    }

    fn import(&self, repo: &Path) -> Result<Pack, UpdateError> {
        rift_update::import_offline(
            &self.built_in,
            repo,
            &self.path("tuf"),
            &self.store,
            &Accept,
        )
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

fn root_v1(m: &Maintainers) -> PathBuf {
    m.path("root-v1-a.json")
}

#[test]
fn a_threshold_root_installs_offline_signed_targets() {
    let m = Maintainers::new("a", &ROOT[..2]);
    let summary = production::check_root(&root_v1(&m), None).unwrap();
    println!("result key policy root: {summary}");
    assert!(summary.contains("root 2 of 3") && summary.contains("targets 2 of 2"));
    let repo = m.release(&[&root_v1(&m)], "a", &TARGETS, 1).unwrap();
    let pack = m.import(&repo).unwrap();
    assert_eq!(m.current(), Some(pack.digest.hex()));
}

#[test]
fn signatures_short_of_a_threshold_are_refused() {
    // A root signed by one of its three root keys: the tool refuses it, and
    // so does a client that was given it as its trusted root.
    let m = Maintainers::new("a", &ROOT[..1]);
    let error = production::check_root(&root_v1(&m), None).unwrap_err();
    println!("result key policy 1 of 2-of-3 root: {error}");
    assert!(error.to_string().contains("own root threshold"), "{error}");

    let full = m.path("root-v1-full.json");
    std::fs::copy(root_v1(&m), &full).unwrap();
    m.sign(&full, "a", &ROOT[1..2], None);
    let repo = m.release(&[&full], "a", &TARGETS, 1).unwrap();
    let error = m.import(&repo).unwrap_err();
    assert_eq!(error.refusal(), Refusal::Signature, "{error}");
    assert_eq!(m.current(), None);

    // Targets signed by one of their two keys are not published.
    let error = m.release(&[&full], "a", &TARGETS[..1], 2).unwrap_err();
    println!("result key policy 1 of 2-of-2 targets: {error}");
    assert!(error.to_string().contains("targets threshold"), "{error}");
}

/// Generation b replaces every key of generation a in root v2, signed by two
/// of b's root keys and cross-signed by two of a's.
fn rotate(m: &Maintainers, cross_signers: &[&str]) -> PathBuf {
    m.keys("b");
    let v2 = m.draft("b", 2);
    m.sign(&v2, "b", &ROOT[..2], None);
    m.sign(&v2, "a", cross_signers, Some(&root_v1(m)));
    v2
}

#[test]
fn a_rotation_is_followed_and_the_retired_keys_cannot_return() {
    let m = Maintainers::new("a", &ROOT[..2]);
    m.import(&m.release(&[&root_v1(&m)], "a", &TARGETS, 1).unwrap())
        .unwrap();

    let v2 = rotate(&m, &ROOT[1..]);
    let summary = production::check_root(&v2, Some(&root_v1(&m))).unwrap();
    println!("result key policy rotation: {summary}");
    assert!(summary.contains("cross-signed by v1"), "{summary}");
    // The app still has root v1 built in; it walks to v2.
    let rotated = m
        .import(&m.release(&[&root_v1(&m), &v2], "b", &TARGETS, 2).unwrap())
        .unwrap();
    assert_eq!(m.current(), Some(rotated.digest.hex()));

    // Whoever holds generation a's keys (the reason for a rotation) offers a
    // newer release signed with them and hides root v2. The device trusts v2
    // now, so a's keys sign nothing it accepts.
    let replay = m.release(&[&root_v1(&m)], "a", &TARGETS, 3).unwrap();
    let error = m.import(&replay).unwrap_err();
    println!("result key policy retired keys: {error}");
    assert_eq!(error.refusal(), Refusal::Signature, "{error}");
    assert_eq!(m.current(), Some(rotated.digest.hex()));
}

#[test]
fn a_rotation_needs_the_previous_root_threshold() {
    let m = Maintainers::new("a", &ROOT[..2]);
    m.import(&m.release(&[&root_v1(&m)], "a", &TARGETS, 1).unwrap())
        .unwrap();
    let good = m.current();

    // Root v2 with only one of generation a's root signatures.
    let v2 = rotate(&m, &ROOT[2..]);
    let error = production::check_root(&v2, Some(&root_v1(&m))).unwrap_err();
    println!("result key policy weak rotation: {error}");
    assert!(
        error.to_string().contains("root threshold of v1"),
        "{error}"
    );

    // The tool will not publish it, so the repository is made with a good v2
    // and its v2 is then replaced: a mirror can serve any root file.
    let full = m.path("root-v2-full.json");
    std::fs::copy(&v2, &full).unwrap();
    m.sign(&full, "a", &ROOT[..1], Some(&root_v1(&m)));
    assert!(m.release(&[&root_v1(&m), &v2], "b", &TARGETS, 2).is_err());
    let repo = m.release(&[&root_v1(&m), &full], "b", &TARGETS, 3).unwrap();
    std::fs::copy(&v2, repo.join("metadata/2.root.json")).unwrap();
    let error = m.import(&repo).unwrap_err();
    assert_eq!(error.refusal(), Refusal::Signature, "{error}");
    assert_eq!(m.current(), good);
}

#[test]
fn a_damaged_saved_root_is_refused_not_replaced_by_the_built_in_one() {
    let m = Maintainers::new("a", &ROOT[..2]);
    m.import(&m.release(&[&root_v1(&m)], "a", &TARGETS, 1).unwrap())
        .unwrap();
    let v2 = rotate(&m, &ROOT[1..]);
    m.import(&m.release(&[&root_v1(&m), &v2], "b", &TARGETS, 2).unwrap())
        .unwrap();
    let saved = m.path("tuf").join(rift_update::TRUSTED_ROOT);
    let bytes = std::fs::read(&saved).unwrap();
    std::fs::write(&saved, &bytes[..bytes.len() / 2]).unwrap();
    let error = m
        .import(&m.release(&[&root_v1(&m), &v2], "b", &TARGETS, 3).unwrap())
        .unwrap_err();
    println!("result key policy damaged saved root: {error}");
    assert_eq!(error.refusal(), Refusal::Unreadable, "{error}");
}

#[test]
fn the_tool_keeps_offline_and_online_keys_apart() {
    let m = Maintainers::new("a", &ROOT[..2]);

    // A policy that lets the timestamp key sign targets.
    let policy = m.policy("a", 2);
    let mut parsed: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&policy).unwrap()).unwrap();
    parsed["targets"]["keys"][1] = "a-timestamp.pub.json".into();
    std::fs::write(&policy, parsed.to_string()).unwrap();
    let error = production::draft_root(&policy, &m.path("mixed.json")).unwrap_err();
    println!("result key policy shared key: {error}");
    assert!(
        error.to_string().contains("offline") && error.to_string().contains("online"),
        "{error}"
    );

    // A stranger's key, and the same holder twice, cannot sign a root.
    m.keys("x");
    let v2 = m.draft("a", 2);
    assert!(production::sign_root(&v2, &m.key("x", "root-a"), None).is_err());
    production::sign_root(&v2, &m.key("a", "root-a"), None).unwrap();
    let error = production::sign_root(&v2, &m.key("a", "root-a"), None).unwrap_err();
    assert!(error.to_string().contains("already signed"), "{error}");

    // An offline key handed to the publishing machine is refused, not used.
    let pack = m.path("pack");
    std::fs::create_dir(&pack).unwrap();
    rift_pack::write_demo_pack(&pack, jiff::Timestamp::now()).unwrap();
    let targets = m.path("targets.json");
    production::draft_targets(&pack, NonZeroU64::MIN, days(90), &targets).unwrap();
    for holder in TARGETS {
        production::sign_targets(&targets, &root_v1(&m), &m.key("a", holder)).unwrap();
    }
    let online = vec![
        m.key("a", "snapshot"),
        m.key("a", "timestamp"),
        m.key("a", "root-c"),
    ];
    let release = OnlineRelease {
        version: NonZeroU64::MIN,
        snapshot_expires: days(14),
        timestamp_expires: days(7),
    };
    let error = production::publish_signed(
        &[root_v1(&m)],
        &targets,
        &pack,
        &online,
        None,
        &release,
        &m.path("repo"),
    )
    .unwrap_err();
    println!("result key policy offline key online: {error}");
    assert!(
        error.to_string().contains("offline keys do not belong"),
        "{error}"
    );
}

/// The model the apps ship; any valid model file would do.
const A_MODEL: &[u8] = include_bytes!("../../../models/url-model.bin");

#[test]
fn a_model_signed_by_the_delegated_model_key_is_installed() {
    let m = Maintainers::new("a", &ROOT[..2]);
    let repo = m
        .release_with_model(&[&root_v1(&m)], "a", 1, A_MODEL, &m.key("a", MODEL))
        .unwrap();
    // The metadata has the model role, signed by its own key, listed in the snapshot.
    let model_json = std::fs::read_to_string(repo.join("metadata/1.model.json")).unwrap();
    assert!(model_json.contains(rift_core::pack::MODEL));
    let snapshot = std::fs::read_to_string(repo.join("metadata/1.snapshot.json")).unwrap();
    assert!(snapshot.contains("model.json"));
    let pack = m.import(&repo).unwrap();
    let installed = pack.model.expect("the delegated model is in the pack");
    assert_eq!(
        installed.digest_hex(),
        rift_core::urlmodel::UrlModel::parse(A_MODEL)
            .unwrap()
            .digest_hex()
    );
}

#[test]
fn the_tool_refuses_a_model_key_that_is_not_the_delegated_one_or_not_its_own() {
    let m = Maintainers::new("a", &ROOT[..2]);
    // The publisher is handed another online key (the snapshot key) for the model.
    let error = m
        .release_with_model(&[&root_v1(&m)], "a", 1, A_MODEL, &m.key("a", "snapshot"))
        .unwrap_err();
    println!("result model key wrong: {error}");
    // A delegation to a key that already signs a root role is refused when the
    // targets holders sign it.
    let pack = m.path("pack-shared");
    std::fs::create_dir(&pack).unwrap();
    rift_pack::write_demo_pack(&pack, jiff::Timestamp::now()).unwrap();
    std::fs::write(pack.join(rift_core::pack::MODEL), A_MODEL).unwrap();
    let targets = m.path("targets-shared.json");
    production::draft_targets_delegating_model(
        &pack,
        NonZeroU64::MIN,
        days(90),
        &targets,
        &m.path("a-snapshot.pub.json"),
    )
    .unwrap();
    let error =
        production::sign_targets(&targets, &root_v1(&m), &m.key("a", TARGETS[0])).unwrap_err();
    println!("result model key shared: {error}");
    assert!(error.to_string().contains("must be its own key"), "{error}");
}

#[test]
fn a_changed_model_role_is_refused() {
    let m = Maintainers::new("a", &ROOT[..2]);
    let repo = m
        .release_with_model(&[&root_v1(&m)], "a", 1, A_MODEL, &m.key("a", MODEL))
        .unwrap();
    // A model.json that is not the one the snapshot pinned (its hash and length).
    let path = repo.join("metadata/1.model.json");
    let changed = std::fs::read_to_string(&path)
        .unwrap()
        .replace("\"version\": 1", "\"version\": 7");
    std::fs::write(&path, changed).unwrap();
    let error = m.import(&repo).unwrap_err();
    println!("result model role changed: {error}");
    assert!(m.current().is_none());
}
