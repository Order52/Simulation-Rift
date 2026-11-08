//! Production signing (docs/reports/key-policy.md): every key is held by one
//! person, each role is signed by a threshold of its keys, and the root is
//! rotated by cross-signing. Each step is its own command, so no machine
//! ever needs more than one holder's key:
//!
//! 1. Each holder runs [`generate_key`] and hands over [`export_public_key`].
//! 2. [`draft_root`] builds an unsigned root from a [`RootPolicy`] naming
//!    those public keys.
//! 3. Each root key holder runs [`sign_root`]; for a rotation, the holders
//!    of the previous root's keys sign it too. [`check_root`] confirms both
//!    thresholds before the root is released.
//! 4. For each pack release, [`draft_targets`], then [`sign_targets`] by the
//!    targets key holders, offline.
//! 5. [`publish_signed`] on the publishing machine with only the online
//!    snapshot and timestamp keys; run again to renew the timestamp.
//!
//! Offline roles (root, targets) may share no key with online roles
//! (snapshot, timestamp): a stolen publishing machine must not be able to
//! sign a pack or a root.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use aws_lc_rs::rand::SystemRandom;
use rift_core::pack::Pack;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use tough::editor::RepositoryEditor;
use tough::editor::signed::SignedRole;
use tough::key_source::{KeySource, LocalKeySource};
use tough::schema::decoded::{Decoded, Hex};
use tough::schema::key::Key;
use tough::schema::{
    DelegatedRole, DelegatedTargets, Delegations, Hashes, KeyHolder, Metafile, PathPattern,
    PathSet, Role, RoleKeys, RoleType, Root, Signature, Signed, Snapshot, Targets, Timestamp,
};
use tough::sign::{Sign, parse_keypair};

use crate::{Result, ToolError, io, pack_file_names, refuse_inside_git, runtime, tuf};

const SPEC_VERSION: &str = "1.0.0";
/// Roles whose keys stay offline.
const OFFLINE: [RoleType; 2] = [RoleType::Root, RoleType::Targets];
/// Roles whose keys sign on the publishing machine.
const ONLINE: [RoleType; 2] = [RoleType::Snapshot, RoleType::Timestamp];

/// The delegated targets role that signs Rift AI's model (key-policy.md,
/// "The model key"): one online key, the one path [`MODEL_PATH`], named in
/// the offline-signed targets so that only the targets holders can change who
/// may sign it.
pub const MODEL_ROLE: &str = "model";
/// The only file the model role may sign.
pub const MODEL_PATH: &str = rift_core::pack::MODEL;

/// Generates one Ed25519 key (PKCS#8, mode 0600) at `path`, which must not
/// exist and must lie outside any git work tree.
pub fn generate_key(path: &Path) -> Result<()> {
    let dir = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    refuse_inside_git(dir)?;
    let document = aws_lc_rs::signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| ToolError::Tuf("key generation failed".into()))?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(io(path))?;
    file.write_all(document.as_ref()).map_err(io(path))?;
    file.sync_all().map_err(io(path))
}

/// Writes the public half of the key at `key` as TUF key JSON, and returns
/// its key ID (hex).
pub fn export_public_key(key: &Path, out: &Path) -> Result<String> {
    let public = public_key(key)?;
    let id = public.key_id().map_err(tuf)?;
    write_json(out, &public)?;
    Ok(hex(&id))
}

/// The keys of one role and how many of them must sign.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RolePolicy {
    pub threshold: NonZeroU64,
    /// Public key files (from [`export_public_key`]), relative to the policy file.
    pub keys: Vec<PathBuf>,
}

/// A root to draft: its version, expiry and the keys of the four roles.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootPolicy {
    pub version: NonZeroU64,
    /// RFC 3339, for example `2027-10-21T00:00:00Z`.
    pub expires: String,
    pub root: RolePolicy,
    pub targets: RolePolicy,
    pub snapshot: RolePolicy,
    pub timestamp: RolePolicy,
}

/// Writes an unsigned root built from the policy file at `policy`.
pub fn draft_root(policy: &Path, out: &Path) -> Result<()> {
    let parsed: RootPolicy = read_json(policy)?;
    let base = policy.parent().unwrap_or(Path::new("."));
    let expires: jiff::Timestamp = parsed
        .expires
        .parse()
        .map_err(|e| ToolError::Refused(format!("expires {:?}: {e}", parsed.expires)))?;
    if expires <= jiff::Timestamp::now() {
        return Err(ToolError::Refused(format!(
            "the root would expire at {expires}, in the past"
        )));
    }
    let mut root = Root {
        spec_version: SPEC_VERSION.into(),
        consistent_snapshot: true,
        version: parsed.version,
        expires,
        keys: Default::default(),
        roles: Default::default(),
        _extra: Default::default(),
    };
    for (role, keys) in [
        (RoleType::Root, &parsed.root),
        (RoleType::Targets, &parsed.targets),
        (RoleType::Snapshot, &parsed.snapshot),
        (RoleType::Timestamp, &parsed.timestamp),
    ] {
        let mut keyids = Vec::with_capacity(keys.keys.len());
        for path in &keys.keys {
            let path = base.join(path);
            let key: Key = read_json(&path)?;
            let id = key.key_id().map_err(tuf)?;
            if keyids.contains(&id) {
                return Err(ToolError::Refused(format!(
                    "{} names key {} twice",
                    role_name(role),
                    hex(&id)
                )));
            }
            root.keys.insert(id.clone(), key);
            keyids.push(id);
        }
        root.roles.insert(
            role,
            RoleKeys {
                keyids,
                threshold: keys.threshold,
                _extra: Default::default(),
            },
        );
    }
    check_policy(&root)?;
    write_json(
        out,
        &Signed {
            signed: root,
            signatures: Vec::new(),
        },
    )
}

/// The structural rules every production root must meet: all four roles,
/// each with a reachable threshold, and no key shared between an offline and
/// an online role.
pub fn check_policy(root: &Root) -> Result<()> {
    let keys_of = |role: RoleType| -> Result<&RoleKeys> {
        root.roles
            .get(&role)
            .ok_or_else(|| ToolError::Refused(format!("the root has no {} role", role_name(role))))
    };
    for role in OFFLINE.into_iter().chain(ONLINE) {
        let keys = keys_of(role)?;
        if keys.threshold.get() > u64::try_from(keys.keyids.len()).unwrap_or(u64::MAX) {
            return Err(ToolError::Refused(format!(
                "{} needs {} signatures but names {} keys",
                role_name(role),
                keys.threshold,
                keys.keyids.len()
            )));
        }
    }
    for offline in OFFLINE {
        for online in ONLINE {
            if let Some(shared) = keys_of(offline)?
                .keyids
                .iter()
                .find(|id| keys_of(online).is_ok_and(|k| k.keyids.contains(id)))
            {
                return Err(ToolError::Refused(format!(
                    "key {} signs both {} (offline) and {} (online)",
                    hex(shared),
                    role_name(offline),
                    role_name(online)
                )));
            }
        }
    }
    Ok(())
}

/// Adds the signature of the key at `key` to the root at `root`. The key
/// must be a root key of this root or, for a rotation, of `previous`.
pub fn sign_root(root: &Path, key: &Path, previous: Option<&Path>) -> Result<String> {
    let draft: Signed<Root> = read_json(root)?;
    let previous: Option<Signed<Root>> = previous.map(read_json).transpose()?;
    let id = public_key(key)?.key_id().map_err(tuf)?;
    let in_root = |r: &Root| {
        r.roles
            .get(&RoleType::Root)
            .is_some_and(|k| k.keyids.contains(&id))
    };
    if !in_root(&draft.signed) && !previous.as_ref().is_some_and(|p| in_root(&p.signed)) {
        return Err(ToolError::Refused(format!(
            "key {} is not a root key of this root{}",
            hex(&id),
            if previous.is_some() {
                " or of the previous one"
            } else {
                ""
            }
        )));
    }
    add_signature(root, draft, key)
}

/// Checks that the root at `root` meets [`check_policy`], is signed by its
/// own root threshold and, when `previous` is given, directly follows it and
/// is signed by its root threshold too (what a client checks during a
/// rotation). Returns a one-line summary.
pub fn check_root(root: &Path, previous: Option<&Path>) -> Result<String> {
    let new: Signed<Root> = read_json(root)?;
    check_policy(&new.signed)?;
    new.signed.verify_role(&new).map_err(|e| {
        ToolError::Refused(format!(
            "root v{} is not signed by its own root threshold: {e}",
            new.signed.version
        ))
    })?;
    let mut summary = format!(
        "root v{} expires {}: {}",
        new.signed.version,
        new.signed.expires,
        OFFLINE
            .into_iter()
            .chain(ONLINE)
            .filter_map(|role| {
                let keys = new.signed.roles.get(&role)?;
                Some(format!(
                    "{} {} of {}",
                    role_name(role),
                    keys.threshold,
                    keys.keyids.len()
                ))
            })
            .collect::<Vec<_>>()
            .join(", ")
    );
    if let Some(previous) = previous {
        let old: Signed<Root> = read_json(previous)?;
        if old.signed.version.checked_add(1) != Some(new.signed.version) {
            return Err(ToolError::Refused(format!(
                "root v{} does not directly follow v{}",
                new.signed.version, old.signed.version
            )));
        }
        old.signed.verify_role(&new).map_err(|e| {
            ToolError::Refused(format!(
                "root v{} is not signed by the root threshold of v{}: {e}",
                new.signed.version, old.signed.version
            ))
        })?;
        summary.push_str(&format!("; cross-signed by v{}", old.signed.version));
    }
    Ok(summary)
}

/// Writes unsigned targets metadata (version `version`) for the pack in
/// `pack_dir`, after validating the pack with the app's own validator.
pub fn draft_targets(
    pack_dir: &Path,
    version: NonZeroU64,
    expires: jiff::Timestamp,
    out: &Path,
) -> Result<Pack> {
    draft_targets_with(pack_dir, version, expires, out, None)
}

/// As [`draft_targets`], but with the model delegated to the holder of
/// `model_key` (a public key file from [`export_public_key`]): the targets
/// then list the other pack files and name that key as the only signer of
/// [`MODEL_PATH`], whose entry is signed by [`publish_signed`] on the
/// publishing machine.
pub fn draft_targets_delegating_model(
    pack_dir: &Path,
    version: NonZeroU64,
    expires: jiff::Timestamp,
    out: &Path,
    model_key: &Path,
) -> Result<Pack> {
    draft_targets_with(pack_dir, version, expires, out, Some(model_key))
}

fn draft_targets_with(
    pack_dir: &Path,
    version: NonZeroU64,
    expires: jiff::Timestamp,
    out: &Path,
    model_key: Option<&Path>,
) -> Result<Pack> {
    let pack = read_pack(pack_dir)?;
    let mut targets = Targets::new(SPEC_VERSION.into(), version, expires);
    runtime()?.block_on(async {
        for name in pack_file_names(pack_dir) {
            if model_key.is_some() && name == MODEL_PATH {
                continue;
            }
            let (target_name, target) = RepositoryEditor::build_target(pack_dir.join(name))
                .await
                .map_err(tuf)?;
            targets.targets.insert(target_name, target);
        }
        Ok::<_, ToolError>(())
    })?;
    if let Some(path) = model_key {
        let key: Key = read_json(path)?;
        let id = key.key_id().map_err(tuf)?;
        let mut delegations = Delegations::new();
        delegations.keys.insert(id.clone(), key);
        delegations.roles.push(DelegatedRole {
            name: MODEL_ROLE.into(),
            keyids: vec![id],
            threshold: NonZeroU64::MIN,
            paths: PathSet::Paths(vec![PathPattern::new(MODEL_PATH).map_err(tuf)?]),
            terminating: true,
            targets: None,
        });
        targets.delegations = Some(delegations);
    }
    write_json(
        out,
        &Signed {
            signed: targets,
            signatures: Vec::new(),
        },
    )?;
    Ok(pack)
}

/// The model delegation of `targets`, if it has one: it must be exactly the
/// one role this tool knows how to publish (one key, one path), or the targets
/// are refused.
fn model_delegation(targets: &Targets) -> Result<Option<&Delegations>> {
    let Some(delegations) = &targets.delegations else {
        return Ok(None);
    };
    let paths_ok = |role: &DelegatedRole| matches!(&role.paths, PathSet::Paths(paths) if paths.len() == 1 && paths.iter().all(|p| p.value() == MODEL_PATH));
    match delegations.roles.as_slice() {
        [] => Ok(None),
        [role]
            if role.name == MODEL_ROLE
                && role.threshold == NonZeroU64::MIN
                && role.keyids.len() == 1
                && paths_ok(role) =>
        {
            Ok(Some(delegations))
        }
        _ => Err(ToolError::Refused(format!(
            "the targets delegate something other than the {MODEL_ROLE} role for {MODEL_PATH} to one key"
        ))),
    }
}

/// Refuses a delegation key that is also a key of any role of `root`: the
/// model key must be its own, so that a stolen one signs nothing else.
fn check_model_key_is_its_own(delegations: &Delegations, root: &Root) -> Result<()> {
    for id in delegations.keys.keys() {
        if let Some((role, _)) = root.roles.iter().find(|(_, k)| k.keyids.contains(id)) {
            return Err(ToolError::Refused(format!(
                "the model key {} is also a {} key; it must be its own key",
                hex(id),
                role_name(*role)
            )));
        }
    }
    Ok(())
}

/// Adds the signature of the key at `key` to the targets metadata at
/// `targets`; the key must be a targets key of `root`.
pub fn sign_targets(targets: &Path, root: &Path, key: &Path) -> Result<String> {
    let draft: Signed<Targets> = read_json(targets)?;
    let root: Signed<Root> = read_json(root)?;
    let id = public_key(key)?.key_id().map_err(tuf)?;
    if !root
        .signed
        .roles
        .get(&RoleType::Targets)
        .is_some_and(|k| k.keyids.contains(&id))
    {
        return Err(ToolError::Refused(format!(
            "key {} is not a targets key of root v{}",
            hex(&id),
            root.signed.version
        )));
    }
    if let Some(delegations) = model_delegation(&draft.signed)? {
        check_model_key_is_its_own(delegations, &root.signed)?;
    }
    add_signature(targets, draft, key)
}

/// Version and expiry of the online roles in one publication. The model
/// role, if the targets delegate one, takes the timestamp's expiry (7 days)
/// and the release's version.
#[derive(Debug, Clone, Copy)]
pub struct OnlineRelease {
    pub version: NonZeroU64,
    pub snapshot_expires: jiff::Timestamp,
    pub timestamp_expires: jiff::Timestamp,
}

/// Publishes a signed repository in `out` (`metadata/`, `targets/`) from
/// the chain of roots `roots` (oldest first; a client walks it from the root
/// it trusts), the offline-signed `targets` for the pack in `pack_dir`, and
/// snapshot and timestamp metadata signed here with the online keys.
/// Everything a client would check is checked first.
///
/// If the targets delegate the model ([`draft_targets_delegating_model`]),
/// `model_key` must be the delegated key: the model's entry is then signed
/// here, into `model.json`, and the snapshot lists it. Without a delegation
/// `model_key` must be None.
pub fn publish_signed(
    roots: &[PathBuf],
    targets: &Path,
    pack_dir: &Path,
    online_keys: &[PathBuf],
    model_key: Option<&Path>,
    release: &OnlineRelease,
    out: &Path,
) -> Result<()> {
    let chain: Vec<Signed<Root>> = roots.iter().map(|p| read_json(p)).collect::<Result<_>>()?;
    let latest = check_chain(&chain)?;
    check_policy(&latest.signed)?;

    let targets: Signed<Targets> = read_json(targets)?;
    latest.signed.verify_role(&targets).map_err(|e| {
        ToolError::Refused(format!(
            "the targets are not signed by the targets threshold of root v{}: {e}",
            latest.signed.version
        ))
    })?;
    // A model the publisher would sign must pass what the app will check of it
    // (rift_core::pack::model_canary), so a broken one is stopped here, not on
    // every phone.
    if let Some(model) = read_pack(pack_dir)?.model {
        rift_core::pack::model_canary(&model).map_err(|why| {
            ToolError::Refused(format!("the model in the pack is refused: {why}"))
        })?;
    }
    let delegations = model_delegation(&targets.signed)?;
    match (delegations, model_key) {
        (Some(_), None) => {
            return Err(ToolError::Refused(
                "the targets delegate the model; publish-signed needs the model key".into(),
            ));
        }
        (None, Some(_)) => {
            return Err(ToolError::Refused(
                "a model key was given, but the targets delegate nothing".into(),
            ));
        }
        _ => {}
    }
    if let Some(delegations) = delegations {
        check_model_key_is_its_own(delegations, &latest.signed)?;
    }
    let names = pack_file_names(pack_dir);
    // With the model delegated, the targets list every pack file but the model.
    let expected: HashSet<&str> = names
        .iter()
        .copied()
        .filter(|name| delegations.is_none() || *name != MODEL_PATH)
        .collect();
    let listed: HashSet<&str> = targets.signed.targets.keys().map(|n| n.raw()).collect();
    if listed != expected {
        return Err(ToolError::Refused(format!(
            "the targets list {listed:?}, not exactly the pack files"
        )));
    }
    let mut files = Vec::with_capacity(names.len());
    for name in names {
        let path = pack_dir.join(name);
        let bytes = fs::read(&path).map_err(io(&path))?;
        let digest = Sha256::digest(&bytes);
        if delegations.is_some() && name == MODEL_PATH {
            // Signed below by the model role, not by the targets.
            files.push((format!("{}.{name}", hex_bytes(&digest)), bytes));
            continue;
        }
        let signed_target = targets
            .signed
            .targets
            .iter()
            .find(|(n, _)| n.raw() == name)
            .map(|(_, t)| t)
            .ok_or_else(|| ToolError::Refused(format!("the targets do not list {name}")))?;
        if signed_target.length != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
            || signed_target.hashes.sha256.as_ref() != digest.as_slice()
        {
            return Err(ToolError::Refused(format!(
                "{name} in the pack differs from the signed targets"
            )));
        }
        files.push((format!("{}.{name}", hex_bytes(&digest)), bytes));
    }

    // The online roles: only keys named for them may sign, and an offline key
    // on this machine is refused rather than used.
    let holder = KeyHolder::Root(latest.signed.clone());
    for path in online_keys {
        let id = public_key(path)?.key_id().map_err(tuf)?;
        if let Some(role) = OFFLINE.into_iter().find(|role| {
            latest
                .signed
                .roles
                .get(role)
                .is_some_and(|k| k.keyids.contains(&id))
        }) {
            return Err(ToolError::Refused(format!(
                "{} is a {} key; offline keys do not belong on the publishing machine",
                path.display(),
                role_name(role)
            )));
        }
    }
    let sources: Vec<Box<dyn KeySource>> = online_keys
        .iter()
        .map(|path| Box::new(LocalKeySource { path: path.clone() }) as Box<dyn KeySource>)
        .collect();
    let targets_bytes = pretty(&targets)?;
    // The model role's metadata, signed with the model key alone.
    let model_signed = match (delegations, model_key) {
        (Some(delegations), Some(key)) => {
            let mut listed = Targets::new(
                SPEC_VERSION.into(),
                release.version,
                release.timestamp_expires,
            );
            if pack_dir.join(MODEL_PATH).exists() {
                let (name, target) = runtime()?.block_on(async {
                    RepositoryEditor::build_target(pack_dir.join(MODEL_PATH))
                        .await
                        .map_err(tuf)
                })?;
                listed.targets.insert(name, target);
            }
            let sources: Vec<Box<dyn KeySource>> = vec![Box::new(LocalKeySource {
                path: key.to_path_buf(),
            })];
            let role = DelegatedTargets {
                name: MODEL_ROLE.into(),
                targets: listed,
            };
            let holder = KeyHolder::Delegations(delegations.clone());
            let rng = SystemRandom::new();
            Some(runtime()?.block_on(async {
                SignedRole::new(role, &holder, &sources, &rng)
                    .await
                    .map_err(tuf)
            })?)
        }
        _ => None,
    };
    let mut snapshot = Snapshot::new(
        SPEC_VERSION.into(),
        release.version,
        release.snapshot_expires,
    );
    snapshot.meta.insert(
        "targets.json".into(),
        metafile(&targets_bytes, targets.signed.version),
    );
    if let Some(model) = &model_signed {
        snapshot.meta.insert(
            format!("{MODEL_ROLE}.json"),
            metafile(model.buffer(), model.signed().signed.version()),
        );
    }
    let rng = SystemRandom::new();
    let (snapshot, timestamp) = runtime()?.block_on(async {
        let snapshot = SignedRole::new(snapshot, &holder, &sources, &rng)
            .await
            .map_err(tuf)?;
        let mut timestamp = Timestamp::new(
            SPEC_VERSION.into(),
            release.version,
            release.timestamp_expires,
        );
        timestamp.meta.insert(
            "snapshot.json".into(),
            metafile(snapshot.buffer(), snapshot.signed().signed.version),
        );
        let timestamp = SignedRole::new(timestamp, &holder, &sources, &rng)
            .await
            .map_err(tuf)?;
        Ok::<_, ToolError>((snapshot, timestamp))
    })?;

    let metadata = out.join("metadata");
    let target_dir = out.join("targets");
    for dir in [&metadata, &target_dir] {
        fs::create_dir_all(dir).map_err(io(dir))?;
    }
    for (root, path) in chain.iter().zip(roots) {
        let to = metadata.join(format!("{}.root.json", root.signed.version));
        fs::copy(path, &to).map_err(io(&to))?;
    }
    let mut written = vec![
        (
            metadata.join(format!("{}.targets.json", targets.signed.version)),
            targets_bytes,
        ),
        (
            metadata.join(snapshot.signed().signed.filename(true)),
            snapshot.buffer().clone(),
        ),
    ];
    if let Some(model) = &model_signed {
        written.push((
            metadata.join(model.signed().signed.filename(true)),
            model.buffer().clone(),
        ));
    }
    written.extend(
        files
            .into_iter()
            .map(|(name, bytes)| (target_dir.join(name), bytes)),
    );
    // The timestamp last: it is what makes a client see the new release.
    written.push((
        metadata.join(timestamp.signed().signed.filename(true)),
        timestamp.buffer().clone(),
    ));
    for (path, bytes) in written {
        fs::write(&path, bytes).map_err(io(&path))?;
    }
    Ok(())
}

/// Checks that each root in `chain` (oldest first) is signed by its own
/// root threshold and by that of the root before it, with consecutive
/// versions; returns the newest.
fn check_chain(chain: &[Signed<Root>]) -> Result<&Signed<Root>> {
    let (first, _) = chain
        .split_first()
        .ok_or_else(|| ToolError::Refused("no root given".into()))?;
    first.signed.verify_role(first).map_err(|e| {
        ToolError::Refused(format!(
            "root v{} is not signed by its own threshold: {e}",
            first.signed.version
        ))
    })?;
    for pair in chain.windows(2) {
        let [old, new] = pair else { continue };
        if old.signed.version.checked_add(1) != Some(new.signed.version) {
            return Err(ToolError::Refused(format!(
                "root v{} does not directly follow v{}",
                new.signed.version, old.signed.version
            )));
        }
        for (by, what) in [(old, "the previous root's"), (new, "its own")] {
            by.signed.verify_role(new).map_err(|e| {
                ToolError::Refused(format!(
                    "root v{} is not signed by {what} root threshold: {e}",
                    new.signed.version
                ))
            })?;
        }
    }
    chain
        .last()
        .ok_or_else(|| ToolError::Refused("no root given".into()))
}

fn add_signature<T: Role + serde::Serialize>(
    path: &Path,
    mut draft: Signed<T>,
    key: &Path,
) -> Result<String> {
    let bytes = fs::read(key).map_err(io(key))?;
    let pair = parse_keypair(&bytes).map_err(tuf)?;
    let id = pair.tuf_key().key_id().map_err(tuf)?;
    if draft.signatures.iter().any(|s| s.keyid == id) {
        return Err(ToolError::Refused(format!(
            "already signed by key {}",
            hex(&id)
        )));
    }
    let data = draft.signed.canonical_form().map_err(tuf)?;
    let sig = runtime()?
        .block_on(pair.sign(&data, &SystemRandom::new()))
        .map_err(tuf)?;
    draft.signatures.push(Signature {
        keyid: id.clone(),
        sig: sig.into(),
    });
    write_json(path, &draft)?;
    Ok(hex(&id))
}

fn metafile(bytes: &[u8], version: NonZeroU64) -> Metafile {
    Metafile {
        hashes: Some(Hashes {
            sha256: Sha256::digest(bytes).to_vec().into(),
            _extra: HashMap::new(),
        }),
        length: Some(u64::try_from(bytes.len()).unwrap_or(u64::MAX)),
        version,
        _extra: HashMap::new(),
    }
}

fn read_pack(pack_dir: &Path) -> Result<Pack> {
    let files: Vec<(&'static str, Vec<u8>)> = pack_file_names(pack_dir)
        .iter()
        .map(|name| {
            let path = pack_dir.join(name);
            fs::read(&path).map(|b| (*name, b)).map_err(io(&path))
        })
        .collect::<Result<_>>()?;
    Ok(Pack::validate(
        files.iter().map(|(n, b)| (*n, b.as_slice())),
    )?)
}

fn public_key(key: &Path) -> Result<Key> {
    let bytes = fs::read(key).map_err(io(key))?;
    Ok(parse_keypair(&bytes).map_err(tuf)?.tuf_key())
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).map_err(io(path))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| ToolError::Refused(format!("{}: {e}", path.display())))
}

/// The layout tough writes: pretty JSON and a final newline.
fn pretty<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(tuf)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    fs::write(path, pretty(value)?).map_err(io(path))
}

fn hex(bytes: &Decoded<Hex>) -> String {
    hex_bytes(bytes.as_ref())
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn role_name(role: RoleType) -> &'static str {
    match role {
        RoleType::Root => "root",
        RoleType::Targets => "targets",
        RoleType::Snapshot => "snapshot",
        RoleType::Timestamp => "timestamp",
        RoleType::DelegatedTargets => "delegated targets",
    }
}
