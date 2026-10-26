//! Rift's own updates (architecture §8.11): reads the latest release from
//! GitHub's API and checks a downloaded APK against the SHA-256 published
//! with it. The answer is untrusted: only a final release of Rift's own
//! repository, with assets at exactly the addresses its release workflow
//! gives them, is accepted. Android then refuses an APK not signed like
//! the installed app, and the controller checks the package and signer
//! before it asks Android.

use serde::Deserialize;
use sha2::{Digest, Sha256};

/// The latest final release (GitHub skips drafts and pre-releases).
pub const LATEST_URL: &str = "https://api.github.com/repos/Order52/Simulation-Rift/releases/latest";
const DOWNLOAD_PREFIX: &str = "https://github.com/Order52/Simulation-Rift/releases/download/";

/// The API's answer: a few kilobytes per asset.
pub const MAX_RELEASE_BYTES: u64 = 1 << 20;
pub const MAX_CHECKSUM_BYTES: u64 = 4 << 10;
/// The release APK is about 24 MiB.
pub const MAX_APK_BYTES: u64 = 96 << 20;

/// `major.minor.patch`, compared in that order.
pub type Version = (u32, u32, u32);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppRelease {
    pub version: Version,
    pub apk_url: String,
    pub sha256_url: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReleaseError {
    #[error("the release information is not valid ({0})")]
    Invalid(String),
    #[error("the release has no {0}")]
    Missing(String),
}

#[derive(Deserialize)]
struct RawRelease {
    tag_name: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<RawAsset>,
}

#[derive(Deserialize)]
struct RawAsset {
    name: String,
    browser_download_url: String,
}

/// `1.2.3` or `v1.2.3`: three decimal numbers of at most nine digits.
pub fn parse_version(text: &str) -> Option<Version> {
    let mut parts = text.strip_prefix('v').unwrap_or(text).split('.');
    let mut next = || {
        parts
            .next()
            .filter(|p| !p.is_empty() && p.len() <= 9 && p.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|p| p.parse::<u32>().ok())
    };
    let version = (next()?, next()?, next()?);
    parts.next().is_none().then_some(version)
}

/// Whether `candidate` is newer than the installed `current` version name.
/// An installed version that does not parse is never replaced.
pub fn is_newer(current: &str, candidate: Version) -> bool {
    parse_version(current).is_some_and(|installed| candidate > installed)
}

/// The asset addresses a release of `version` has, as the release workflow names them.
pub fn asset_urls(version: Version) -> (String, String) {
    let (major, minor, patch) = version;
    let apk = format!("{DOWNLOAD_PREFIX}v{major}.{minor}.{patch}/rift-{major}.{minor}.{patch}.apk");
    let sha256 = format!("{apk}.sha256");
    (apk, sha256)
}

/// The latest release from GitHub's answer, checked as described above.
pub fn latest(json: &[u8]) -> Result<AppRelease, ReleaseError> {
    let raw: RawRelease =
        serde_json::from_slice(json).map_err(|e| ReleaseError::Invalid(e.to_string()))?;
    if raw.draft || raw.prerelease {
        return Err(ReleaseError::Invalid("not a final release".into()));
    }
    if !raw.tag_name.starts_with('v') {
        return Err(ReleaseError::Invalid(format!("tag {:?}", raw.tag_name)));
    }
    let version = parse_version(&raw.tag_name)
        .ok_or_else(|| ReleaseError::Invalid(format!("tag {:?}", raw.tag_name)))?;
    let (apk_url, sha256_url) = asset_urls(version);
    let has = |url: &str| {
        raw.assets
            .iter()
            .any(|a| a.browser_download_url == url && url.ends_with(&format!("/{}", a.name)))
    };
    if !has(&apk_url) {
        return Err(ReleaseError::Missing("APK for this phone".into()));
    }
    if !has(&sha256_url) {
        return Err(ReleaseError::Missing("SHA-256 file".into()));
    }
    Ok(AppRelease {
        version,
        apk_url,
        sha256_url,
    })
}

/// The digest in a `sha256sum`/`shasum` line for `file_name`.
pub fn parse_checksum(text: &str, file_name: &str) -> Result<[u8; 32], ReleaseError> {
    let line = text.lines().next().unwrap_or_default();
    let mut fields = line.split_whitespace();
    let digest = fields.next().unwrap_or_default();
    let named = fields.next().map(|n| n.trim_start_matches('*'));
    if named.is_some_and(|n| n != file_name) {
        return Err(ReleaseError::Invalid(
            "the SHA-256 file names another file".into(),
        ));
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(digest, &mut out)
        .map_err(|_| ReleaseError::Invalid("the SHA-256 file holds no digest".into()))?;
    Ok(out)
}

/// Whether `bytes` have the published digest.
pub fn matches(bytes: &[u8], digest: &[u8; 32]) -> bool {
    Sha256::digest(bytes).as_slice() == digest
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(tag: &str, assets: &[(&str, &str)], prerelease: bool) -> Vec<u8> {
        let assets: Vec<_> = assets
            .iter()
            .map(|(name, url)| serde_json::json!({"name": name, "browser_download_url": url}))
            .collect();
        serde_json::to_vec(&serde_json::json!({"tag_name": tag, "prerelease": prerelease, "draft": false, "assets": assets})).unwrap()
    }

    const APK: &str =
        "https://github.com/Order52/Simulation-Rift/releases/download/v0.10.3/rift-0.10.3.apk";
    const SUM: &str = "https://github.com/Order52/Simulation-Rift/releases/download/v0.10.3/rift-0.10.3.apk.sha256";

    #[test]
    fn a_release_of_rift_is_read() {
        let json = release(
            "v0.10.3",
            &[
                ("rift-0.10.3.apk", APK),
                ("rift-0.10.3.apk.sha256", SUM),
                (
                    "rift-browser-0.10.3.apk",
                    "https://github.com/Order52/Simulation-Rift/releases/download/v0.10.3/rift-browser-0.10.3.apk",
                ),
            ],
            false,
        );
        let got = latest(&json).unwrap();
        assert_eq!(got.version, (0, 10, 3));
        assert_eq!(got.apk_url, APK);
        assert_eq!(got.sha256_url, SUM);
    }

    #[test]
    fn assets_anywhere_else_are_refused() {
        // Another repository, a lookalike host, another tag's file: not Rift's release.
        for apk in [
            "https://github.com/someone/Simulation-Rift/releases/download/v0.10.3/rift-0.10.3.apk",
            "https://github.com.evil.example/Order52/Simulation-Rift/releases/download/v0.10.3/rift-0.10.3.apk",
            "https://github.com/Order52/Simulation-Rift/releases/download/v0.10.2/rift-0.10.3.apk",
            "http://github.com/Order52/Simulation-Rift/releases/download/v0.10.3/rift-0.10.3.apk",
        ] {
            let json = release(
                "v0.10.3",
                &[("rift-0.10.3.apk", apk), ("rift-0.10.3.apk.sha256", SUM)],
                false,
            );
            assert_eq!(
                latest(&json),
                Err(ReleaseError::Missing("APK for this phone".into())),
                "{apk}"
            );
        }
        let json = release("v0.10.3", &[("rift-0.10.3.apk", APK)], false);
        assert_eq!(
            latest(&json),
            Err(ReleaseError::Missing("SHA-256 file".into()))
        );
    }

    #[test]
    fn pre_releases_odd_tags_and_garbage_are_refused() {
        let ok = [("rift-0.10.3.apk", APK), ("rift-0.10.3.apk.sha256", SUM)];
        assert!(latest(&release("v0.10.3", &ok, true)).is_err());
        for tag in [
            "0.10.3",
            "v0.10",
            "v0.10.3.1",
            "v0.10.-3",
            "v0.10.3-beta",
            "v0.10.+3",
            "v0.10.9999999999",
            "ai-memory",
        ] {
            assert!(latest(&release(tag, &ok, false)).is_err(), "{tag}");
        }
        assert!(latest(b"not json").is_err());
        assert!(latest(b"{}").is_err());
    }

    #[test]
    fn only_a_newer_version_replaces_the_installed_one() {
        assert!(is_newer("0.10.0", (0, 10, 1)));
        assert!(is_newer("0.9.9", (0, 10, 0)));
        assert!(is_newer("0.10.9", (1, 0, 0)));
        assert!(!is_newer("0.10.1", (0, 10, 1)));
        assert!(!is_newer("0.10.2", (0, 10, 1)));
        assert!(!is_newer("1.0.0", (0, 99, 99)));
        assert!(!is_newer("dev", (9, 9, 9)));
    }

    #[test]
    fn the_published_digest_is_checked() {
        let apk = b"an apk";
        let hex = hex::encode(Sha256::digest(apk));
        let digest =
            parse_checksum(&format!("{hex}  rift-0.10.3.apk\n"), "rift-0.10.3.apk").unwrap();
        assert!(matches(apk, &digest));
        assert!(!matches(b"another apk", &digest));
        assert!(parse_checksum(&hex, "rift-0.10.3.apk").is_ok());
        assert!(parse_checksum(&format!("{hex} *rift-0.10.3.apk"), "rift-0.10.3.apk").is_ok());
        assert!(parse_checksum(&format!("{hex}  rift-0.10.2.apk"), "rift-0.10.3.apk").is_err());
        assert!(parse_checksum("zz  rift-0.10.3.apk", "rift-0.10.3.apk").is_err());
        assert!(parse_checksum("", "rift-0.10.3.apk").is_err());
    }
}
