//! Rift's own updates (docs/architecture.md §8.11): the latest release of
//! Rift on GitHub, fetched and checked by the core. The controller checks
//! the APK's package and signer, then hands it to Android's installer.

use std::sync::atomic::AtomicBool;

use rift_core::appupdate::{self, MAX_APK_BYTES, MAX_CHECKSUM_BYTES, MAX_RELEASE_BYTES};
use rift_core::download::{self, DownloadPolicy};

const USER_AGENT: &str = "Rift-update";

/// A newer release, as the core accepted it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AppRelease {
    /// `major.minor.patch`.
    pub version: String,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum AppUpdateFailure {
    #[error("{reason}")]
    Failed { reason: String },
}

fn failed(reason: impl ToString) -> AppUpdateFailure {
    AppUpdateFailure::Failed {
        reason: reason.to_string(),
    }
}

fn fetch(url: &str, max_bytes: u64) -> Result<Vec<u8>, AppUpdateFailure> {
    download::fetch(
        url,
        &DownloadPolicy::default(),
        USER_AGENT,
        max_bytes,
        &AtomicBool::new(false),
    )
    .map_err(failed)
}

/// The latest release if it is newer than `installed` (the installed
/// version name); None if Rift is up to date.
#[uniffi::export]
pub fn newer_app_release(installed: String) -> Result<Option<AppRelease>, AppUpdateFailure> {
    let release =
        appupdate::latest(&fetch(appupdate::LATEST_URL, MAX_RELEASE_BYTES)?).map_err(failed)?;
    if !appupdate::is_newer(&installed, release.version) {
        return Ok(None);
    }
    let (major, minor, patch) = release.version;
    Ok(Some(AppRelease {
        version: format!("{major}.{minor}.{patch}"),
    }))
}

/// Downloads the APK of `release` to `path`, only if it has the SHA-256
/// published with it. The addresses are derived from the version again,
/// never taken from the caller.
#[uniffi::export]
pub fn download_app_release(release: AppRelease, path: String) -> Result<(), AppUpdateFailure> {
    let version =
        appupdate::parse_version(&release.version).ok_or_else(|| failed("not a version"))?;
    let (apk_url, sha256_url) = appupdate::asset_urls(version);
    let name = apk_url.rsplit('/').next().unwrap_or_default();
    let listed = fetch(&sha256_url, MAX_CHECKSUM_BYTES)?;
    let digest =
        appupdate::parse_checksum(&String::from_utf8_lossy(&listed), name).map_err(failed)?;
    let apk = fetch(&apk_url, MAX_APK_BYTES)?;
    if !appupdate::matches(&apk, &digest) {
        return Err(failed(
            "the download does not match the SHA-256 published with it",
        ));
    }
    std::fs::write(&path, &apk).map_err(|e| failed(format!("the update could not be saved: {e}")))
}
