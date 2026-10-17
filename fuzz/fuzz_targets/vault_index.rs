//! A vault index file on disk may have been replaced by anything (B2/B5 in the
//! threat model). Reading it must never panic, and since a forger without the
//! vault identity cannot produce a valid MAC, arbitrary bytes must never be
//! accepted as an index.
#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use rift_core::vault::{VaultKey, read_index};

static KEY: LazyLock<VaultKey> = LazyLock::new(VaultKey::generate);
static DIR: LazyLock<tempfile::TempDir> =
    LazyLock::new(|| tempfile::tempdir().expect("temporary directory"));

fuzz_target!(|data: &[u8]| {
    std::fs::write(DIR.path().join("index.age"), data).expect("write index");
    assert!(
        read_index(DIR.path(), &KEY).is_err(),
        "fuzzer forged a vault index"
    );
});
