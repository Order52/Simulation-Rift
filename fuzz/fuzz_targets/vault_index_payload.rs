//! The vault index decoder behind the MAC. `vault_index` cannot reach it:
//! without the vault identity no input authenticates. An index that
//! decodes must have no duplicate object ids, and must survive encoding and
//! decoding again unchanged, so a write after a read keeps what was read.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rift_core::vault::{decode_index, encode_index};

fuzz_target!(|data: &[u8]| {
    let Ok(index) = decode_index(data) else {
        return;
    };
    let mut ids: Vec<_> = index.entries.iter().map(|e| e.id).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), index.entries.len(), "duplicate ids accepted");
    let encoded = encode_index(&index).expect("a decoded index encodes");
    assert_eq!(decode_index(&encoded).expect("its encoding decodes"), index);
});
