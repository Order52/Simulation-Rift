//! Indicator tables come from signed packs, but are still parsed as untrusted
//! bytes. Parsing must never panic, and a table that parses must answer every
//! one of its own records with that record's metadata index.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rift_core::intel::UrlTable;

const HEADER_LEN: usize = 24;
const RECORD_LEN: usize = 16 + 4;

fuzz_target!(|data: &[u8]| {
    let Some((count, bytes)) = data.split_first_chunk::<2>() else {
        return;
    };
    let meta_count = u32::from(u16::from_le_bytes(*count));
    let Ok(table) = UrlTable::parse(bytes, meta_count) else {
        return;
    };
    let records = &bytes[HEADER_LEN..];
    assert_eq!(table.len(), records.len() / RECORD_LEN);
    for record in records.chunks_exact(RECORD_LEN) {
        let (key, meta) = record.split_at(16);
        let key: [u8; 16] = key.try_into().expect("16-byte key");
        let meta = u32::from_le_bytes(meta.try_into().expect("4-byte meta"));
        assert!(meta < meta_count);
        assert_eq!(table.lookup(&key), Some(meta));
    }
});
