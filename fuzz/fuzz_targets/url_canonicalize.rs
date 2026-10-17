//! URL canonicalization runs on every navigation and every indicator lookup.
//! It must never panic, and its output must be ASCII and a fixed point:
//! otherwise the same URL could hash differently depending on how often it
//! was normalized (three such bugs were found by property tests).
#![no_main]

use libfuzzer_sys::fuzz_target;
use rift_core::urlcanon::canonicalize;

fuzz_target!(|data: &[u8]| {
    let Ok(first) = canonicalize(data) else {
        return;
    };
    let text = first.to_string();
    assert!(text.is_ascii(), "{text:?}");
    let second = canonicalize(text.as_bytes()).map(|url| url.to_string());
    assert_eq!(second, Ok(text), "canonicalization is not idempotent");
    assert!(first.expressions().len() <= 30);
    let _ = first.expression_hashes();
});
