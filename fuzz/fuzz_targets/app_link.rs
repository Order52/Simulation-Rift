//! A page or another app chooses the links Check and the watch explain:
//! explaining one must not panic, and what it shows must be short and
//! escaped (docs/architecture.md §10.15).
#![no_main]

use libfuzzer_sys::fuzz_target;
use rift_core::applink::explain;

fuzz_target!(|data: &[u8]| {
    let Some(link) = explain(data) else {
        return;
    };
    for text in std::iter::once(&link.does).chain(&link.details).chain(link.app.iter()).chain(link.fallback.iter()) {
        // At most a few 120-character values in one sentence, each escaped.
        assert!(text.chars().count() < 2_000, "{text:?}");
        assert!(!text.chars().any(|c| c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')), "{text:?}");
    }
    if let Some(fallback) = &link.fallback {
        assert!(fallback.starts_with("https://") || fallback.starts_with("http://"), "{fallback:?}");
    }
});
