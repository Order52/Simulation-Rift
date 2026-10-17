//! Server-supplied filenames become display metadata in the trusted UI. The
//! result must never contain a path separator, a control character or a
//! bidi/invisible character, must be bounded, and must be a fixed point.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rift_core::transfer::display_name;

const BIDI_AND_INVISIBLE: &[char] = &[
    '\u{200b}', '\u{200c}', '\u{200d}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}',
    '\u{202d}', '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', '\u{feff}',
];

fuzz_target!(|supplied: &str| {
    let shown = display_name(supplied);
    assert!(!shown.is_empty());
    assert!(shown.chars().count() <= 120);
    assert!(
        !shown
            .chars()
            .any(|c| c == '/' || c == '\\' || c.is_control() || BIDI_AND_INVISIBLE.contains(&c)),
        "{shown:?}"
    );
    assert_eq!(
        display_name(&shown),
        shown,
        "display_name is not idempotent"
    );
});
