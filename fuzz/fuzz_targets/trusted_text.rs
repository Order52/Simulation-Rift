//! Text from websites and downloaded files reaches Rift's own UI: a file
//! shown as plain text (§11.2), web-supplied words inside Rift's messages,
//! and the explanations of address warnings. None of it may carry a control
//! character (beyond a text file's line breaks and tabs) or a character that
//! reorders or hides text, or a page could make its words look like Rift's.
//! The reference set is Unicode's own Bidi_Control property (PropList.txt)
//! plus the zero-width and invisible characters, written out here
//! independently of the product's list.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rift_core::heuristics::{HeuristicConfig, assess};
use rift_core::text::{escape_for_display, plain_text};
use rift_core::urlcanon::canonicalize;

/// Bidi_Control (Unicode 16.0 PropList.txt).
const BIDI_CONTROL: &[char] = &[
    '\u{061c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}',
    '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
];
/// Zero-width and invisible characters that can hide or join text.
const INVISIBLE: &[char] = &['\u{200b}', '\u{200c}', '\u{200d}', '\u{2060}', '\u{feff}'];

fn hides(c: char) -> bool {
    BIDI_CONTROL.contains(&c) || INVISIBLE.contains(&c)
}

fn assert_shown_safely(text: &str, line_breaks: bool) {
    let bad = text
        .chars()
        .find(|&c| hides(c) || (c.is_control() && !(line_breaks && (c == '\n' || c == '\t'))));
    assert_eq!(bad, None, "{text:?}");
}

fuzz_target!(|data: &[u8]| {
    let Some((&limit, raw)) = data.split_first() else {
        return;
    };
    match plain_text(raw, usize::from(limit) * 16) {
        Some(shown) => assert_shown_safely(&shown.text, true),
        None => assert!(raw.iter().take(8 * 1024).any(|&b| b == 0), "text refused as binary"),
    }
    assert_shown_safely(&escape_for_display(&String::from_utf8_lossy(raw)), false);
    if let Ok(url) = canonicalize(raw) {
        let config = HeuristicConfig {
            protected_domains: vec!["paypal.com".into()],
            shorteners: vec!["bit.ly".into()],
            ..HeuristicConfig::default()
        };
        for flag in assess(raw, &url, &config) {
            assert_shown_safely(&flag.explain(), false);
        }
    }
});
