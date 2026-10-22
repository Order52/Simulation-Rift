//! Content filter lists are text from the network, and page addresses and
//! class names come from the browser app: none of it may panic the
//! controller, and the style rules made from any list must hold only
//! plain selectors, one per rule, within the bounds that keep them under
//! Binder's size limit (docs/architecture.md §10.9).
#![no_main]

use libfuzzer_sys::fuzz_target;
use rift_core::filters::Filters;

const RULE: &str = "{display:none!important}";

fn check(css: &str) {
    assert!(css.len() <= 200_000, "css over its bound");
    for line in css.lines() {
        let selector = line.strip_suffix(RULE).unwrap_or_else(|| panic!("not one plain rule: {line:?}"));
        assert!(
            !selector.chars().any(|c| matches!(c, '{' | '}' | ';' | '@' | '\\' | '<') || c.is_control()),
            "selector could write css: {selector:?}"
        );
        assert!(!selector.to_ascii_lowercase().contains("url("), "{selector:?}");
    }
}

fuzz_target!(|data: &[u8]| {
    // list \0 address \0 page \0 class names and ids, one per line
    let mut parts = data.split(|b| *b == 0).map(String::from_utf8_lossy);
    let (Some(list), Some(url), Some(page), Some(names)) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return;
    };
    let filters = Filters::new(vec![list.into_owned()]);
    let _ = filters.blocks(&url, &page, "script");
    let _ = filters.blocks(&url, &page, &page);
    let cosmetic = filters.cosmetic(&url);
    check(&cosmetic.css);
    let names: Vec<String> = names.lines().map(str::to_owned).collect();
    check(&filters.generic_css(&names, &names, &cosmetic.exceptions));
});
