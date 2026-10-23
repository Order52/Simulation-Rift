//! Link-cleaning rules are text from the network and addresses come from
//! anywhere: neither may panic the controller, and cleaning may change an
//! address's site only by unwrapping a redirect link, into a web address
//! (docs/architecture.md §10.10).
#![no_main]

use libfuzzer_sys::fuzz_target;
use rift_core::clean::Rules;
use url::Url;

/// Rules shaped like upstream ones, with one pattern of each kind from the input.
fn with_patterns(pattern: &str) -> String {
    let p = serde_json::to_string(pattern).unwrap_or_default();
    format!(
        r#"{{"providers":{{"a":{{"urlPattern":".*","rules":[{p},"utm_[a-z]*"],"rawRules":[{p}],"exceptions":[{p}],"redirections":[{p},"[?&]u=(https?[^&]+)"]}}}}}}"#
    )
}

fn origin(address: &str) -> Option<url::Origin> {
    Url::parse(address).ok().map(|u| u.origin())
}

fuzz_target!(|data: &[u8]| {
    // rules (or one pattern) \0 address
    let mut parts = data.splitn(2, |b| *b == 0).map(String::from_utf8_lossy);
    let (Some(rules), Some(address)) = (parts.next(), parts.next()) else {
        return;
    };
    for text in [rules.to_string(), with_patterns(&rules)] {
        let Ok(rules) = Rules::parse(&text) else {
            continue;
        };
        let cleaned = rules.clean(&address);
        if cleaned.url == *address {
            continue;
        }
        let url = Url::parse(&cleaned.url).expect("a changed address is a valid URL");
        assert!(matches!(url.scheme(), "http" | "https"), "{cleaned:?}");
        if cleaned.unwrapped.is_empty() {
            assert_eq!(origin(&address), origin(&cleaned.url), "site changed: {address:?} -> {cleaned:?}");
        }
    }
});
