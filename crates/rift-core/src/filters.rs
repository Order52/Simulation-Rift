//! Content filters (§10.9): ad, tracker and annoyance lists in EasyList
//! syntax, taken from their upstream projects and matched here, in the
//! trusted core, so the browser app gets a yes or no and some CSS, never a
//! rule engine of its own.
//!
//! Lists are untrusted text. They can only take things away from a page: a
//! request is answered "block", or an element is hidden. They cannot allow
//! what Rift's own checks refuse (the checks run first and the proxy applies
//! them to every connection), and the CSS made from them is rebuilt here
//! from selectors that pass [`safe_selector`], one rule each, so no list can
//! write a rule of its own into a page.

use std::collections::HashSet;

use adblock::{
    Engine, FilterSet,
    lists::{FilterFormat, ParseOptions, RuleTypes},
    request::Request,
};

/// Most selectors returned for one page (specific and generic together).
const MAX_SELECTORS: usize = 3_000;
/// Longest selector kept, in bytes.
const MAX_SELECTOR_LEN: usize = 200;
/// Most bytes of CSS returned at once: it crosses Binder, whose transactions are limited to 1 MB.
const MAX_CSS_BYTES: usize = 200_000;
/// Most class names and ids taken from one page when asking for generic rules.
const MAX_PAGE_NAMES: usize = 4_000;
/// Longest class name or id taken from a page.
const MAX_NAME_LEN: usize = 100;

/// Request kinds the engine knows; anything else is `other`.
const KINDS: &[&str] = &[
    "document",
    "subdocument",
    "stylesheet",
    "script",
    "image",
    "font",
    "media",
    "xmlhttprequest",
    "ping",
    "websocket",
    "other",
];

/// A compiled set of lists.
pub struct Filters {
    engine: Engine,
}

impl std::fmt::Debug for Filters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Filters").finish_non_exhaustive()
    }
}

/// What to hide on one page.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cosmetic {
    /// Style rules, one per selector.
    pub css: String,
    /// Class and id exceptions to pass back with the page's names ([`Filters::generic_css`]).
    pub exceptions: Vec<String>,
    /// The site opted out of generic rules (`$generichide`).
    pub generic_hidden: bool,
}

impl Filters {
    /// Compiles `lists`, each the text of one list. Lines that do not parse are skipped, as every blocker does.
    #[must_use]
    pub fn new(lists: Vec<String>) -> Self {
        let mut set = FilterSet::new(false);
        let options = ParseOptions {
            format: FilterFormat::Standard,
            rule_types: RuleTypes::All,
            ..ParseOptions::default()
        };
        for text in lists {
            set.add_filter_list(text, options);
        }
        Self {
            engine: Engine::new_with_filter_set(set),
        }
    }

    /// Whether a request for `url`, made by the page at `page` for a `kind` of resource, is blocked.
    /// `kind` is one of the engine's request kinds; anything else counts as `other`.
    #[must_use]
    pub fn blocks(&self, url: &str, page: &str, kind: &str) -> bool {
        let kind = if KINDS.contains(&kind) { kind } else { "other" };
        // A page that cannot be parsed is judged as if the request were its own.
        let Ok(request) = Request::new(url, if page.is_empty() { url } else { page }, kind, "get")
        else {
            return false;
        };
        let result = self.engine.check_network_request(&request);
        result.filter.is_some() && result.exception.is_none()
    }

    /// The rules that hide elements on `url`'s page, without the generic ones.
    #[must_use]
    pub fn cosmetic(&self, url: &str) -> Cosmetic {
        let found = self.engine.url_cosmetic_resources(url);
        let mut selectors: Vec<&String> = found
            .hide_selectors
            .iter()
            .filter(|s| safe_selector(s))
            .collect();
        selectors.sort();
        selectors.truncate(MAX_SELECTORS);
        let mut exceptions: Vec<String> = found.exceptions.into_iter().collect();
        exceptions.sort();
        exceptions.truncate(MAX_PAGE_NAMES);
        Cosmetic {
            css: rules(selectors.iter().map(|s| s.as_str())),
            exceptions,
            generic_hidden: found.generichide,
        }
    }

    /// The generic hide rules for the class names and ids a page uses, as style rules.
    #[must_use]
    pub fn generic_css(&self, classes: &[String], ids: &[String], exceptions: &[String]) -> String {
        let names = |list: &[String]| -> Vec<String> {
            list.iter()
                .filter(|n| n.len() <= MAX_NAME_LEN)
                .take(MAX_PAGE_NAMES)
                .cloned()
                .collect()
        };
        let exceptions: HashSet<String> = exceptions.iter().take(MAX_PAGE_NAMES).cloned().collect();
        let mut found =
            self.engine
                .hidden_class_id_selectors(names(classes), names(ids), &exceptions);
        found.retain(|s| safe_selector(s));
        found.sort();
        found.dedup();
        found.truncate(MAX_SELECTORS);
        rules(found.iter().map(String::as_str))
    }
}

/// One style rule per selector: a selector the engine cannot parse then spoils only its own rule. Stops at [`MAX_CSS_BYTES`].
fn rules<'a>(selectors: impl Iterator<Item = &'a str>) -> String {
    const RULE: &str = "{display:none!important}\n";
    let mut css = String::new();
    for selector in selectors {
        if css
            .len()
            .saturating_add(selector.len())
            .saturating_add(RULE.len())
            > MAX_CSS_BYTES
        {
            break;
        }
        css.push_str(selector);
        css.push_str(RULE);
    }
    css
}

/// Whether a selector from a list is plain enough to put in a style rule
/// unescaped: nothing that closes the rule or opens another, loads a
/// resource, or is a procedural filter (those are JSON-encoded actions).
fn safe_selector(selector: &str) -> bool {
    !selector.is_empty()
        && selector.len() <= MAX_SELECTOR_LEN
        && !selector.starts_with('{')
        && !selector
            .chars()
            .any(|c| matches!(c, '{' | '}' | ';' | '@' | '\\' | '<') || c.is_control())
        && !selector.to_ascii_lowercase().contains("url(")
        && !selector.to_ascii_lowercase().contains("expression(")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filters() -> Filters {
        Filters::new(vec![
            "! Title: test\n||ads.example^\n||track.example/pixel.gif\n@@||ads.example/ok.js\n\
             ||accounts.example.org/gsi/$third-party\n\
             ##.banner-ad\nnews.example##.cookie-wall\n###sponsor\nnews.example##div{x}\n"
                .into(),
            "||custom.example^$script\n".into(),
        ])
    }

    #[test]
    fn blocks_by_host_and_path() {
        let f = filters();
        assert!(f.blocks(
            "https://ads.example/a.js",
            "https://news.example/",
            "script"
        ));
        assert!(f.blocks(
            "https://track.example/pixel.gif",
            "https://news.example/",
            "image"
        ));
        assert!(!f.blocks(
            "https://track.example/other.gif",
            "https://news.example/",
            "image"
        ));
        assert!(!f.blocks(
            "https://news.example/story",
            "https://news.example/",
            "document"
        ));
    }

    #[test]
    fn exceptions_and_options_apply() {
        let f = filters();
        assert!(!f.blocks(
            "https://ads.example/ok.js",
            "https://news.example/",
            "script"
        ));
        // `$third-party`: only from another site.
        assert!(f.blocks(
            "https://accounts.example.org/gsi/iframe",
            "https://news.example/",
            "subdocument"
        ));
        assert!(!f.blocks(
            "https://accounts.example.org/gsi/iframe",
            "https://accounts.example.org/",
            "subdocument"
        ));
        // `$script`: not images.
        assert!(f.blocks(
            "https://custom.example/x.js",
            "https://news.example/",
            "script"
        ));
        assert!(!f.blocks(
            "https://custom.example/x.png",
            "https://news.example/",
            "image"
        ));
    }

    #[test]
    fn unknown_kinds_and_bad_urls_do_not_block_or_panic() {
        let f = filters();
        assert!(f.blocks("https://ads.example/a", "https://n.example/", "nonsense"));
        assert!(!f.blocks("not a url", "https://n.example/", "script"));
        // An unreadable page address only makes the request third-party.
        assert!(f.blocks("https://ads.example/a", "garbage", "script"));
        assert!(f.blocks("https://ads.example/a", "", "script"));
    }

    #[test]
    fn cosmetic_rules_are_per_site_and_sanitised() {
        let f = filters();
        let news = f.cosmetic("https://news.example/story");
        assert!(news.css.contains(".cookie-wall{display:none!important}"));
        // The injected "div{x}" selector never reaches the CSS.
        assert!(!news.css.contains("div{x}"));
        let other = f.cosmetic("https://other.example/");
        assert!(!other.css.contains(".cookie-wall"));
    }

    #[test]
    fn generic_rules_follow_the_pages_names() {
        let f = filters();
        let css = f.generic_css(
            &["banner-ad".into(), "content".into()],
            &["sponsor".into()],
            &[],
        );
        assert!(css.contains(".banner-ad{display:none!important}"), "{css}");
        assert!(css.contains("#sponsor{display:none!important}"), "{css}");
        assert!(!css.contains(".content"));
        let excepted = f.generic_css(&["banner-ad".into()], &[], &[".banner-ad".into()]);
        assert!(!excepted.contains("banner-ad"), "{excepted}");
    }

    #[test]
    fn selectors_that_could_write_css_are_refused() {
        for bad in [
            "a}b{c",
            "a;b",
            "@import x",
            "a\\b",
            "a{",
            "x:style(color:red)url(",
            "",
            "a<b",
        ] {
            assert!(!safe_selector(bad), "{bad}");
        }
        for good in [
            ".ad",
            "#a-b",
            "div[class*=\"ad-\"]",
            "a > b",
            "div:has(> .x)",
            "a:not(.b) , c",
        ] {
            assert!(safe_selector(good), "{good}");
        }
    }

    #[test]
    fn css_is_bounded() {
        let list: String = (0..20_000)
            .map(|i| format!("##.some-long-ad-class-name-{i}\n"))
            .collect();
        let f = Filters::new(vec![list]);
        let names: Vec<String> = (0..20_000)
            .map(|i| format!("some-long-ad-class-name-{i}"))
            .collect();
        let css = f.generic_css(&names, &[], &[]);
        assert!(css.len() <= MAX_CSS_BYTES);
        assert!(css.lines().count() <= MAX_SELECTORS);
        assert!(css.lines().count() > 100);
    }

    proptest::proptest! {
        /// Whatever a list, an address or a page's names contain, nothing panics and every rule is plain.
        #[test]
        fn nothing_in_a_list_or_page_can_write_css(
            list in proptest::strategy::Strategy::prop_map(
                proptest::collection::vec("(##|###|a.example##|\\|\\||#\\?#|#@#)[^\n]{0,60}", 0..60),
                |lines| lines.join("\n"),
            ),
            url in ".{0,200}", page in ".{0,200}", names in proptest::collection::vec(".{0,40}", 0..40)) {
            let f = Filters::new(vec![list]);
            let _ = f.blocks(&url, &page, "script");
            for css in [f.cosmetic(&url).css, f.generic_css(&names, &names, &[])] {
                proptest::prop_assert!(css.len() <= MAX_CSS_BYTES);
                for line in css.lines() {
                    let selector = line.strip_suffix("{display:none!important}");
                    proptest::prop_assert!(selector.is_some_and(safe_selector), "{line:?}");
                }
            }
        }
    }

    #[test]
    fn an_empty_set_blocks_nothing() {
        let f = Filters::new(Vec::new());
        assert!(!f.blocks("https://ads.example/a.js", "https://n.example/", "script"));
        assert_eq!(f.cosmetic("https://n.example/"), Cosmetic::default());
    }
}
