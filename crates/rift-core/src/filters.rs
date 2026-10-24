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
//!
//! The lists' other changes to a page (`:style()`, `:remove()`,
//! `:remove-class()`, `:remove-attr()`, and hiding found by `:has-text()` or
//! `:upward()`) are what get a page out from under a sign-in wall. They are
//! checked here too and sent as data, which a fixed script in the browser
//! applies: a style may change only how an element looks (no resource, no
//! rule of its own), and anything else, including every list's scripts
//! (`##+js()`), is dropped.

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
/// Most changes beyond hiding returned for one page.
const MAX_ACTIONS: usize = 300;
/// Most bytes of those changes at once (they cross Binder too).
const MAX_ACTIONS_BYTES: usize = 100_000;
/// Most steps in one change's selector.
const MAX_STEPS: usize = 8;
/// Longest declaration a `:style()` may set.
const MAX_STYLE_LEN: usize = 300;
/// Longest text a `:has-text()` may look for.
const MAX_TEXT_LEN: usize = 200;

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
    /// Changes a style sheet cannot make, as a JSON array for the browser's
    /// script (empty if none). Each is `{"s": steps, "a": action}`: steps are
    /// `["css", selector]`, `["text", text or /regex/flags]` or `["up", n or
    /// selector]`, and the action is `["hide"]`, `["remove"]`, `["style",
    /// declarations]`, `["remove-class", name]` or `["remove-attr", name]`.
    pub actions: String,
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

    /// The compiled lists as bytes, to be kept and loaded again by [`Filters::from_saved`] (a
    /// cache: the format is the engine's own and changes between versions of it).
    #[must_use]
    pub fn save(&self) -> Vec<u8> {
        self.engine.serialize()
    }

    /// The lists as saved by [`Filters::save`]; `None` if the bytes are not a set the engine accepts
    /// (another version, a damaged file): the engine verifies them, and the caller compiles the lists again.
    #[must_use]
    pub fn from_saved(bytes: &[u8]) -> Option<Self> {
        let mut engine = Engine::default();
        engine.deserialize(bytes).ok()?;
        Some(Self { engine })
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
        let mut procedural: Vec<&String> = found.procedural_actions.iter().collect();
        procedural.sort();
        let mut styles = Vec::new();
        let mut actions = Vec::new();
        for json in procedural {
            match change(json) {
                Some(Change::Rule(rule)) => styles.push(rule),
                Some(Change::Script(action)) if actions.len() < MAX_ACTIONS => actions.push(action),
                _ => {}
            }
        }
        let mut css = rules(selectors.iter().map(|s| s.as_str()));
        for rule in styles {
            if css.len().saturating_add(rule.len()) > MAX_CSS_BYTES {
                break;
            }
            css.push_str(&rule);
        }
        let mut actions = serde_json::Value::Array(actions).to_string();
        while actions.len() > MAX_ACTIONS_BYTES {
            // Rare: halve the list until it fits, rather than cut a JSON text.
            let Ok(serde_json::Value::Array(mut list)) =
                serde_json::from_str::<serde_json::Value>(&actions)
            else {
                actions.clear();
                break;
            };
            list.truncate(list.len() / 2);
            actions = serde_json::Value::Array(list).to_string();
        }
        if actions == "[]" {
            actions.clear();
        }
        Cosmetic {
            css,
            exceptions,
            generic_hidden: found.generichide,
            actions,
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

/// One checked change from a list.
enum Change {
    /// A style rule (a plain selector and its declarations, or hidden).
    Rule(String),
    /// A change for the browser's script.
    Script(serde_json::Value),
}

/// Checks one of the engine's JSON-encoded procedural or action filters;
/// `None` if any part is unsupported or unsafe, so the rule is dropped whole.
fn change(json: &str) -> Option<Change> {
    use serde_json::{Value, json};
    let value: Value = serde_json::from_str(json).ok()?;
    let steps = value.get("selector")?.as_array()?;
    if steps.is_empty() || steps.len() > MAX_STEPS {
        return None;
    }
    let mut checked = Vec::with_capacity(steps.len());
    for step in steps {
        let arg = step.get("arg")?.as_str()?;
        let kind = match step.get("type")?.as_str()? {
            "css-selector" if safe_selector(arg.trim()) => "css",
            "has-text"
                if !arg.is_empty()
                    && arg.len() <= MAX_TEXT_LEN
                    && !arg.chars().any(char::is_control) =>
            {
                "text"
            }
            "upward" if arg.parse::<u8>().is_ok_and(|n| n > 0) || safe_selector(arg) => "up",
            _ => return None,
        };
        checked.push(json!([kind, arg.trim()]));
    }
    let action = match value.get("action") {
        None | Some(Value::Null) => json!(["hide"]),
        Some(action) => match action.get("type")?.as_str()? {
            "remove" => json!(["remove"]),
            "style" => {
                let style = action.get("arg")?.as_str()?.trim();
                safe_style(style).then(|| json!(["style", style]))?
            }
            kind @ ("remove-class" | "remove-attr") => {
                let name = action.get("arg")?.as_str()?;
                let plain = !name.is_empty()
                    && name.len() <= MAX_NAME_LEN
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
                plain.then(|| json!([kind, name]))?
            }
            _ => return None,
        },
    };
    // A plain selector that is styled or hidden needs no script: a style
    // rule, which also holds for elements the page adds later.
    if let ([only], Some(kind)) = (steps.as_slice(), action.get(0).and_then(Value::as_str))
        && only.get("type").and_then(Value::as_str) == Some("css-selector")
        && (kind == "hide" || kind == "style")
    {
        let selector = only.get("arg")?.as_str()?.trim();
        let body = action
            .get(1)
            .and_then(Value::as_str)
            .unwrap_or("display:none!important");
        return Some(Change::Rule(format!("{selector}{{{body}}}\n")));
    }
    Some(Change::Script(json!({ "s": checked, "a": action })))
}

/// Whether a list's `:style()` declarations change only how an element
/// looks: nothing that closes the rule, loads a resource, imports, escapes
/// or comments.
fn safe_style(style: &str) -> bool {
    const MARKERS: &[&str] = &[
        "url(",
        "image-set(",
        "image(",
        "expression(",
        "/*",
        "-moz-binding",
        "behavior",
    ];
    let lower = style.to_ascii_lowercase();
    !style.is_empty()
        && style.len() <= MAX_STYLE_LEN
        && !style
            .chars()
            .any(|c| matches!(c, '{' | '}' | '@' | '\\' | '<' | '"' | '\'') || c.is_control())
        && !MARKERS.iter().any(|m| lower.contains(m))
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
        && !is_procedural(selector)
}

/// Selectors only a blocker's own engine understands (uBlock's and AdGuard's
/// procedural cosmetic filters: `:has-text()`, `:contains()`, `:xpath()`…). In
/// a style sheet they match nothing and spoil only their own rule, so they
/// are not sent; the browser has no engine for them, and none is added.
fn is_procedural(selector: &str) -> bool {
    const MARKERS: &[&str] = &[
        ":has-text(",
        ":contains(",
        ":-abp-",
        ":xpath(",
        ":matches-css",
        ":matches-attr(",
        ":matches-media(",
        ":matches-path(",
        ":min-text-length(",
        ":nth-ancestor(",
        ":upward(",
        ":remove(",
        ":style(",
        ":others(",
        ":watch-attr(",
        ":not-has(",
        ":if(",
        ":if-not(",
        ":-js-",
        "[-ext-",
        ":properties(",
        ":withtext(",
    ];
    let lower = selector.to_ascii_lowercase();
    MARKERS.iter().any(|m| lower.contains(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filters() -> Filters {
        Filters::new(vec![
            "! Title: test\n||ads.example^\n||track.example/pixel.gif\n@@||ads.example/ok.js\n\
             ||accounts.example.org/gsi/$third-party\n\
             ##.banner-ad\nnews.example##.cookie-wall\n###sponsor\nnews.example##div{color:red} body{display:none}\n"
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
        // A rule that tries to close itself and open another never reaches the CSS.
        assert!(!news.css.contains("body{"), "{}", news.css);
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
    fn a_saved_set_answers_as_the_original_and_damage_is_refused() {
        let f = filters();
        let saved = f.save();
        let again = Filters::from_saved(&saved).expect("loads");
        assert!(again.blocks(
            "https://ads.example/a.js",
            "https://news.example/",
            "script"
        ));
        assert!(!again.blocks(
            "https://ads.example/ok.js",
            "https://news.example/",
            "script"
        ));
        assert_eq!(
            again.cosmetic("https://news.example/").css,
            f.cosmetic("https://news.example/").css
        );
        assert!(Filters::from_saved(&[]).is_none());
        assert!(Filters::from_saved(b"not a saved set").is_none());
        let mut damaged = saved;
        let middle = damaged.len() / 2;
        if let Some(byte) = damaged.get_mut(middle) {
            *byte ^= 0xff;
        }
        // Either refused, or still a set that does not panic.
        if let Some(loaded) = Filters::from_saved(&damaged) {
            let _ = loaded.blocks("https://ads.example/a.js", "https://n.example/", "script");
        }
    }

    #[test]
    fn an_empty_set_blocks_nothing() {
        let f = Filters::new(Vec::new());
        assert!(!f.blocks("https://ads.example/a.js", "https://n.example/", "script"));
        assert_eq!(f.cosmetic("https://n.example/"), Cosmetic::default());
    }

    fn walls() -> Filters {
        Filters::new(vec![
            "social.example##body:style(overflow: auto !important;)\n\
             social.example##.signup-wall:remove()\n\
             social.example##div:has-text(Sign up to continue):upward(2)\n\
             social.example##.feed:remove-class(blurred)\n\
             social.example##main:remove-attr(inert)\n\
             social.example#?#.modal:has-text(/log ?in/i)\n\
             social.example##+js(set, signupWall, false)\n\
             social.example##.q:matches-css(position: fixed)\n\
             evil.example##body:style(background: url(https://track.example/p.gif))\n\
             evil.example##body:style(color: red} * {display: none)\n\
             evil.example##body:style(color: \\72 ed)\n\
             evil.example##.x:remove-attr(on\"click)\n"
                .into(),
        ])
    }

    #[test]
    fn sign_in_walls_are_taken_down() {
        let page = walls().cosmetic("https://www.social.example/post/1");
        // A plain selector with a style becomes a style rule.
        assert!(
            page.css.contains("body{overflow: auto !important;}"),
            "{}",
            page.css
        );
        let actions: serde_json::Value = serde_json::from_str(&page.actions).unwrap();
        let actions = actions.as_array().unwrap();
        let has = |want: serde_json::Value| actions.contains(&want);
        assert!(
            has(serde_json::json!({"s": [["css", ".signup-wall"]], "a": ["remove"]})),
            "{actions:?}"
        );
        assert!(has(serde_json::json!({
            "s": [["css", "div"], ["text", "Sign up to continue"], ["up", "2"]],
            "a": ["hide"]
        })));
        assert!(has(
            serde_json::json!({"s": [["css", ".feed"]], "a": ["remove-class", "blurred"]})
        ));
        assert!(has(
            serde_json::json!({"s": [["css", "main"]], "a": ["remove-attr", "inert"]})
        ));
        assert!(has(
            serde_json::json!({"s": [["css", ".modal"], ["text", "/log ?in/i"]], "a": ["hide"]})
        ));
        // A list's scripts never reach the page, nor what the script cannot do.
        assert!(!page.actions.contains("signupWall"));
        assert!(!page.actions.contains("matches-css") && !page.actions.contains("position: fixed"));
        assert_eq!(actions.len(), 5);
        // Other sites get none of it.
        let other = walls().cosmetic("https://other.example/");
        assert!(other.actions.is_empty() && !other.css.contains("overflow"));
    }

    #[test]
    fn a_style_can_only_change_how_things_look() {
        let page = walls().cosmetic("https://evil.example/");
        assert!(page.actions.is_empty(), "{}", page.actions);
        assert!(
            !page.css.contains("url(") && !page.css.contains("color"),
            "{}",
            page.css
        );
        for bad in [
            "a} b{color:red",
            "background:url(x)",
            "color:\\72",
            "@import x",
            "color:red/*",
            "width:expression(1)",
            "a<b",
        ] {
            assert!(!safe_style(bad), "{bad}");
        }
        assert!(safe_style(
            "overflow: auto !important; position: static !important"
        ));
    }

    #[test]
    fn changes_are_bounded() {
        let many: String = (0..2 * MAX_ACTIONS)
            .map(|i| format!("social.example##.w{i}:remove()\n"))
            .collect();
        let page = Filters::new(vec![many]).cosmetic("https://social.example/");
        let actions: serde_json::Value = serde_json::from_str(&page.actions).unwrap();
        assert_eq!(actions.as_array().unwrap().len(), MAX_ACTIONS);
        assert!(page.actions.len() <= MAX_ACTIONS_BYTES);
        assert!(change("not json").is_none());
        assert!(change(r#"{"selector":[]}"#).is_none());
        assert!(change(r#"{"selector":[{"type":"xpath","arg":"//div"}]}"#).is_none());
        assert!(change(r#"{"selector":[{"type":"css-selector","arg":"a"}],"action":{"type":"inject","arg":"x"}}"#).is_none());
    }
}
