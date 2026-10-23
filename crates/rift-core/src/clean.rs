//! Link cleaning (§10.10): tracking parameters taken off an address, and the
//! address a redirect link wraps taken out of it, with the rules the ClearURLs
//! project keeps (its `data.min.json` format), which the user downloads.
//!
//! The rules are untrusted text. They are bounded before they are compiled,
//! and the `regex` engine matches in linear time, so no rule can make a check
//! slow. Cleaning can only take things away from an address: a parameter, or
//! a part a raw rule matches. A raw rule whose result has another scheme,
//! host or port is not applied, so no list can turn one site's address into
//! another's. The one change of site is unwrapping, which the result names,
//! and every address that comes out of here is checked again like any other.

use std::collections::BTreeMap;

use percent_encoding::percent_decode_str;
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use url::Url;

/// The largest rules file accepted: the upstream file is about 40 KB.
pub const MAX_RULES_BYTES: usize = 2 * 1024 * 1024;
const MAX_PROVIDERS: usize = 2_000;
const MAX_PATTERNS: usize = 20_000;
const MAX_PATTERN_CHARS: usize = 2_000;
/// Compiled size per pattern; the upstream patterns need a few KB.
const PATTERN_SIZE_LIMIT: usize = 256 * 1024;
/// Redirect links wrapped in redirect links, as far as this goes.
const MAX_UNWRAPS: usize = 5;
const MAX_URL_BYTES: usize = 16 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RulesError {
    #[error("the rules file is larger than {MAX_RULES_BYTES} bytes")]
    TooLarge,
    #[error("the rules file is not in the ClearURLs format: {0}")]
    Format(String),
    #[error("the rules file has more than {0}")]
    TooMany(&'static str),
    #[error("the rules file has no rules this build can use")]
    Empty,
}

#[derive(Deserialize)]
struct RulesFile {
    providers: BTreeMap<String, ProviderFile>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProviderFile {
    url_pattern: String,
    #[serde(default)]
    complete_provider: bool,
    #[serde(default)]
    rules: Vec<String>,
    #[serde(default)]
    raw_rules: Vec<String>,
    #[serde(default)]
    referral_marketing: Vec<String>,
    #[serde(default)]
    exceptions: Vec<String>,
    #[serde(default)]
    redirections: Vec<String>,
}

#[derive(Debug)]
struct Provider {
    name: String,
    url_pattern: Regex,
    complete: bool,
    /// Parameter names, each matched whole (`^rule$`), as ClearURLs does.
    fields: Vec<Regex>,
    raw: Vec<Regex>,
    exceptions: Vec<Regex>,
    redirections: Vec<Regex>,
}

/// Compiled cleaning rules.
#[derive(Debug)]
pub struct Rules {
    providers: Vec<Provider>,
    /// Patterns that did not compile here (JavaScript syntax that the `regex`
    /// engine lacks, such as look-around); their rules are left out.
    skipped: usize,
}

/// What cleaning did to an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cleaned {
    /// The address with what the rules match taken away, in the form the
    /// engine loads (see `policy::engine_address`).
    pub url: String,
    /// Names of the parameters removed, decoded, in the order found.
    pub removed: Vec<String>,
    /// Each address taken out of a redirect link, outermost first; `url`
    /// is the last of them, cleaned.
    pub unwrapped: Vec<String>,
    /// Rules that matched (providers' names), in the order applied.
    pub providers: Vec<String>,
    /// The whole address is a tracker's (ClearURLs' "complete provider"):
    /// there is nothing to keep, and the user is told so.
    pub tracker_only: bool,
}

impl Cleaned {
    /// Whether the address changed.
    pub fn changed(&self, original: &str) -> bool {
        self.url != original
    }
}

impl Rules {
    /// Compiles a ClearURLs rules file. Patterns that do not compile are
    /// skipped (counted in [`Rules::skipped`]); a provider whose own URL
    /// pattern does not compile is left out whole.
    pub fn parse(text: &str) -> Result<Self, RulesError> {
        if text.len() > MAX_RULES_BYTES {
            return Err(RulesError::TooLarge);
        }
        let file: RulesFile =
            serde_json::from_str(text).map_err(|e| RulesError::Format(e.to_string()))?;
        if file.providers.len() > MAX_PROVIDERS {
            return Err(RulesError::TooMany("2,000 providers"));
        }
        let total: usize = file
            .providers
            .values()
            .map(|p| {
                1usize
                    .saturating_add(p.rules.len())
                    .saturating_add(p.raw_rules.len())
                    .saturating_add(p.referral_marketing.len())
                    .saturating_add(p.exceptions.len())
                    .saturating_add(p.redirections.len())
            })
            .fold(0usize, usize::saturating_add);
        if total > MAX_PATTERNS {
            return Err(RulesError::TooMany("20,000 patterns"));
        }
        let mut skipped = 0usize;
        let mut compile = |pattern: &str| -> Option<Regex> {
            let built = (pattern.chars().count() <= MAX_PATTERN_CHARS)
                .then(|| {
                    RegexBuilder::new(pattern)
                        .case_insensitive(true)
                        .size_limit(PATTERN_SIZE_LIMIT)
                        .dfa_size_limit(PATTERN_SIZE_LIMIT)
                        .build()
                        .ok()
                })
                .flatten();
            if built.is_none() {
                skipped = skipped.saturating_add(1);
            }
            built
        };
        let mut providers = Vec::new();
        for (name, p) in file.providers {
            let Some(url_pattern) = compile(&p.url_pattern) else {
                continue;
            };
            let fields = p
                .rules
                .iter()
                .chain(&p.referral_marketing)
                .filter_map(|rule| compile(&format!("^(?:{rule})$")))
                .collect();
            let raw = p.raw_rules.iter().filter_map(|r| compile(r)).collect();
            let exceptions = p.exceptions.iter().filter_map(|r| compile(r)).collect();
            let redirections = p.redirections.iter().filter_map(|r| compile(r)).collect();
            providers.push(Provider {
                name,
                url_pattern,
                complete: p.complete_provider,
                fields,
                raw,
                exceptions,
                redirections,
            });
        }
        if providers.is_empty() {
            return Err(RulesError::Empty);
        }
        Ok(Self { providers, skipped })
    }

    /// Patterns left out because they did not compile here.
    pub fn skipped(&self) -> usize {
        self.skipped
    }

    /// Providers in use.
    pub fn providers(&self) -> usize {
        self.providers.len()
    }

    /// Cleans `address`, an `http` or `https` address in the engine's form.
    /// Anything else comes back unchanged, with nothing removed.
    pub fn clean(&self, address: &str) -> Cleaned {
        let mut out = Cleaned {
            url: address.to_owned(),
            removed: Vec::new(),
            unwrapped: Vec::new(),
            providers: Vec::new(),
            tracker_only: false,
        };
        if address.len() > MAX_URL_BYTES || web(address).is_none() {
            return out;
        }
        for _ in 0..=MAX_UNWRAPS {
            match self.clean_once(&mut out) {
                Some(inner) if out.unwrapped.len() < MAX_UNWRAPS => {
                    out.unwrapped.push(inner.clone());
                    out.url = inner;
                }
                _ => break,
            }
        }
        out
    }

    /// One pass over `out.url`. Returns the address a redirect link wraps,
    /// to clean next; otherwise cleans `out.url` in place.
    fn clean_once(&self, out: &mut Cleaned) -> Option<String> {
        for provider in &self.providers {
            let url = out.url.clone();
            if !provider.url_pattern.is_match(&url)
                || provider.exceptions.iter().any(|e| e.is_match(&url))
            {
                continue;
            }
            note(&mut out.providers, &provider.name);
            if provider.complete {
                out.tracker_only = true;
                return None;
            }
            for redirection in &provider.redirections {
                let inner = redirection
                    .captures(&url)
                    .and_then(|c| c.get(1))
                    .and_then(|m| percent_decode_str(m.as_str()).decode_utf8().ok())
                    .and_then(|inner| web(&inner));
                if inner.is_some() {
                    return inner;
                }
            }
            let mut cleaned = url;
            for raw in &provider.raw {
                let candidate = raw.replace_all(&cleaned, "").into_owned();
                if let Some(next) = web(&candidate)
                    && same_origin(&cleaned, &next)
                {
                    cleaned = next;
                }
            }
            out.url = remove_fields(&cleaned, &provider.fields, &mut out.removed);
        }
        None
    }
}

/// `address` without its query and fragment.
pub fn without_query(address: &str) -> Option<String> {
    let mut url = Url::parse(address).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    url.set_query(None);
    url.set_fragment(None);
    Some(url.into())
}

/// `address` with `https` in place of `http`; None if it is not `http`.
pub fn with_https(address: &str) -> Option<String> {
    let mut url = Url::parse(address).ok()?;
    if url.scheme() != "http" {
        return None;
    }
    // The default port goes with the scheme; another port is kept.
    if url.port() == Some(80) {
        url.set_port(None).ok()?;
    }
    url.set_scheme("https").ok()?;
    Some(url.into())
}

/// `text` as a web address in the engine's form, if it is one.
fn web(text: &str) -> Option<String> {
    let url = Url::parse(text.trim()).ok()?;
    (matches!(url.scheme(), "http" | "https") && url.host_str().is_some_and(|h| !h.is_empty()))
        .then(|| url.into())
}

fn same_origin(a: &str, b: &str) -> bool {
    match (Url::parse(a), Url::parse(b)) {
        (Ok(a), Ok(b)) => a.origin() == b.origin(),
        _ => false,
    }
}

fn note(names: &mut Vec<String>, name: &str) {
    if !names.iter().any(|n| n == name) {
        names.push(name.to_owned());
    }
}

/// Takes the parameters whose names match `fields` out of the query and out
/// of a `key=value` fragment. Kept parameters keep their exact spelling.
fn remove_fields(address: &str, fields: &[Regex], removed: &mut Vec<String>) -> String {
    if fields.is_empty() {
        return address.to_owned();
    }
    let Ok(mut url) = Url::parse(address) else {
        return address.to_owned();
    };
    let mut drop = |pairs: &str| -> Option<String> {
        let kept: Vec<&str> = pairs
            .split('&')
            .filter(|pair| {
                let name = pair.split_once('=').map_or(*pair, |(name, _)| name);
                let decoded = percent_decode_str(&name.replace('+', " "))
                    .decode_utf8_lossy()
                    .into_owned();
                let matched = !name.is_empty() && fields.iter().any(|f| f.is_match(&decoded));
                if matched {
                    note(removed, &decoded);
                }
                !matched
            })
            .collect();
        let joined = kept.join("&");
        (!joined.is_empty()).then_some(joined)
    };
    if let Some(query) = url.query().map(str::to_owned) {
        let kept = drop(&query);
        url.set_query(kept.as_deref());
    }
    // A fragment is cleaned only when it reads as parameters (`#a=1&b=2`).
    if let Some(fragment) = url.fragment().map(str::to_owned)
        && fragment.contains('=')
        && !fragment.contains('/')
    {
        let kept = drop(&fragment);
        url.set_fragment(kept.as_deref());
    }
    url.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// A few rules in the ClearURLs format, modelled on upstream ones.
    const RULES: &str = r#"{"providers":{
        "globalRules":{"urlPattern":".*","rules":["(?:%3F)?utm(?:_[a-z_]*)?","(?:%3F)?fbclid","(?:%3F)?gclid"],
            "referralMarketing":["(?:%3F)?ref_?"],
            "exceptions":["^https?:\\/\\/[^/]+\\/keep-utm"]},
        "amazon":{"urlPattern":"^https?:\\/\\/(?:[a-z0-9-]+\\.)*?amazon(?:\\.[a-z]{2,}){1,}",
            "rules":["qid","sr"],"rawRules":["\\/ref=[^/?]*"],"referralMarketing":["tag"]},
        "google":{"urlPattern":"^https?:\\/\\/(?:[a-z0-9-]+\\.)*?google(?:\\.[a-z]{2,}){1,}",
            "rules":["ved","usg"],
            "redirections":["^https?:\\/\\/(?:[a-z0-9-]+\\.)*?google(?:\\.[a-z]{2,}){1,}\\/url\\?.*?(?:url|q)=(https?[^&]+)"]},
        "doubleclick":{"urlPattern":"^https?:\\/\\/(?:[a-z0-9-]+\\.)*?doubleclick\\.net","completeProvider":true},
        "hostile":{"urlPattern":"^https?:\\/\\/hostile\\.example","rawRules":["hostile\\.example","\\/secret"]},
        "lookaround":{"urlPattern":"^https?:\\/\\/la\\.example","rules":["(?<=x)y","z"]}
    }}"#;

    fn rules() -> Rules {
        Rules::parse(RULES).unwrap()
    }

    #[test]
    fn tracking_parameters_are_removed_and_named() {
        let c = rules()
            .clean("https://shop.example/item?id=7&utm_source=news&utm_medium=mail&fbclid=abc#top");
        assert_eq!(c.url, "https://shop.example/item?id=7#top");
        assert_eq!(c.removed, ["utm_source", "utm_medium", "fbclid"]);
        assert!(c.unwrapped.is_empty() && !c.tracker_only);
        // Nothing to take away: the address comes back as it was.
        let plain = "https://shop.example/item?id=7";
        assert!(!rules().clean(plain).changed(plain));
    }

    #[test]
    fn kept_parameters_keep_their_spelling_and_an_empty_query_goes() {
        let c = rules().clean("https://a.example/s?q=a+b%20c&utm_source=x");
        assert_eq!(c.url, "https://a.example/s?q=a+b%20c");
        let c = rules().clean("https://a.example/s?utm_source=x&gclid=y");
        assert_eq!(c.url, "https://a.example/s");
        // Fragment parameters too, but not a fragment that is a route.
        let c = rules().clean("https://a.example/p#utm_source=x&page=2");
        assert_eq!(c.url, "https://a.example/p#page=2");
        let c = rules().clean("https://a.example/p#/route?utm_source=x");
        assert_eq!(c.url, "https://a.example/p#/route?utm_source=x");
    }

    #[test]
    fn site_rules_raw_rules_and_exceptions_apply() {
        let c = rules().clean("https://www.amazon.de/Some-Thing/dp/B000/ref=sr_1_3?qid=1&sr=8-3&tag=aff-21&keywords=x");
        assert_eq!(c.url, "https://www.amazon.de/Some-Thing/dp/B000?keywords=x");
        assert_eq!(c.removed, ["qid", "sr", "tag"]);
        assert!(c.providers.contains(&"amazon".to_owned()));
        let kept = "https://a.example/keep-utm?utm_source=x";
        assert_eq!(rules().clean(kept).url, kept);
    }

    #[test]
    fn redirect_links_are_unwrapped_and_the_inner_address_cleaned() {
        let c = rules().clean(
            "https://www.google.com/url?sa=t&url=https%3A%2F%2Fnews.example%2Fstory%3Futm_source%3Dg%26id%3D4&usg=x",
        );
        assert_eq!(
            c.unwrapped,
            ["https://news.example/story?utm_source=g&id=4"]
        );
        assert_eq!(c.url, "https://news.example/story?id=4");
        assert_eq!(c.removed, ["utm_source"]);
    }

    #[test]
    fn unwrapping_takes_only_web_addresses_and_stops() {
        let c = rules().clean("https://www.google.com/url?q=javascript%3Aalert(1)");
        assert!(c.unwrapped.is_empty());
        // Wrapped in itself more times than allowed: stops at the limit.
        let mut url = "https://end.example/".to_owned();
        for _ in 0..MAX_UNWRAPS.saturating_add(3) {
            url = format!(
                "https://www.google.com/url?q={}",
                percent_encoding::utf8_percent_encode(&url, percent_encoding::NON_ALPHANUMERIC)
            );
        }
        let c = rules().clean(&url);
        assert_eq!(c.unwrapped.len(), MAX_UNWRAPS);
    }

    #[test]
    fn a_tracker_only_address_is_named_not_cleaned() {
        let c = rules().clean("https://ad.doubleclick.net/ddm/clk/123;abc");
        assert!(c.tracker_only);
        assert_eq!(c.url, "https://ad.doubleclick.net/ddm/clk/123;abc");
    }

    #[test]
    fn a_raw_rule_cannot_change_the_site() {
        // "hostile.example" removed from the host would leave another
        // address; only the path rule applies.
        let c = rules().clean("https://hostile.example/secret/page");
        assert_eq!(c.url, "https://hostile.example/page");
    }

    #[test]
    fn patterns_this_engine_lacks_are_skipped_not_fatal() {
        let r = rules();
        assert_eq!(r.skipped(), 1);
        let c = r.clean("https://la.example/?z=1&y=2");
        assert_eq!(c.url, "https://la.example/?y=2");
    }

    #[test]
    fn hostile_files_are_refused_before_compiling() {
        assert_eq!(
            Rules::parse(&" ".repeat(MAX_RULES_BYTES.saturating_add(1))).unwrap_err(),
            RulesError::TooLarge
        );
        assert!(matches!(Rules::parse("[]"), Err(RulesError::Format(_))));
        assert_eq!(
            Rules::parse(r#"{"providers":{}}"#).unwrap_err(),
            RulesError::Empty
        );
        let many = format!(
            r#"{{"providers":{{"p":{{"urlPattern":".*","rules":[{}]}}}}}}"#,
            vec!["\"a\""; MAX_PATTERNS.saturating_add(1)].join(",")
        );
        assert!(matches!(Rules::parse(&many), Err(RulesError::TooMany(_))));
        // A pattern too big to compile within the limit is skipped.
        let big = r#"{"providers":{"p":{"urlPattern":".*","rules":["(?:\\w{100}){100}","a"]}}}"#;
        assert_eq!(Rules::parse(big).unwrap().skipped(), 1);
    }

    #[test]
    fn only_web_addresses_are_cleaned() {
        for text in [
            "javascript:alert(1)?utm_source=x",
            "not an address",
            "file:///x?utm_source=1",
        ] {
            assert_eq!(rules().clean(text).url, text);
        }
    }

    #[test]
    fn query_and_scheme_helpers() {
        assert_eq!(
            without_query("https://a.example/p?x=1#f").as_deref(),
            Some("https://a.example/p")
        );
        assert_eq!(
            with_https("http://a.example:80/p").as_deref(),
            Some("https://a.example/p")
        );
        assert_eq!(
            with_https("http://a.example:8080/p").as_deref(),
            Some("https://a.example:8080/p")
        );
        assert_eq!(with_https("https://a.example/"), None);
        assert_eq!(without_query("ftp://a.example/?x"), None);
    }

    proptest! {
        /// Without unwrapping, cleaning never changes the site, and it never
        /// makes an address longer.
        #[test]
        fn cleaning_keeps_the_site(
            host in "[a-z]{1,10}\\.(example|amazon\\.de|hostile\\.example)",
            path in "(/[a-z0-9=._-]{0,8}){0,3}",
            query in proptest::collection::vec(("(utm_[a-z]{1,4}|qid|tag|id|q|fbclid)", "[a-z0-9%]{0,6}"), 0..5),
        ) {
            let query = query.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&");
            let address = web(&format!("https://{host}{path}?{query}")).unwrap();
            let c = rules().clean(&address);
            prop_assert!(c.unwrapped.is_empty());
            prop_assert!(same_origin(&address, &c.url), "{address} -> {}", c.url);
            prop_assert!(c.url.len() <= address.len(), "{address} -> {}", c.url);
        }
    }
}
