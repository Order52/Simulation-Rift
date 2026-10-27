//! Navigation policy (docs/architecture.md §10.2–§10.4, INV-6, INV-7).
//!
//! A pure function of its inputs: no I/O, no clocks, no globals, so every
//! combination can be tested. The browser host asks before each main-frame
//! navigation it can observe and must follow the decision.

use crate::heuristics::{self, Flag, HeuristicConfig, Severity};
use crate::intel::UrlTable;
use crate::text::escape_for_display;
use crate::urlcanon::{self, CanonError};
use crate::urlmodel::{Assessment, Level, UrlModel, View};
use url::Url;

/// Freshness of the active intelligence snapshot, determined by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntelState {
    Current,
    /// Installed but past its expected refresh; still used offline.
    Stale,
    /// No verified snapshot installed.
    Missing,
}

#[derive(Debug)]
pub struct NavigationContext<'a> {
    /// The engine's renderer sandbox was positively verified (INV-7).
    pub sandbox_verified: bool,
    pub indicators: Option<&'a UrlTable>,
    pub intel_state: IntelState,
    pub heuristics: &'a HeuristicConfig,
    /// Rift AI (§16), if loaded: advisory, consulted after the indicators.
    pub model: Option<&'a UrlModel>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Load the page; `notes` are shown in the protection details.
    Proceed { notes: Vec<Note> },
    /// Show a trusted interstitial; load only if the user confirms.
    Confirm {
        reasons: Vec<Reason>,
        notes: Vec<Note>,
    },
    /// Do not load. `inspect_anyway` permits an explicit per-navigation
    /// override in the same restricted session (only for indicator matches).
    Block {
        reason: BlockReason,
        inspect_anyway: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    Heuristic(Flag),
    /// Rift AI rates the address High.
    Ai(AiFinding),
    /// The URL could not be assessed (e.g. longer than the checker accepts).
    NotChecked(CanonError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    Heuristic(Flag),
    /// Rift AI rates the address Elevated.
    Ai(AiFinding),
    IntelStale,
    IntelMissing,
}

/// What Rift AI said about an address, for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiFinding {
    /// 0 to 99: never 100, which would read as certainty.
    pub score: u8,
    pub signals: Vec<String>,
}

impl AiFinding {
    pub fn from_assessment(assessment: &Assessment) -> Self {
        Self {
            score: assessment.risk,
            signals: assessment.signals.clone(),
        }
    }

    fn because(&self) -> String {
        if self.signals.is_empty() {
            String::new()
        } else {
            format!(" What stood out: {}.", self.signals.join("; "))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockReason {
    SandboxUnavailable,
    SchemeNotAllowed(String),
    InvalidUrl,
    /// Matched indicators: (expression that matched, pack metadata index).
    KnownMalicious(Vec<(String, u32)>),
}

impl Reason {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Heuristic(flag) => flag.code(),
            Self::Ai(_) => "ai-suspicious",
            Self::NotChecked(_) => "not-checked",
        }
    }

    pub fn explain(&self) -> String {
        match self {
            Self::Heuristic(flag) => flag.explain(),
            Self::Ai(finding) => format!(
                "Rift AI: this address closely resembles known phishing and malware links ({}/100).{} A resemblance, not proof.",
                finding.score,
                finding.because()
            ),
            Self::NotChecked(error) => format!("This address could not be checked ({error})."),
        }
    }
}

impl Note {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Heuristic(flag) => flag.code(),
            Self::Ai(_) => "ai-elevated",
            Self::IntelStale => "intel-stale",
            Self::IntelMissing => "intel-missing",
        }
    }

    pub fn explain(&self) -> String {
        match self {
            Self::Heuristic(flag) => flag.explain(),
            Self::Ai(finding) => format!(
                "Rift AI: this address somewhat resembles known malicious links ({}/100).{} Not proof either way.",
                finding.score,
                finding.because()
            ),
            Self::IntelStale => {
                "The threat database is out of date; recently listed sites may be missed."
                    .to_owned()
            }
            Self::IntelMissing => {
                "No threat database is installed; only the built-in address checks ran.".to_owned()
            }
        }
    }
}

impl BlockReason {
    pub fn code(&self) -> &'static str {
        match self {
            Self::SandboxUnavailable => "sandbox-unavailable",
            Self::SchemeNotAllowed(_) => "scheme-not-allowed",
            Self::InvalidUrl => "invalid-url",
            Self::KnownMalicious(_) => "known-malicious",
        }
    }

    pub fn explain(&self) -> String {
        match self {
            Self::SandboxUnavailable => {
                "Browsing is unavailable: the browser engine's sandbox could not be confirmed on this device."
                    .to_owned()
            }
            Self::SchemeNotAllowed(scheme) => format!(
                "Rift opens only web addresses; \"{}:\" links are blocked.",
                escape_for_display(scheme)
            ),
            Self::InvalidUrl => "This is not a valid web address.".to_owned(),
            Self::KnownMalicious(_) => {
                "This address is listed as malicious in the installed threat database.".to_owned()
            }
        }
    }
}

/// Decides a main-frame navigation to `raw` (as typed or as reported by the engine).
pub fn decide_navigation(raw: &[u8], ctx: &NavigationContext<'_>) -> Decision {
    if !ctx.sandbox_verified {
        return block(BlockReason::SandboxUnavailable);
    }
    match explicit_scheme(raw) {
        Some(scheme) if scheme != "http" && scheme != "https" => {
            return block(BlockReason::SchemeNotAllowed(scheme));
        }
        _ => {}
    }

    // Judge the address the engine will load, not a looser reading of it.
    let Some(address) = engine_address(raw) else {
        return block(BlockReason::InvalidUrl);
    };
    let raw = address.as_bytes();

    let mut notes = match ctx.intel_state {
        IntelState::Current => Vec::new(),
        IntelState::Stale => vec![Note::IntelStale],
        IntelState::Missing => vec![Note::IntelMissing],
    };
    let url = match urlcanon::canonicalize(raw) {
        Ok(url) => url,
        Err(CanonError::NoHost | CanonError::InvalidHost) => return block(BlockReason::InvalidUrl),
        // Unassessable is never silently "fine": the user must confirm.
        Err(error) => {
            return Decision::Confirm {
                reasons: vec![Reason::NotChecked(error)],
                notes,
            };
        }
    };

    if let Some(table) = ctx.indicators {
        let matches = table.matches(&url);
        if !matches.is_empty() {
            return Decision::Block {
                reason: BlockReason::KnownMalicious(matches),
                inspect_anyway: true,
            };
        }
    }

    let mut reasons = Vec::new();
    for flag in heuristics::assess(raw, &url, ctx.heuristics) {
        match flag.severity() {
            Severity::Warn => reasons.push(Reason::Heuristic(flag)),
            Severity::Info => notes.push(Note::Heuristic(flag)),
        }
    }
    // Advisory (§16): it can ask the user to confirm; it never blocks, and
    // a low score adds nothing (it is not a sign of safety).
    if let Some(model) = ctx.model {
        let assessment = model.assess(&url, View::Address);
        match assessment.level {
            Level::High => reasons.push(Reason::Ai(AiFinding::from_assessment(&assessment))),
            Level::Elevated => notes.push(Note::Ai(AiFinding::from_assessment(&assessment))),
            Level::Low => {}
        }
    }
    if reasons.is_empty() {
        Decision::Proceed { notes }
    } else {
        Decision::Confirm { reasons, notes }
    }
}

fn block(reason: BlockReason) -> Decision {
    Decision::Block {
        reason,
        inspect_anyway: false,
    }
}

/// A web address as a browser engine parses it (the WHATWG URL standard,
/// which Chromium and Qt WebEngine follow), serialized; `None` if it is not
/// an `http` or `https` address the engine could load.
///
/// The Safe Browsing canonicalization the checks use is deliberately loose,
/// and on its own it read some addresses differently from the engine:
/// `https://evil.example\@good.example/` was checked as `good.example` and
/// opened as `evil.example`, and a host with spaces was let through to an
/// engine that then loaded nothing. Checking this form, and loading it,
/// keeps the two readings the same.
pub fn engine_address(raw: &[u8]) -> Option<String> {
    let url = Url::parse(std::str::from_utf8(raw).ok()?).ok()?;
    matches!(url.scheme(), "http" | "https").then(|| url.into())
}

/// The URL to load for text typed in the address bar or shared with Rift.
/// The first `http(s)://` link in the text is used, so a message such as
/// "look at this: https://…" opens its link; if there is none, the whole
/// text is the address. Without a scheme it becomes an `https://` address,
/// unless it holds spaces (then it is no address at all, and comes back
/// unchanged for the decision to refuse). A web address comes back in the
/// form the engine will load (see `engine_address`); any other scheme comes
/// back unchanged for the decision to judge. Only the decision says whether
/// it may load. Applying it again changes nothing, so the controller and
/// the browser can both apply it.
pub fn typed_address(input: &str) -> String {
    let link = link_in_text(input);
    let address =
        if explicit_scheme(link.as_bytes()).is_some() || link.contains(char::is_whitespace) {
            link
        } else {
            format!("https://{link}")
        };
    engine_address(address.as_bytes()).unwrap_or(address)
}

/// The first `http://` or `https://` link in `text` (ending at whitespace,
/// a quote or an angle bracket, without trailing punctuation), after undoing
/// the "defanged" spellings that threat reports use so that a link cannot be
/// clicked by accident (`hxxps://`, `example[.]com`, `[:]`). Otherwise the
/// trimmed text.
fn link_in_text(text: &str) -> String {
    let text = text.trim();
    let lower = text.to_ascii_lowercase();
    // A link on its own is taken exactly as it is.
    if (lower.starts_with("https://") || lower.starts_with("http://"))
        && !text.contains(char::is_whitespace)
    {
        return text.to_owned();
    }
    let text = refang(text);
    // ASCII lowercasing keeps every byte offset.
    let lower = text.to_ascii_lowercase();
    let start = [lower.find("https://"), lower.find("http://")]
        .into_iter()
        .flatten()
        .min();
    let Some(link) = start.and_then(|at| text.get(at..)) else {
        return text;
    };
    let end = link
        .find(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '"' | '\'' | '`'))
        .unwrap_or(link.len());
    trim_trailing_punctuation(link.get(..end).unwrap_or(link)).to_owned()
}

fn refang(text: &str) -> String {
    let mut out = text
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("{.}", ".")
        .replace("[:]", ":");
    for (defanged, plain) in [("hxxps://", "https://"), ("hxxp://", "http://")] {
        while let Some(at) = out.to_ascii_lowercase().find(defanged) {
            out.replace_range(at..at.saturating_add(defanged.len()), plain);
        }
    }
    out
}

/// Drops sentence punctuation after a link, and closing brackets that do
/// not close one opened inside it ("(see https://example.org/a_(b))").
fn trim_trailing_punctuation(mut link: &str) -> &str {
    loop {
        let Some(last) = link.chars().next_back() else {
            return link;
        };
        let opener = match last {
            ')' => Some('('),
            ']' => Some('['),
            '}' => Some('{'),
            _ => None,
        };
        let strip = match opener {
            Some(open) => link.matches(last).count() > link.matches(open).count(),
            None => matches!(last, '.' | ',' | ';' | ':' | '!' | '?'),
        };
        if !strip {
            return link;
        }
        link = link
            .get(..link.len().saturating_sub(last.len_utf8()))
            .unwrap_or_default();
    }
}

/// The scheme the input explicitly names, if any (`javascript:`, `intent:`, …).
/// `host:8080`-style input is not a scheme. Inputs without one are treated as
/// web addresses by canonicalization.
pub(crate) fn explicit_scheme(raw: &[u8]) -> Option<String> {
    let trimmed = raw.trim_ascii_start();
    let colon = trimmed.iter().position(|&b| b == b':')?;
    let (candidate, rest) = trimmed.split_at(colon);
    let (first, tail) = candidate.split_first()?;
    let looks_like_scheme = first.is_ascii_alphabetic()
        && tail
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'));
    let followed_by_port = rest.get(1).is_some_and(u8::is_ascii_digit);
    (looks_like_scheme && !followed_by_port)
        .then(|| String::from_utf8_lossy(candidate).to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::urlcanon::{MAX_URL_BYTES, expression_hash};

    fn table(expressions: &[&str]) -> UrlTable {
        let entries = expressions
            .iter()
            .zip(0u32..)
            .map(|(e, i)| (expression_hash(e), i))
            .collect();
        UrlTable::parse(&UrlTable::encode(entries).unwrap(), 100).unwrap()
    }

    fn config() -> HeuristicConfig {
        HeuristicConfig {
            protected_domains: vec!["paypal.com".into()],
            ..HeuristicConfig::default()
        }
    }

    fn decide(raw: &str, indicators: Option<&UrlTable>, sandbox_verified: bool) -> Decision {
        let heuristics = config();
        let ctx = NavigationContext {
            sandbox_verified,
            indicators,
            intel_state: IntelState::Current,
            heuristics: &heuristics,
            model: None,
        };
        decide_navigation(raw.as_bytes(), &ctx)
    }

    #[test]
    fn unverified_sandbox_blocks_everything_without_override() {
        let decision = decide("https://example.org/", None, false);
        assert_eq!(
            decision,
            Decision::Block {
                reason: BlockReason::SandboxUnavailable,
                inspect_anyway: false
            }
        );
    }

    #[test]
    fn only_web_schemes_are_navigable() {
        for (raw, scheme) in [
            ("javascript:alert(1)", "javascript"),
            ("JavaScript:alert(1)", "javascript"),
            ("  file:///etc/passwd", "file"),
            ("content://contacts/people", "content"),
            ("intent://scan/#Intent;scheme=zxing;end", "intent"),
            ("data:text/html,<script>1</script>", "data"),
            ("market://details?id=x", "market"),
        ] {
            assert_eq!(
                decide(raw, None, true),
                Decision::Block {
                    reason: BlockReason::SchemeNotAllowed(scheme.into()),
                    inspect_anyway: false
                },
                "{raw}"
            );
        }
        assert!(matches!(
            decide("https://example.org/", None, true),
            Decision::Proceed { .. }
        ));
        // Not an address the engine could load; typed text gets a scheme
        // from typed_address first.
        assert_eq!(
            decide("example.org", None, true),
            Decision::Block {
                reason: BlockReason::InvalidUrl,
                inspect_anyway: false
            }
        );
        assert!(matches!(
            decide(&typed_address("example.org"), None, true),
            Decision::Proceed { .. }
        ));
        // "host:port" is not read as a scheme.
        assert!(matches!(
            decide(&typed_address("localhost:8080/x"), None, true),
            Decision::Proceed { .. }
        ));
    }

    #[test]
    fn indicator_match_blocks_with_explicit_override_only() {
        let bad = table(&["evil.example/"]);
        match decide("https://cdn.evil.example/kit/index.html", Some(&bad), true) {
            Decision::Block {
                reason: BlockReason::KnownMalicious(hits),
                inspect_anyway: true,
            } => {
                assert_eq!(hits, vec![("evil.example/".to_owned(), 0)]);
            }
            other => panic!("expected block, got {other:?}"),
        }
    }

    #[test]
    fn checks_judge_the_host_the_engine_opens() {
        // Browsers read '\\' as '/' in web addresses, so these open evil.example.
        let bad = table(&["evil.example/"]);
        for raw in [
            "https://evil.example\\@good.example/",
            "https://evil.example\\.good.example/",
            "https://evil.example\\good.example",
        ] {
            assert!(
                matches!(
                    decide(raw, Some(&bad), true),
                    Decision::Block {
                        reason: BlockReason::KnownMalicious(_),
                        ..
                    }
                ),
                "{raw}"
            );
            assert!(
                typed_address(raw).starts_with("https://evil.example/"),
                "{raw}"
            );
        }
        // The lookalike check sees the real host too.
        assert!(matches!(
            decide("https://paypa1.com\\.example.org/", None, true),
            Decision::Confirm { reasons, .. }
                if reasons.iter().any(|r| r.code() == "lookalike")
        ));
        // A host the engine cannot load is not "not flagged".
        for raw in [
            "https://exa mple.org/",
            "https://Check this out: https://example.com/",
            "https://example.org:99999/",
        ] {
            assert_eq!(
                decide(raw, None, true),
                Decision::Block {
                    reason: BlockReason::InvalidUrl,
                    inspect_anyway: false
                },
                "{raw}"
            );
        }
    }

    #[test]
    fn shared_text_opens_its_link() {
        for (text, expected) in [
            ("https://example.org/a", "https://example.org/a"),
            ("https://example.org/a.", "https://example.org/a."),
            ("https://example.org/[.]", "https://example.org/[.]"),
            (
                "Check this out: https://example.com/a (from a friend)",
                "https://example.com/a",
            ),
            (
                "Example Domain\nhttps://example.org/",
                "https://example.org/",
            ),
            (
                "see https://en.wikipedia.org/wiki/Foo_(bar).",
                "https://en.wikipedia.org/wiki/Foo_(bar)",
            ),
            ("(https://example.org/x)", "https://example.org/x"),
            ("<https://example.org/x>", "https://example.org/x"),
            (
                "first http://a.example/ then https://b.example/",
                "http://a.example/",
            ),
            ("HTTPS://Example.ORG/Path", "https://example.org/Path"),
            // Defanged, as in threat reports.
            ("hxxps://evil[.]example/x", "https://evil.example/x"),
            (
                "IOC: hXXp://198[.]51[.]100[.]7[:]8080/a, seen today",
                "http://198.51.100.7:8080/a",
            ),
            ("evil(.)example/kit", "https://evil.example/kit"),
            // Without a link, the text is the address.
            (" example.org/a ", "https://example.org/a"),
            ("javascript:alert(1)", "javascript:alert(1)"),
        ] {
            assert_eq!(typed_address(text), expected, "{text:?}");
        }
        assert_eq!(typed_address("no link in here"), "no link in here");
        assert_eq!(
            decide(&typed_address("just some words"), None, true),
            Decision::Block {
                reason: BlockReason::InvalidUrl,
                inspect_anyway: false
            }
        );
        // A link found in text is judged like any other.
        assert!(matches!(
            decide(
                &typed_address("pay here: hxxps://paypa1[.]com/login"),
                None,
                true
            ),
            Decision::Confirm { .. }
        ));
    }

    #[test]
    fn indicator_match_wins_over_clean_heuristics() {
        let bad = table(&["plain.example/"]);
        assert!(matches!(
            decide("https://plain.example/", Some(&bad), true),
            Decision::Block { .. }
        ));
    }

    #[test]
    fn warn_level_heuristics_require_confirmation() {
        match decide("https://paypa1.com/login", None, true) {
            Decision::Confirm { reasons, .. } => {
                assert!(reasons.contains(&Reason::Heuristic(Flag::LookalikeOf {
                    protected: "paypal.com".into()
                })));
            }
            other => panic!("expected confirm, got {other:?}"),
        }
    }

    #[test]
    fn info_level_heuristics_are_notes_only() {
        match decide("http://example.org/", None, true) {
            Decision::Proceed { notes } => assert!(notes.contains(&Note::Heuristic(Flag::NoTls))),
            other => panic!("expected proceed, got {other:?}"),
        }
    }

    #[test]
    fn unassessable_urls_are_never_silently_allowed() {
        let long = format!("https://example.org/{}", "a".repeat(MAX_URL_BYTES));
        assert!(matches!(
            decide(&long, None, true),
            Decision::Confirm { reasons, .. } if reasons == vec![Reason::NotChecked(CanonError::TooLong)]
        ));
        assert_eq!(
            decide("https://.../", None, true),
            Decision::Block {
                reason: BlockReason::InvalidUrl,
                inspect_anyway: false
            }
        );
    }

    #[test]
    fn every_reason_has_a_distinct_code_and_a_sentence() {
        let flag = Flag::LookalikeOf {
            protected: "paypal.com".into(),
        };
        let reasons = [
            Reason::Heuristic(flag.clone()).explain(),
            Reason::NotChecked(CanonError::TooLong).explain(),
            Note::IntelStale.explain(),
            Note::IntelMissing.explain(),
            BlockReason::SandboxUnavailable.explain(),
            BlockReason::SchemeNotAllowed("intent".into()).explain(),
            BlockReason::InvalidUrl.explain(),
            BlockReason::KnownMalicious(Vec::new()).explain(),
        ];
        assert!(reasons.iter().all(|r| r.ends_with('.') && r.len() > 20));
        assert!(reasons[0].contains("paypal.com"));
        let codes = [
            BlockReason::SandboxUnavailable.code(),
            BlockReason::SchemeNotAllowed(String::new()).code(),
            BlockReason::InvalidUrl.code(),
            BlockReason::KnownMalicious(Vec::new()).code(),
            Note::IntelStale.code(),
            Note::IntelMissing.code(),
            Reason::NotChecked(CanonError::NoHost).code(),
            flag.code(),
        ];
        let unique: std::collections::BTreeSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len());
    }

    #[test]
    fn web_supplied_text_cannot_reorder_an_explanation() {
        let decision = decide("https://xn--pypal-4ve.com/", None, true);
        let Decision::Confirm { reasons, .. } = decision else {
            panic!("expected confirm, got {decision:?}");
        };
        for reason in reasons {
            let text = reason.explain();
            assert!(
                !text.chars().any(crate::text::is_hidden_or_control),
                "{text}"
            );
        }
        let flag = Flag::MixedScriptLabel {
            label: "p\u{202e}lap".into(),
        };
        assert!(flag.explain().contains("p\\u{202e}lap"));
    }

    #[test]
    fn typed_addresses_default_to_https_without_hiding_schemes() {
        assert_eq!(typed_address(" example.org/a "), "https://example.org/a");
        assert_eq!(
            typed_address("localhost:8080/x"),
            "https://localhost:8080/x"
        );
        assert_eq!(typed_address("http://example.org/"), "http://example.org/");
        assert_eq!(typed_address("javascript:alert(1)"), "javascript:alert(1)");
        assert!(matches!(
            decide(&typed_address("file:///etc/passwd"), None, true),
            Decision::Block { .. }
        ));
    }

    #[test]
    fn rift_ai_warns_or_notes_and_never_blocks() {
        use crate::urlmodel::{Kind, model_for_tests};
        let heuristics = HeuristicConfig::default();
        // High for "verify" in a path, Elevated for a .xyz ending alone.
        let model = model_for_tests(
            &[(Kind::PathWord, "verify", 6.0), (Kind::Tld, "xyz", 1.0)],
            -0.5,
        );
        let decide = |raw: &str, indicators: Option<&UrlTable>| {
            let ctx = NavigationContext {
                sandbox_verified: true,
                indicators,
                intel_state: IntelState::Current,
                heuristics: &heuristics,
                model: Some(&model),
            };
            decide_navigation(raw.as_bytes(), &ctx)
        };
        match decide("https://shop.example.xyz/account/verify", None) {
            Decision::Confirm { reasons, .. } => {
                let [Reason::Ai(finding)] = reasons.as_slice() else {
                    panic!("{reasons:?}")
                };
                assert!(finding.score >= 90, "{finding:?}");
                assert_eq!(
                    finding.signals[0],
                    "the word \u{201c}verify\u{201d} in the path"
                );
                let text = Reason::Ai(finding.clone()).explain();
                assert!(text.contains("not proof"), "{text}");
            }
            other => panic!("expected a warning, got {other:?}"),
        }
        match decide("https://shop.example.xyz/", None) {
            Decision::Proceed { notes } => {
                assert!(notes.iter().any(|n| n.code() == "ai-elevated"), "{notes:?}")
            }
            other => panic!("expected a note, got {other:?}"),
        }
        // Nothing for a low score: it is not shown as a sign of safety.
        assert_eq!(
            decide("https://example.org/", None),
            Decision::Proceed { notes: vec![] }
        );
        // The database decides first: a listed address is blocked whatever the AI says.
        let listed = table(&["shop.example.xyz/"]);
        assert!(matches!(
            decide("https://shop.example.xyz/account/verify", Some(&listed)),
            Decision::Block {
                reason: BlockReason::KnownMalicious(_),
                ..
            }
        ));
    }

    #[test]
    fn missing_or_stale_intel_is_surfaced() {
        let heuristics = HeuristicConfig::default();
        for (state, note) in [
            (IntelState::Missing, Note::IntelMissing),
            (IntelState::Stale, Note::IntelStale),
        ] {
            let ctx = NavigationContext {
                sandbox_verified: true,
                indicators: None,
                intel_state: state,
                heuristics: &heuristics,
                model: None,
            };
            match decide_navigation(b"https://example.org/", &ctx) {
                Decision::Proceed { notes } => assert!(notes.contains(&note)),
                other => panic!("expected proceed, got {other:?}"),
            }
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(4000))]
        #[test]
        fn typed_addresses_are_stable(
            text in proptest::prop_oneof![
                "\\PC{0,200}",
                "[ a-zA-Z:]{0,12}(hxxps?|https?|HTTP)://[a-z0-9.:/@\\\\()\\[\\] ]{0,40}[ .,)]{0,3}",
            ]
        ) {
            let address = typed_address(&text);
            proptest::prop_assert_eq!(typed_address(&address), address);
        }
    }
}
