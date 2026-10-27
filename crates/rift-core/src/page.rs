//! Facts about a loaded page (docs/architecture.md §10.5): whether it asks
//! for a password or a card, and whether it names itself after a protected
//! brand on a site that is not that brand's.
//!
//! The facts come from a script in the page, which the page can see and
//! change: they can add warnings, never clear one. Each flag is a fact
//! ("the title says PayPal"), not a verdict.
//!
//! [`rules`] adds fixed checks over the page model's counts (§16.1) that
//! need no training: what copied sign-in pages are made of. On the 2021
//! dataset's 80,000 pages each fires on 1-15% of phishing pages and about
//! 0.1% of ordinary ones (docs/reports/page-model.md).

use crate::heuristics::Severity;
use crate::pagemodel::PageCounts;
use crate::text::escape_for_display;
use crate::urlcanon::CanonicalUrl;

/// The longest name text read; the rest is ignored.
pub const MAX_NAME_CHARS: usize = 512;

/// What the browser read from a page. `names` is the text the page uses
/// to say what it is: its title, its site name and its first heading.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PageFacts {
    pub names: String,
    pub password: bool,
    pub card: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageFlag {
    /// The page names itself after `protected`'s brand and asks for a
    /// password or a card, on another site.
    ClaimsBrand {
        protected: String,
        asks: &'static str,
    },
    /// A password field on a page that is not encrypted.
    PasswordWithoutTls,
    AsksForPassword,
    AsksForCard,
    /// A password field, and the page's links go nowhere (`#`, empty) or
    /// there are none.
    LinksGoNowhere,
    /// A password field, and a form sends to a `.php` script on another site.
    FormToScriptElsewhere,
    /// A password field, and the right-click menu is blocked.
    BlocksRightClick,
}

impl PageFlag {
    pub fn severity(&self) -> Severity {
        match self {
            Self::ClaimsBrand { .. }
            | Self::PasswordWithoutTls
            | Self::LinksGoNowhere
            | Self::FormToScriptElsewhere
            | Self::BlocksRightClick => Severity::Warn,
            Self::AsksForPassword | Self::AsksForCard => Severity::Info,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::ClaimsBrand { .. } => "page-claims-brand",
            Self::PasswordWithoutTls => "page-password-no-tls",
            Self::AsksForPassword => "page-asks-password",
            Self::AsksForCard => "page-asks-card",
            Self::LinksGoNowhere => "page-dead-links",
            Self::FormToScriptElsewhere => "page-form-elsewhere",
            Self::BlocksRightClick => "page-no-right-click",
        }
    }

    /// The fact in one plain sentence; `host` is the page's site.
    pub fn explain(&self, host: &str) -> String {
        let host = escape_for_display(host);
        match self {
            Self::ClaimsBrand { protected, asks } => {
                let protected = escape_for_display(protected);
                format!(
                    "This page presents itself as {} and asks for your {asks}, but the site is {host}, not {protected}.",
                    escape_for_display(brand_of(&protected))
                )
            }
            Self::PasswordWithoutTls => {
                format!("{host} asks for a password over a connection that is not encrypted.")
            }
            Self::AsksForPassword => format!("{host} asks for a password."),
            Self::AsksForCard => format!("{host} asks for card details."),
            Self::LinksGoNowhere => format!(
                "{host} asks for a password, and its links go nowhere, as on copied sign-in pages."
            ),
            Self::FormToScriptElsewhere => format!(
                "{host} asks for a password, and a form on it sends what is typed to a script on another site."
            ),
            Self::BlocksRightClick => format!(
                "{host} asks for a password and blocks the right-click menu, as copied sign-in pages do to hide how they are made."
            ),
        }
    }
}

/// The flags for a page at `url` with `facts`; `protected` are the
/// registrable domains whose brands are checked.
pub fn assess(url: &CanonicalUrl, facts: &PageFacts, protected: &[String]) -> Vec<PageFlag> {
    let mut flags = Vec::new();
    let asks = match (facts.password, facts.card) {
        (true, true) => Some("password and card details"),
        (true, false) => Some("password"),
        (false, true) => Some("card details"),
        (false, false) => None,
    };
    let host = url.host();
    let names: String = facts
        .names
        .chars()
        .take(MAX_NAME_CHARS)
        .collect::<String>()
        .to_lowercase();
    if let Some(asks) = asks {
        for domain in protected {
            if host == domain || host.ends_with(&format!(".{domain}")) {
                continue;
            }
            if names_word(&names, brand_of(domain)) {
                flags.push(PageFlag::ClaimsBrand {
                    protected: domain.clone(),
                    asks,
                });
            }
        }
    }
    if facts.password && url.scheme() == "http" {
        flags.push(PageFlag::PasswordWithoutTls);
    }
    if facts.password {
        flags.push(PageFlag::AsksForPassword);
    }
    if facts.card {
        flags.push(PageFlag::AsksForCard);
    }
    flags
}

/// The checks over a page's counts that need no training; only on a page
/// with a password field.
pub fn rules(counts: &PageCounts) -> Vec<PageFlag> {
    let mut flags = Vec::new();
    if counts.pw == 0 {
        return flags;
    }
    // At least four links in five go nowhere, of five or more; or no link.
    let nowhere = u64::from(counts.an).saturating_mul(5) >= u64::from(counts.a).saturating_mul(4);
    if counts.a == 0 || (counts.a >= 5 && nowhere) {
        flags.push(PageFlag::LinksGoNowhere);
    }
    if counts.fphp > 0 && counts.fx > 0 {
        flags.push(PageFlag::FormToScriptElsewhere);
    }
    if counts.rc > 0 {
        flags.push(PageFlag::BlocksRightClick);
    }
    flags
}

fn brand_of(domain: &str) -> &str {
    domain.split('.').next().unwrap_or(domain)
}

/// Whether `word` (three letters or more) is a whole word of `text`.
pub(crate) fn names_word(text: &str, word: &str) -> bool {
    if word.chars().count() < 3 {
        return false;
    }
    text.match_indices(word).any(|(at, _)| {
        let before = text.get(..at).and_then(|t| t.chars().last());
        let after = text
            .get(at.saturating_add(word.len())..)
            .and_then(|t| t.chars().next());
        !before.is_some_and(char::is_alphanumeric) && !after.is_some_and(char::is_alphanumeric)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::urlcanon::canonicalize;

    fn flags(raw: &str, names: &str, password: bool, card: bool) -> Vec<PageFlag> {
        let url = canonicalize(raw.as_bytes()).expect("canonicalizes");
        let facts = PageFacts {
            names: names.into(),
            password,
            card,
        };
        assess(&url, &facts, &["paypal.com".into(), "apple.com".into()])
    }

    #[test]
    fn a_sign_in_page_named_after_a_brand_on_another_site_warns() {
        let found = flags(
            "https://secure-login.example/",
            "PayPal: Log in to your account",
            true,
            false,
        );
        assert!(
            found.contains(&PageFlag::ClaimsBrand {
                protected: "paypal.com".into(),
                asks: "password"
            }),
            "{found:?}"
        );
        assert_eq!(found[0].severity(), Severity::Warn);
        let text = found[0].explain("secure-login.example");
        assert!(
            text.contains("presents itself as paypal") && text.contains("not paypal.com"),
            "{text}"
        );
        assert!(
            flags("https://pay.example/", "Apple ID", false, true)
                .iter()
                .any(|f| matches!(
                    f,
                    PageFlag::ClaimsBrand {
                        asks: "card details",
                        ..
                    }
                ))
        );
    }

    #[test]
    fn the_brand_itself_and_pages_that_ask_nothing_are_quiet() {
        assert_eq!(
            flags(
                "https://www.paypal.com/signin",
                "PayPal: Log in",
                true,
                false
            ),
            vec![PageFlag::AsksForPassword]
        );
        // A news page about the brand asks for nothing.
        assert!(flags("https://news.example/", "Apple's new phone", false, false).is_empty());
        // Part of another word is not the brand.
        assert_eq!(
            flags(
                "https://shop.example/",
                "Pineapple shop: sign in",
                true,
                false
            ),
            vec![PageFlag::AsksForPassword]
        );
    }

    #[test]
    fn a_password_over_plain_http_warns() {
        let found = flags("http://intranet.example/", "Sign in", true, false);
        assert!(found.contains(&PageFlag::PasswordWithoutTls));
        assert!(found.iter().any(|f| f.severity() == Severity::Warn));
    }

    fn counts(json: &str) -> PageCounts {
        PageCounts::from_report(json).expect("a report")
    }

    #[test]
    fn copied_sign_in_pages_are_named_by_rule() {
        let codes = |json: &str| {
            rules(&counts(json))
                .iter()
                .map(PageFlag::code)
                .collect::<Vec<_>>()
        };
        assert_eq!(codes(r#"{"pw":1,"a":10,"an":9}"#), ["page-dead-links"]);
        assert_eq!(codes(r#"{"pw":1}"#), ["page-dead-links"], "no link at all");
        assert_eq!(
            codes(r#"{"pw":1,"a":5,"fm":1,"fx":1,"fphp":1,"rc":1}"#),
            ["page-form-elsewhere", "page-no-right-click"]
        );
        // Ordinary sign-in pages: links that go places; a form to the site's own script.
        assert!(codes(r#"{"pw":1,"a":10,"an":7,"fm":1,"fphp":1}"#).is_empty());
        assert!(
            codes(r#"{"pw":1,"a":4,"an":4}"#).is_empty(),
            "too few links to judge"
        );
        // Nothing without a password field.
        assert!(codes(r#"{"a":0,"rc":1,"fx":1,"fphp":1}"#).is_empty());
        let warn = rules(&counts(r#"{"pw":1}"#));
        assert_eq!(warn[0].severity(), Severity::Warn);
        assert!(warn[0].explain("a\u{202e}b.example").starts_with("a"));
    }

    #[test]
    fn long_names_are_cut_and_text_is_escaped() {
        let long = format!("{} paypal", "x ".repeat(MAX_NAME_CHARS));
        assert_eq!(
            flags("https://a.example/", &long, true, false),
            vec![PageFlag::AsksForPassword]
        );
        let text = PageFlag::AsksForPassword.explain("a\u{202e}b.example");
        assert!(!text.contains('\u{202e}'), "{text}");
    }
}
