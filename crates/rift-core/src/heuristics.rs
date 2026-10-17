//! Explainable URL heuristics (docs/architecture.md §12.2).
//!
//! Each flag states a measured fact about the URL ("the host's skeleton
//! equals paypal.com"), never a verdict. Heuristics can make a navigation
//! *Suspicious*; only indicator matches can make it *Known malicious*.
//! Confusable and mixed-script checks use Unicode UTS #39 via
//! `unicode-security` rather than ad-hoc character tables.

use unicode_security::{MixedScript, skeleton};

use crate::urlcanon::CanonicalUrl;

/// Pack-provided configuration: thresholds and lists are data, not code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeuristicConfig {
    /// Frequently impersonated registrable domains, e.g. "paypal.com".
    pub protected_domains: Vec<String>,
    /// URL-shortener hosts whose destination is unknown until followed.
    pub shorteners: Vec<String>,
    pub max_subdomain_depth: usize,
    pub max_url_bytes: usize,
}

impl Default for HeuristicConfig {
    fn default() -> Self {
        Self {
            protected_domains: Vec::new(),
            shorteners: Vec::new(),
            max_subdomain_depth: 4,
            max_url_bytes: 2048,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Shown in the protection details; does not interrupt navigation.
    Info,
    /// Warrants a trusted interstitial before loading.
    Warn,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Flag {
    /// Host is a lookalike (same UTS #39 skeleton) of a protected domain.
    LookalikeOf {
        protected: String,
    },
    /// A protected domain appears inside the host but is not its suffix,
    /// e.g. `paypal.com.account-check.example`.
    ProtectedNameInSubdomain {
        protected: String,
    },
    /// A host label mixes scripts (e.g. Latin with Cyrillic).
    MixedScriptLabel {
        label: String,
    },
    /// `user@host` form, which can make the real host hard to see.
    CredentialsInUrl,
    /// Internationalized host; `unicode` is its displayed form.
    InternationalizedHost {
        unicode: String,
    },
    IpLiteralHost,
    NonDefaultPort(u16),
    DeepSubdomain {
        depth: usize,
    },
    LongUrl {
        bytes: usize,
    },
    /// Shortener: the destination is unknown until the link is followed.
    UrlShortener,
    NoTls,
}

impl Flag {
    pub fn severity(&self) -> Severity {
        match self {
            Self::LookalikeOf { .. }
            | Self::ProtectedNameInSubdomain { .. }
            | Self::MixedScriptLabel { .. }
            | Self::CredentialsInUrl => Severity::Warn,
            Self::InternationalizedHost { .. }
            | Self::IpLiteralHost
            | Self::NonDefaultPort(_)
            | Self::DeepSubdomain { .. }
            | Self::LongUrl { .. }
            | Self::UrlShortener
            | Self::NoTls => Severity::Info,
        }
    }
}

/// Evaluates every heuristic. `raw` is the URL as received (credentials and
/// port are visible there but stripped from the canonical form).
pub fn assess(raw: &[u8], url: &CanonicalUrl, config: &HeuristicConfig) -> Vec<Flag> {
    let mut flags = Vec::new();
    let host = url.host();
    let authority = raw_authority(raw);

    if authority.contains(&b'@') {
        flags.push(Flag::CredentialsInUrl);
    }
    if let Some(port) = explicit_port(authority)
        && !matches!((url.scheme(), port), ("https", 443) | ("http", 80))
    {
        flags.push(Flag::NonDefaultPort(port));
    }
    if url.scheme() == "http" {
        flags.push(Flag::NoTls);
    }
    if raw.len() > config.max_url_bytes {
        flags.push(Flag::LongUrl { bytes: raw.len() });
    }
    if url.host_is_ip() {
        flags.push(Flag::IpLiteralHost);
        return flags; // name-based checks do not apply to addresses
    }

    let depth = host.split('.').count().saturating_sub(2);
    if depth > config.max_subdomain_depth {
        flags.push(Flag::DeepSubdomain { depth });
    }
    if config.shorteners.iter().any(|s| s == host) {
        flags.push(Flag::UrlShortener);
    }

    let (unicode, idna_result) = idna::domain_to_unicode(host);
    if idna_result.is_ok() && unicode != host {
        flags.push(Flag::InternationalizedHost {
            unicode: unicode.clone(),
        });
    }
    for label in unicode.split('.') {
        if !label.is_ascii() && !label.is_single_script() {
            flags.push(Flag::MixedScriptLabel {
                label: label.to_owned(),
            });
        }
    }
    flags.extend(protected_name_flags(
        host,
        &unicode,
        &config.protected_domains,
    ));
    flags
}

fn protected_name_flags(host: &str, unicode: &str, protected: &[String]) -> Vec<Flag> {
    let mut flags = Vec::new();
    let labels: Vec<&str> = unicode.split('.').collect();
    for domain in protected {
        if host == domain || host.ends_with(&format!(".{domain}")) {
            continue; // the genuine domain or one of its subdomains
        }
        let width = domain.split('.').count();
        let tail = labels
            .get(labels.len().saturating_sub(width)..)
            .map(|t| t.join("."));
        if let Some(tail) = tail
            && skeleton_of(&tail) == skeleton_of(domain)
        {
            flags.push(Flag::LookalikeOf {
                protected: domain.clone(),
            });
            continue;
        }
        if format!(".{host}.").contains(&format!(".{domain}.")) {
            flags.push(Flag::ProtectedNameInSubdomain {
                protected: domain.clone(),
            });
        }
    }
    flags
}

fn skeleton_of(text: &str) -> String {
    skeleton(&text.to_lowercase())
        .collect::<String>()
        .to_lowercase()
}

/// The raw authority (between "://" and the first '/', '?' or '#'), used only
/// for facts the canonical form deliberately drops.
fn raw_authority(raw: &[u8]) -> &[u8] {
    let start = raw
        .windows(3)
        .position(|w| w == b"://")
        .map_or(0, |at| at.saturating_add(3));
    let rest = raw.get(start..).unwrap_or_default();
    let end = rest
        .iter()
        .position(|&b| matches!(b, b'/' | b'?' | b'#'))
        .unwrap_or(rest.len());
    rest.get(..end).unwrap_or_default()
}

fn explicit_port(authority: &[u8]) -> Option<u16> {
    let host_port = match authority.iter().rposition(|&b| b == b'@') {
        Some(at) => authority.get(at.saturating_add(1)..)?,
        None => authority,
    };
    if host_port.first() == Some(&b'[') {
        let close = host_port.iter().position(|&b| b == b']')?;
        let after = host_port.get(close.saturating_add(1)..)?;
        return std::str::from_utf8(after.strip_prefix(b":")?)
            .ok()?
            .parse()
            .ok();
    }
    let colon = host_port.iter().rposition(|&b| b == b':')?;
    std::str::from_utf8(host_port.get(colon.saturating_add(1)..)?)
        .ok()?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::urlcanon::canonicalize;

    fn config() -> HeuristicConfig {
        HeuristicConfig {
            protected_domains: vec!["paypal.com".into(), "example-bank.co.uk".into()],
            shorteners: vec!["bit.ly".into()],
            ..HeuristicConfig::default()
        }
    }

    fn flags(raw: &str) -> Vec<Flag> {
        let url = canonicalize(raw.as_bytes()).expect("canonicalizes");
        assess(raw.as_bytes(), &url, &config())
    }

    fn has(raw: &str, wanted: &Flag) -> bool {
        flags(raw).contains(wanted)
    }

    #[test]
    fn genuine_domain_and_its_subdomains_are_quiet() {
        assert!(flags("https://paypal.com/").is_empty());
        assert!(flags("https://www.paypal.com/signin").is_empty());
        assert!(flags("https://login.example-bank.co.uk/").is_empty());
    }

    #[test]
    fn cyrillic_lookalike_is_flagged() {
        // "раураl.com" with Cyrillic р, а, у.
        let lookalike = "https://\u{440}\u{430}\u{443}\u{440}\u{430}l.com/";
        let found = flags(lookalike);
        assert!(
            found.contains(&Flag::LookalikeOf {
                protected: "paypal.com".into()
            }),
            "{found:?}"
        );
        assert!(
            found
                .iter()
                .any(|f| matches!(f, Flag::InternationalizedHost { .. }))
        );
    }

    #[test]
    fn mixed_script_label_is_flagged() {
        // Latin "pay" + Cyrillic "раl".
        let found = flags("https://pay\u{440}\u{430}l.com/");
        assert!(
            found
                .iter()
                .any(|f| matches!(f, Flag::MixedScriptLabel { .. })),
            "{found:?}"
        );
        assert!(found.iter().any(|f| f.severity() == Severity::Warn));
    }

    #[test]
    fn ascii_confusable_is_flagged() {
        assert!(has(
            "https://paypa1.com/",
            &Flag::LookalikeOf {
                protected: "paypal.com".into()
            }
        ));
    }

    #[test]
    fn protected_name_in_subdomain_is_flagged() {
        let wanted = Flag::ProtectedNameInSubdomain {
            protected: "paypal.com".into(),
        };
        assert!(has("https://paypal.com.account-review.example/", &wanted));
        assert!(!has("https://notpaypal.com/", &wanted));
    }

    #[test]
    fn structural_facts() {
        assert!(has("https://user@evil.example/", &Flag::CredentialsInUrl));
        assert!(has(
            "https://evil.example:8443/",
            &Flag::NonDefaultPort(8443)
        ));
        assert!(!has(
            "https://evil.example:443/",
            &Flag::NonDefaultPort(443)
        ));
        assert!(has("http://evil.example/", &Flag::NoTls));
        assert!(has("http://192.168.1.1/admin", &Flag::IpLiteralHost));
        assert!(has("https://bit.ly/abc", &Flag::UrlShortener));
        assert!(has(
            "https://a.b.c.d.e.f.example/",
            &Flag::DeepSubdomain { depth: 5 }
        ));
        let long = format!("https://example.org/{}", "a".repeat(3000));
        assert!(
            flags(&long)
                .iter()
                .any(|f| matches!(f, Flag::LongUrl { .. }))
        );
    }

    #[test]
    fn info_flags_do_not_warn() {
        let found = flags("http://bit.ly:8080/x");
        assert!(!found.is_empty());
        assert!(
            found.iter().all(|f| f.severity() == Severity::Info),
            "{found:?}"
        );
    }
}
