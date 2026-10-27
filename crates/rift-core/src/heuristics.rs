//! Explainable URL heuristics (docs/architecture.md §12.2).
//!
//! Each flag states a measured fact about the URL ("the host's skeleton
//! equals paypal.com"), never a verdict. Heuristics can make a navigation
//! *Suspicious*; only indicator matches can make it *Known malicious*.
//! Confusable and mixed-script checks use Unicode UTS #39 via
//! `unicode-security` rather than ad-hoc character tables.

use unicode_security::{MixedScript, skeleton};

use crate::text::escape_for_display;
use crate::urlcanon::CanonicalUrl;

/// Pack-provided configuration: thresholds and lists are data, not code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeuristicConfig {
    /// Frequently impersonated registrable domains, e.g. "paypal.com".
    pub protected_domains: Vec<String>,
    /// URL-shortener hosts whose destination is unknown until followed.
    pub shorteners: Vec<String>,
    /// Platforms where anyone can publish a site under the platform's own
    /// name (`someone.web.app`), e.g. "web.app".
    pub hosting: Vec<String>,
    pub max_subdomain_depth: usize,
    pub max_url_bytes: usize,
}

impl Default for HeuristicConfig {
    fn default() -> Self {
        Self {
            protected_domains: Vec::new(),
            shorteners: Vec::new(),
            hosting: Vec::new(),
            max_subdomain_depth: 4,
            max_url_bytes: 2048,
        }
    }
}

/// The brands Check protects (§10.3), written by `tools/rift-train/brands.py`:
/// the hand-picked ones, and those today's phishing addresses fake most.
pub const SHIPPED_BRANDS: &str = include_str!("../../../models/brands.txt");

/// A protected brand's registrable domain. A learned one protects
/// addresses only: its name may be a product people run on their own sites,
/// so a page naming it is not a claim to be it (§10.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Brand {
    pub domain: String,
    pub learned: bool,
}

/// Reads `domain [learned]` lines; `#` starts a comment. A line that is not
/// a plain lowercase domain is skipped.
pub fn parse_brands(text: &str) -> Vec<Brand> {
    text.lines()
        .filter_map(|line| {
            let mut words = line.split('#').next()?.split_whitespace();
            let domain = words.next()?;
            let learned = match words.next() {
                None => false,
                Some("learned") => true,
                Some(_) => return None,
            };
            let plain = domain.len() <= 253
                && domain.contains('.')
                && !domain.starts_with(['.', '-'])
                && domain.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-'
                });
            (plain && words.next().is_none()).then(|| Brand {
                domain: domain.to_owned(),
                learned,
            })
        })
        .collect()
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
    /// The host names a protected domain's brand (`paypal-login.example`)
    /// but is not that domain. `lure` is a word fake pages use ("login",
    /// "verify") found with it, or the name of the free hosting it is on.
    BrandInHost {
        protected: String,
        lure: Option<String>,
    },
    /// The path contains a protected domain (`/paypal.com/signin`), as kits
    /// for fake pages copied onto other sites do.
    ProtectedNameInPath {
        protected: String,
    },
    /// The site is on a platform where anyone can publish a site.
    FreeHosting {
        platform: String,
    },
    /// The site name ends in `.zip` or `.mov`, which read as a file name.
    FileNameTld {
        tld: String,
    },
}

impl Flag {
    /// The protected domain a name-based flag is about.
    fn protected(&self) -> Option<&String> {
        match self {
            Self::LookalikeOf { protected } | Self::ProtectedNameInSubdomain { protected } => {
                Some(protected)
            }
            _ => None,
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::LookalikeOf { .. }
            | Self::ProtectedNameInSubdomain { .. }
            | Self::MixedScriptLabel { .. }
            | Self::CredentialsInUrl
            | Self::ProtectedNameInPath { .. }
            | Self::BrandInHost { lure: Some(_), .. } => Severity::Warn,
            Self::InternationalizedHost { .. }
            | Self::IpLiteralHost
            | Self::NonDefaultPort(_)
            | Self::DeepSubdomain { .. }
            | Self::LongUrl { .. }
            | Self::UrlShortener
            | Self::NoTls
            | Self::BrandInHost { lure: None, .. }
            | Self::FreeHosting { .. }
            | Self::FileNameTld { .. } => Severity::Info,
        }
    }

    /// Stable identifier, for tests and for UI that needs to tell flags apart.
    pub fn code(&self) -> &'static str {
        match self {
            Self::LookalikeOf { .. } => "lookalike",
            Self::ProtectedNameInSubdomain { .. } => "protected-name-in-subdomain",
            Self::MixedScriptLabel { .. } => "mixed-script",
            Self::CredentialsInUrl => "credentials-in-url",
            Self::InternationalizedHost { .. } => "internationalized-host",
            Self::IpLiteralHost => "ip-address",
            Self::NonDefaultPort(_) => "non-default-port",
            Self::DeepSubdomain { .. } => "deep-subdomain",
            Self::LongUrl { .. } => "long-url",
            Self::UrlShortener => "url-shortener",
            Self::NoTls => "no-tls",
            Self::BrandInHost { .. } => "brand-in-host",
            Self::ProtectedNameInPath { .. } => "protected-name-in-path",
            Self::FreeHosting { .. } => "free-hosting",
            Self::FileNameTld { .. } => "file-name-tld",
        }
    }

    /// The fact in one plain sentence for the trusted UI (§10.4). Parts that
    /// come from the address are escaped, so they cannot reorder the wording.
    pub fn explain(&self) -> String {
        match self {
            Self::LookalikeOf { protected } => format!(
                "This address looks like {} but is a different site.",
                escape_for_display(protected)
            ),
            Self::ProtectedNameInSubdomain { protected } => {
                let protected = escape_for_display(protected);
                format!("This address contains {protected}, but the site is not {protected}.")
            }
            Self::MixedScriptLabel { label } => format!(
                "Part of this address (\"{}\") mixes alphabets, a common way to imitate another name.",
                escape_for_display(label)
            ),
            Self::CredentialsInUrl => {
                "This address puts a user name before the site name, which can hide the real site."
                    .to_owned()
            }
            Self::InternationalizedHost { unicode } => format!(
                "The site name uses international characters: {}.",
                escape_for_display(unicode)
            ),
            Self::IpLiteralHost => {
                "This address is a numeric IP address, not a site name.".to_owned()
            }
            Self::NonDefaultPort(port) => format!("This address uses the unusual port {port}."),
            Self::DeepSubdomain { depth } => {
                format!("The site name has {depth} levels of subdomains.")
            }
            Self::LongUrl { bytes } => format!("This address is unusually long ({bytes} bytes)."),
            Self::UrlShortener => {
                "This is a link shortener: the destination is unknown until the link is followed."
                    .to_owned()
            }
            Self::NoTls => "The connection to this site is not encrypted.".to_owned(),
            Self::BrandInHost { protected, lure } => {
                let protected = escape_for_display(protected);
                let brand = escape_for_display(brand_of(&protected));
                match lure {
                    Some(lure) => format!(
                        "This address uses the name {brand} with \u{201c}{}\u{201d}, as fake sign-in pages do, but the site is not {protected}.",
                        escape_for_display(lure)
                    ),
                    None => format!(
                        "This address uses the name {brand}, but the site is not {protected}."
                    ),
                }
            }
            Self::ProtectedNameInPath { protected } => {
                let protected = escape_for_display(protected);
                format!(
                    "The address has {protected} after the site name, a trick of fake pages: the site is not {protected}."
                )
            }
            Self::FreeHosting { platform } => format!(
                "This site is on {}, where anyone can publish a site in minutes.",
                escape_for_display(platform)
            ),
            Self::FileNameTld { tld } => format!(
                "The site name ends in .{}, which can be mistaken for a file name.",
                escape_for_display(tld)
            ),
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
    let platform = config
        .hosting
        .iter()
        .find(|p| host.len() > p.len() && host.ends_with(&format!(".{p}")));
    if let Some(platform) = platform {
        flags.push(Flag::FreeHosting {
            platform: platform.clone(),
        });
    }
    if let Some(tld) = host.rsplit('.').next()
        && matches!(tld, "zip" | "mov")
    {
        flags.push(Flag::FileNameTld {
            tld: tld.to_owned(),
        });
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
    let named = protected_name_flags(host, &unicode, &config.protected_domains);
    let lure = lure_in(host, url.path()).or_else(|| platform.cloned());
    for domain in &config.protected_domains {
        if host == domain
            || host.ends_with(&format!(".{domain}"))
            || named.iter().any(|f| f.protected() == Some(domain))
        {
            continue;
        }
        if let Some(joined) = brand_in(host, brand_of(domain)) {
            flags.push(Flag::BrandInHost {
                protected: domain.clone(),
                lure: joined.map(str::to_owned).or_else(|| lure.clone()),
            });
        } else if names_in_path(url.path(), domain) {
            flags.push(Flag::ProtectedNameInPath {
                protected: domain.clone(),
            });
        }
    }
    flags.extend(named);
    flags
}

/// Words fake sign-in, payment and delivery pages put in their addresses.
const LURES: &[&str] = &[
    "login",
    "logon",
    "signin",
    "verify",
    "verification",
    "account",
    "accounts",
    "secure",
    "security",
    "update",
    "wallet",
    "support",
    "billing",
    "payment",
    "password",
    "recover",
    "recovery",
    "unlock",
    "confirm",
    "auth",
    "webscr",
    "banking",
    "invoice",
    "refund",
    "delivery",
    "parcel",
    "tracking",
    "suspended",
    "locked",
    "alert",
    "claim",
    "reward",
    "airdrop",
    "kyc",
    "validate",
    "restore",
    "helpdesk",
    "service",
    "customer",
    "id",
];

/// The registrable name's first label: "paypal" for paypal.com.
fn brand_of(domain: &str) -> &str {
    domain.split('.').next().unwrap_or(domain)
}

/// Whether a label of `host` other than its last names `brand` as a word
/// (`paypal-login`, `login.paypal.example`): `Some(None)`; or joined to a
/// lure (`paypalsecure`): `Some(Some(lure))`.
fn brand_in(host: &str, brand: &str) -> Option<Option<&'static str>> {
    if brand.len() < 3 {
        return None;
    }
    let labels: Vec<&str> = host.split('.').collect();
    let named = labels
        .get(..labels.len().saturating_sub(1))
        .unwrap_or_default();
    for label in named {
        if format!("-{label}-").contains(&format!("-{brand}-")) {
            return Some(None);
        }
        if brand.len() < 4 || brand.contains('-') {
            continue;
        }
        let joined = label.split('-').find_map(|part| {
            let rest = part
                .strip_prefix(brand)
                .or_else(|| part.strip_suffix(brand))?;
            LURES.iter().find(|lure| **lure == rest).copied()
        });
        if joined.is_some() {
            return Some(joined);
        }
    }
    None
}

/// Whether `path` has `domain` as a whole name in it (`/paypal.com/`, `/www.paypal.com`).
fn names_in_path(path: &str, domain: &str) -> bool {
    let path = path.to_ascii_lowercase();
    path.match_indices(domain).any(|(at, _)| {
        let before = path.get(..at).and_then(|p| p.chars().last());
        let after = path
            .get(at.saturating_add(domain.len())..)
            .and_then(|p| p.chars().next());
        matches!(before, Some('/' | '.')) && matches!(after, None | Some('/'))
    })
}

/// The first lure word in the host's labels or the path's words.
fn lure_in(host: &str, path: &str) -> Option<String> {
    let path = path.to_ascii_lowercase();
    host.split(['.', '-'])
        .chain(path.split(|c: char| !c.is_ascii_alphanumeric()))
        .find(|word| LURES.contains(word))
        .map(str::to_owned)
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
        if typo_in(host, brand_of(domain)) {
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

/// Letters a glance takes for one another in an address bar, beyond the
/// UTS #39 skeleton (which keeps `i` and `l` apart).
const LOOK_ALIKE: &[(&str, &str)] = &[
    ("i", "l"),
    ("i", "1"),
    ("l", "1"),
    ("o", "0"),
    ("g", "q"),
    ("u", "v"),
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
];

/// Whether a word of `host` other than its last label is `brand` with one
/// slip a reader misses (`robiox`, `bancolombbia`, `gogle`, `amazno`): a
/// look-alike letter, a repeated letter added or dropped, or two
/// neighbours swapped. An ordinary one-letter difference is not one
/// (`finance` is a word, not a slip of `binance`). Brands shorter than five
/// letters are left out: too many real words are one slip from them.
fn typo_in(host: &str, brand: &str) -> bool {
    if brand.len() < 5 || !brand.is_ascii() {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    labels
        .get(..labels.len().saturating_sub(1))
        .unwrap_or_default()
        .iter()
        .flat_map(|label| label.split('-'))
        .any(|word| word != brand && is_slip(word, brand))
}

fn is_slip(word: &str, brand: &str) -> bool {
    let (w, b) = (word.as_bytes(), brand.as_bytes());
    // A look-alike letter or pair in place of the brand's.
    for (x, y) in LOOK_ALIKE.iter().flat_map(|(x, y)| [(*x, *y), (*y, *x)]) {
        for (at, _) in brand.match_indices(x) {
            let (head, tail) = (brand.get(..at), brand.get(at.saturating_add(x.len())..));
            if let (Some(head), Some(tail)) = (head, tail)
                && word.len()
                    == head
                        .len()
                        .saturating_add(y.len())
                        .saturating_add(tail.len())
                && word.starts_with(head)
                && word.ends_with(tail)
                && word.get(head.len()..head.len().saturating_add(y.len())) == Some(y)
            {
                return true;
            }
        }
    }
    // A repeated letter added or dropped.
    let doubled = |long: &[u8], short: &[u8]| {
        long.len() == short.len().saturating_add(1)
            && (1..long.len()).any(|i| {
                long.get(i) == long.get(i.wrapping_sub(1))
                    && long.get(..i) == short.get(..i)
                    && long.get(i.saturating_add(1)..) == short.get(i..)
            })
    };
    if doubled(w, b) || doubled(b, w) {
        return true;
    }
    // Two neighbours swapped.
    w.len() == b.len()
        && (1..w.len()).any(|i| {
            w.get(i) != w.get(i.wrapping_sub(1))
                && w.get(i) == b.get(i.wrapping_sub(1))
                && w.get(i.wrapping_sub(1)) == b.get(i)
                && w.get(..i.wrapping_sub(1)) == b.get(..i.wrapping_sub(1))
                && w.get(i.saturating_add(1)..) == b.get(i.saturating_add(1)..)
        })
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
            hosting: vec!["web.app".into(), "github.io".into()],
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
    fn the_shipped_brands_parse_and_keep_the_hand_picked_ones() {
        let brands = parse_brands(SHIPPED_BRANDS);
        assert!(
            brands
                .iter()
                .any(|b| b.domain == "paypal.com" && !b.learned)
        );
        assert!(brands.len() <= 300, "{}", brands.len());
        // Every line that names something is read: a typo would drop a brand silently.
        let lines = SHIPPED_BRANDS
            .lines()
            .filter(|l| !l.split('#').next().unwrap_or_default().trim().is_empty())
            .count();
        assert_eq!(brands.len(), lines);
        assert_eq!(
            parse_brands("a.example learned # x\nB.example\nc.example other\nd.example"),
            vec![
                Brand {
                    domain: "a.example".into(),
                    learned: true
                },
                Brand {
                    domain: "d.example".into(),
                    learned: false
                },
            ]
        );
    }

    #[test]
    fn slips_a_reader_misses_are_lookalikes() {
        let cfg = HeuristicConfig {
            protected_domains: vec![
                "roblox.com".into(),
                "bancolombia.com".into(),
                "google.com".into(),
                "amazon.com".into(),
                "binance.com".into(),
                "microsoft.com".into(),
            ],
            ..HeuristicConfig::default()
        };
        let lookalike = |raw: &str| {
            let url = canonicalize(raw.as_bytes()).expect("canonicalizes");
            assess(raw.as_bytes(), &url, &cfg)
                .iter()
                .any(|f| matches!(f, Flag::LookalikeOf { .. }))
        };
        // Seen in OpenPhish's feed, 27 October 2026.
        assert!(lookalike("https://www.robiox.com.tw/games/1"));
        assert!(lookalike("https://bancolombbia.example/personas"));
        assert!(lookalike("https://gogle.example/"));
        assert!(lookalike("https://gooogle.example/"));
        assert!(lookalike("https://amazno.example/"));
        assert!(lookalike("https://login-rnicrosoft.example/"));
        assert!(lookalike("https://secure.goog1e.example/"));
        // Ordinary words one letter away, the brands themselves, and their sites.
        for quiet in [
            "https://finance-today.example/",
            "https://www.roblox.com/",
            "https://create.roblox.com/",
            "https://googly.example/",
            "https://amazing.example/",
            "https://robloxx.com.roblox.com/",
            "https://example.gogle/",
        ] {
            assert!(!lookalike(quiet), "{quiet}");
        }
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
    fn a_brand_with_a_lure_warns_and_alone_only_notes() {
        let warn = |raw: &str| {
            flags(raw)
                .iter()
                .any(|f| f.code() == "brand-in-host" && f.severity() == Severity::Warn)
        };
        assert!(
            warn("https://paypal-login-verify.example/"),
            "{:?}",
            flags("https://paypal-login-verify.example/")
        );
        assert!(warn("https://secure.paypal.account-help.example/"));
        assert!(warn("https://paypalsecure.example/"));
        assert!(warn("https://paypal.example/signin"));
        assert!(warn("https://example-bank-support.example/"));
        // On free hosting, the platform is the lure.
        assert!(warn("https://paypal.web.app/"));
        let note = flags("https://paypal-fan-club.example/");
        assert!(
            note.iter()
                .any(|f| f.code() == "brand-in-host" && f.severity() == Severity::Info),
            "{note:?}"
        );
        // Not a word of the host: no flag.
        assert!(
            flags("https://paypalooza.example/login")
                .iter()
                .all(|f| f.code() != "brand-in-host")
        );
        assert!(flags("https://www.paypal.com/signin").is_empty());
        // Already flagged as a lookalike or a subdomain trick: once only.
        let once = flags("https://paypal.com.login.example/");
        assert_eq!(
            once.iter()
                .filter(|f| f.severity() == Severity::Warn)
                .count(),
            1,
            "{once:?}"
        );
    }

    #[test]
    fn a_protected_name_in_the_path_warns() {
        let wanted = Flag::ProtectedNameInPath {
            protected: "paypal.com".into(),
        };
        assert!(has(
            "https://blog.example/wp-content/paypal.com/signin.php",
            &wanted
        ));
        assert!(has("https://blog.example/x/www.paypal.com", &wanted));
        // A word that only contains it, or a query, is not a path name.
        assert!(!has("https://blog.example/notpaypal.com/", &wanted));
        assert!(!has(
            "https://shop.example/?return=https://paypal.com/",
            &wanted
        ));
    }

    #[test]
    fn free_hosting_and_file_name_endings_are_noted() {
        let found = flags("https://my-portfolio.github.io/");
        assert!(
            found.contains(&Flag::FreeHosting {
                platform: "github.io".into()
            }),
            "{found:?}"
        );
        assert!(found.iter().all(|f| f.severity() == Severity::Info));
        assert!(flags("https://github.io/").is_empty());
        assert!(has(
            "https://invoice.zip/",
            &Flag::FileNameTld { tld: "zip".into() }
        ));
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
