//! URL canonicalization and lookup expressions compatible with Google Safe
//! Browsing ("URLs and Hashing", v4). Using an established, published
//! algorithm means intelligence from different sources matches the same way,
//! and the published examples serve as regression tests.
//!
//! Input is untrusted: it is bounded, processed as bytes (percent-decoding can
//! yield non-UTF-8), and never indexed in a way that can panic.

use std::fmt;

use sha2::{Digest, Sha256};

/// Longest accepted input. Browsers accept longer URLs; Rift refuses to
/// assess them rather than truncating (the caller reports "not checked").
pub const MAX_URL_BYTES: usize = 8 * 1024;

/// Maximum host suffixes and path prefixes, per the Safe Browsing scheme.
const MAX_HOST_SUFFIX_COMPONENTS: usize = 5;
const MAX_PATH_PREFIXES: usize = 4;

/// Truncated SHA-256 of a lookup expression, as stored in URL indicator tables.
pub type ExpressionHash = [u8; 16];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CanonError {
    #[error("URL exceeds {MAX_URL_BYTES} bytes")]
    TooLong,
    #[error("URL has no host")]
    NoHost,
}

/// A canonical URL. All components are ASCII; unsafe bytes are percent-escaped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalUrl {
    scheme: String,
    host: String,
    host_is_ip: bool,
    path: String,
    query: Option<String>,
}

impl CanonicalUrl {
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn host_is_ip(&self) -> bool {
        self.host_is_ip
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }

    /// Host-suffix × path-prefix expressions (at most 5 × 6 = 30), without
    /// scheme, port, or credentials. An indicator matches if any expression does.
    pub fn expressions(&self) -> Vec<String> {
        let mut out = Vec::new();
        for host in self.host_suffixes() {
            for path in self.path_prefixes() {
                push_unique(&mut out, format!("{host}{path}"));
            }
        }
        out
    }

    /// Hashes of [`Self::expressions`], in the same order.
    pub fn expression_hashes(&self) -> Vec<ExpressionHash> {
        self.expressions()
            .iter()
            .map(|e| expression_hash(e))
            .collect()
    }

    fn host_suffixes(&self) -> Vec<String> {
        let mut hosts = vec![self.host.clone()];
        if self.host_is_ip {
            return hosts;
        }
        let components: Vec<&str> = self.host.split('.').collect();
        let count = components.len();
        // Successively drop leading components from (at most) the last five,
        // never down to the bare top-level domain.
        let first = count.saturating_sub(MAX_HOST_SUFFIX_COMPONENTS).max(1);
        for start in first..count.saturating_sub(1) {
            if let Some(suffix) = components.get(start..) {
                push_unique(&mut hosts, suffix.join("."));
            }
        }
        hosts
    }

    fn path_prefixes(&self) -> Vec<String> {
        let mut paths = Vec::new();
        if let Some(query) = &self.query {
            paths.push(format!("{}?{query}", self.path));
        }
        push_unique(&mut paths, self.path.clone());
        // Directory prefixes from the root: "/", "/a/", "/a/b/", "/a/b/c/".
        let directories: Vec<&str> = match self.path.rsplit_once('/') {
            Some((dirs, _file)) => dirs.split('/').filter(|c| !c.is_empty()).collect(),
            None => Vec::new(),
        };
        let mut prefix = String::from("/");
        push_unique(&mut paths, prefix.clone());
        for component in directories.iter().take(MAX_PATH_PREFIXES.saturating_sub(1)) {
            prefix.push_str(component);
            prefix.push('/');
            push_unique(&mut paths, prefix.clone());
        }
        paths
    }
}

impl fmt::Display for CanonicalUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}{}", self.scheme, self.host, self.path)?;
        if let Some(query) = &self.query {
            write!(f, "?{query}")?;
        }
        Ok(())
    }
}

pub fn expression_hash(expression: &str) -> ExpressionHash {
    let digest = Sha256::digest(expression.as_bytes());
    let mut out = [0u8; 16];
    for (dst, src) in out.iter_mut().zip(digest.iter()) {
        *dst = *src;
    }
    out
}

/// Canonicalizes `input` following the Safe Browsing procedure.
pub fn canonicalize(input: &[u8]) -> Result<CanonicalUrl, CanonError> {
    if input.len() > MAX_URL_BYTES {
        return Err(CanonError::TooLong);
    }
    let mut bytes: Vec<u8> = input
        .trim_ascii()
        .iter()
        .copied()
        .filter(|b| !matches!(b, b'\t' | b'\r' | b'\n'))
        .collect();
    if let Some(fragment) = bytes.iter().position(|&b| b == b'#') {
        bytes.truncate(fragment);
    }
    let bytes = unescape_fully(bytes);

    let (scheme, rest) = split_scheme(&bytes);
    let authority_end = rest
        .iter()
        .position(|&b| b == b'/' || b == b'?')
        .unwrap_or(rest.len());
    let (authority, path_and_query) = rest.split_at(authority_end);
    let (host, host_is_ip) = canonical_host(host_from_authority(authority))?;
    let (path, query) = match path_and_query.iter().position(|&b| b == b'?') {
        Some(at) => {
            let (path, query) = path_and_query.split_at(at);
            (path, query.get(1..).map(escape))
        }
        None => (path_and_query, None),
    };
    Ok(CanonicalUrl {
        scheme,
        host,
        host_is_ip,
        path: canonical_path(path),
        query,
    })
}

fn push_unique(list: &mut Vec<String>, item: String) {
    if !list.contains(&item) {
        list.push(item);
    }
}

fn hex_value(b: u8) -> Option<u8> {
    char::from(b)
        .to_digit(16)
        .and_then(|d| u8::try_from(d).ok())
}

/// Decodes one layer of `%XX` escapes; `None` when nothing changed.
fn unescape_once(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let mut changed = false;
    let mut rest = input;
    while let Some((&b, tail)) = rest.split_first() {
        if b == b'%'
            && let [hi, lo, after @ ..] = tail
            && let (Some(hi), Some(lo)) = (hex_value(*hi), hex_value(*lo))
        {
            out.push(hi.wrapping_shl(4) | lo);
            rest = after;
            changed = true;
            continue;
        }
        out.push(b);
        rest = tail;
    }
    changed.then_some(out)
}

/// Unescapes until stable. Terminates: every changing pass shortens the input.
fn unescape_fully(mut bytes: Vec<u8>) -> Vec<u8> {
    while let Some(next) = unescape_once(&bytes) {
        bytes = next;
    }
    bytes
}

fn split_scheme(bytes: &[u8]) -> (String, &[u8]) {
    let separator = bytes.windows(3).position(|w| w == b"://");
    if let Some(at) = separator
        && let (Some(scheme), Some(rest)) = (bytes.get(..at), bytes.get(at.saturating_add(3)..))
        && is_scheme(scheme)
    {
        return (String::from_utf8_lossy(scheme).to_ascii_lowercase(), rest);
    }
    ("http".to_owned(), bytes)
}

fn is_scheme(candidate: &[u8]) -> bool {
    match candidate.split_first() {
        Some((first, rest)) => {
            first.is_ascii_alphabetic()
                && rest
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
        }
        None => false,
    }
}

/// Drops credentials and port; keeps bracketed IPv6 literals intact.
fn host_from_authority(authority: &[u8]) -> &[u8] {
    let host_port = match authority.iter().rposition(|&b| b == b'@') {
        Some(at) => authority.get(at.saturating_add(1)..).unwrap_or_default(),
        None => authority,
    };
    // Trailing dots are dropped from the host later anyway; removing them
    // first keeps port detection identical on re-canonicalization ("0:." must
    // not become host "0:" and then, on a second pass, port-stripped "0").
    let host_port = match host_port.iter().rposition(|&b| b != b'.') {
        Some(last) => host_port.get(..=last).unwrap_or(host_port),
        None => host_port,
    };
    if host_port.first() == Some(&b'[') {
        return match host_port.iter().position(|&b| b == b']') {
            Some(end) => host_port.get(..=end).unwrap_or(host_port),
            None => host_port,
        };
    }
    match host_port.iter().rposition(|&b| b == b':') {
        Some(colon)
            if host_port
                .get(colon.saturating_add(1)..)
                .is_some_and(|p| p.iter().all(u8::is_ascii_digit)) =>
        {
            host_port.get(..colon).unwrap_or(host_port)
        }
        _ => host_port,
    }
}

fn canonical_host(raw: &[u8]) -> Result<(String, bool), CanonError> {
    if raw.first() == Some(&b'[') {
        let lowered = raw.to_ascii_lowercase();
        return Ok((escape(&lowered), true));
    }
    // Internationalized names become Punycode; undecodable bytes stay escaped.
    let ascii: Vec<u8> = match std::str::from_utf8(raw) {
        Ok(text) if !text.is_ascii() => match idna::domain_to_ascii(text) {
            Ok(converted) => converted.into_bytes(),
            Err(_) => raw.to_vec(),
        },
        _ => raw.to_vec(),
    };
    let mut host = Vec::with_capacity(ascii.len());
    for label in ascii.split(|&b| b == b'.').filter(|l| !l.is_empty()) {
        if !host.is_empty() {
            host.push(b'.');
        }
        host.extend(label.iter().map(u8::to_ascii_lowercase));
    }
    if host.is_empty() {
        return Err(CanonError::NoHost);
    }
    if let Some(octets) = parse_ipv4(&host) {
        let [a, b, c, d] = octets;
        return Ok((format!("{a}.{b}.{c}.{d}"), true));
    }
    Ok((escape(&host), false))
}

/// Parses IPv4 the way `inet_aton` (and browsers) do: 1–4 parts, each
/// decimal, octal (leading 0) or hex (0x); the last part fills the remainder.
fn parse_ipv4(host: &[u8]) -> Option<[u8; 4]> {
    let parts: Vec<&[u8]> = host.split(|&b| b == b'.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let values: Vec<u64> = parts
        .iter()
        .map(|p| parse_ip_part(p))
        .collect::<Option<_>>()?;
    let (last, leading) = values.split_last()?;
    if leading.iter().any(|&v| v > 255) {
        return None;
    }
    let remaining_bits =
        8u32.checked_mul(u32::try_from(4usize.checked_sub(leading.len())?).ok()?)?;
    if *last >= 1u64.checked_shl(remaining_bits)? {
        return None;
    }
    let mut address: u64 = 0;
    for &v in leading {
        address = address.checked_shl(8)? | v;
    }
    address = address.checked_shl(remaining_bits)? | last;
    let address = u32::try_from(address).ok()?;
    Some(address.to_be_bytes())
}

fn parse_ip_part(part: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(part).ok()?;
    let (digits, radix) =
        if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            (hex, 16)
        } else if text.len() > 1 && text.starts_with('0') {
            (text.get(1..)?, 8)
        } else {
            (text, 10)
        };
    if digits.is_empty() {
        // "0x" alone is zero in inet_aton; an empty part is not an address.
        return (radix == 16).then_some(0);
    }
    if digits.len() > 12 {
        return None; // far beyond 32 bits in any radix; avoids overflow
    }
    u64::from_str_radix(digits, radix).ok()
}

fn canonical_path(raw: &[u8]) -> String {
    let segments: Vec<&[u8]> = raw.split(|&b| b == b'/').collect();
    let trailing_slash =
        raw.last() == Some(&b'/') || matches!(segments.last(), Some(&b".") | Some(&b".."));
    let mut kept: Vec<&[u8]> = Vec::new();
    for segment in segments {
        match segment {
            b"" | b"." => {}
            b".." => {
                kept.pop();
            }
            other => kept.push(other),
        }
    }
    let mut path = vec![b'/'];
    path.extend(kept.join(&b'/'));
    if trailing_slash && !kept.is_empty() {
        path.push(b'/');
    }
    escape(&path)
}

/// Percent-escapes bytes ≤ 0x20, ≥ 0x7F, '#', and '%' with uppercase hex.
fn escape(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        if b <= 0x20 || b >= 0x7f || b == b'#' || b == b'%' {
            out.push_str(&format!("%{b:02X}"));
        } else {
            out.push(char::from(b));
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)] // tests may panic
mod tests {
    use super::*;

    /// All examples published in "Safe Browsing: URLs and Hashing" (v4).
    const SAFE_BROWSING_VECTORS: &[(&[u8], &str)] = &[
        (b"http://host/%25%32%35", "http://host/%25"),
        (b"http://host/%25%32%35%25%32%35", "http://host/%25%25"),
        (b"http://host/%2525252525252525", "http://host/%25"),
        (b"http://host/asdf%25%32%35asd", "http://host/asdf%25asd"),
        (b"http://host/%%%25%32%35asd%%", "http://host/%25%25%25asd%25%25"),
        (b"http://www.google.com/", "http://www.google.com/"),
        (
            b"http://%31%36%38%2e%31%38%38%2e%39%39%2e%32%36/%2E%73%65%63%75%72%65/%77%77%77%2E%65%62%61%79%2E%63%6F%6D/",
            "http://168.188.99.26/.secure/www.ebay.com/",
        ),
        (
            b"http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/",
            "http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/",
        ),
        (
            b"http://host%23.com/%257Ea%2521b%2540c%2523d%2524e%25f%255E00%252611%252A22%252833%252944_55%252B",
            "http://host%23.com/~a!b@c%23d$e%25f^00&11*22(33)44_55+",
        ),
        (b"http://3279880203/blah", "http://195.127.0.11/blah"),
        (b"http://www.google.com/blah/..", "http://www.google.com/"),
        (b"www.google.com/", "http://www.google.com/"),
        (b"www.google.com", "http://www.google.com/"),
        (b"http://www.evil.com/blah#frag", "http://www.evil.com/blah"),
        (b"http://www.GOOgle.com/", "http://www.google.com/"),
        (b"http://www.google.com.../", "http://www.google.com/"),
        (b"http://www.google.com/foo\tbar\rbaz\n2", "http://www.google.com/foobarbaz2"),
        (b"http://www.google.com/q?", "http://www.google.com/q?"),
        (b"http://www.google.com/q?r?", "http://www.google.com/q?r?"),
        (b"http://www.google.com/q?r?s", "http://www.google.com/q?r?s"),
        (b"http://evil.com/foo#bar#baz", "http://evil.com/foo"),
        (b"http://evil.com/foo;", "http://evil.com/foo;"),
        (b"http://evil.com/foo?bar;", "http://evil.com/foo?bar;"),
        (b"http://\x01\x80.com/", "http://%01%80.com/"),
        (b"http://notrailingslash.com", "http://notrailingslash.com/"),
        (b"http://www.gotaport.com:1234/", "http://www.gotaport.com/"),
        (b"  http://www.google.com/  ", "http://www.google.com/"),
        (b"http:// leadingspace.com/", "http://%20leadingspace.com/"),
        (b"http://%20leadingspace.com/", "http://%20leadingspace.com/"),
        (b"%20leadingspace.com/", "http://%20leadingspace.com/"),
        (b"https://www.securesite.com/", "https://www.securesite.com/"),
        (b"http://host.com/ab%23cd", "http://host.com/ab%23cd"),
        (b"http://host.com//twoslashes?more//slashes", "http://host.com/twoslashes?more//slashes"),
    ];

    #[test]
    fn matches_every_published_safe_browsing_example() {
        let failures: Vec<String> = SAFE_BROWSING_VECTORS
            .iter()
            .filter_map(|(input, expected)| {
                let got = canonicalize(input).map(|c| c.to_string());
                (got.as_deref() != Ok(*expected)).then(|| {
                    format!(
                        "{:?}: expected {expected:?}, got {got:?}",
                        String::from_utf8_lossy(input)
                    )
                })
            })
            .collect();
        assert!(
            failures.is_empty(),
            "{} mismatches:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    fn sorted_expressions(url: &str) -> Vec<String> {
        let mut e = canonicalize(url.as_bytes())
            .map(|c| c.expressions())
            .unwrap_or_default();
        e.sort();
        e
    }

    fn sorted(list: &[&str]) -> Vec<String> {
        let mut v: Vec<String> = list.iter().map(|s| (*s).to_owned()).collect();
        v.sort();
        v
    }

    #[test]
    fn expressions_match_published_examples() {
        assert_eq!(
            sorted_expressions("http://a.b.c/1/2.html?param=1"),
            sorted(&[
                "a.b.c/1/2.html?param=1",
                "a.b.c/1/2.html",
                "a.b.c/",
                "a.b.c/1/",
                "b.c/1/2.html?param=1",
                "b.c/1/2.html",
                "b.c/",
                "b.c/1/",
            ])
        );
        assert_eq!(
            sorted_expressions("http://a.b.c.d.e.f.g/1.html"),
            sorted(&[
                "a.b.c.d.e.f.g/1.html",
                "a.b.c.d.e.f.g/",
                "c.d.e.f.g/1.html",
                "c.d.e.f.g/",
                "d.e.f.g/1.html",
                "d.e.f.g/",
                "e.f.g/1.html",
                "e.f.g/",
                "f.g/1.html",
                "f.g/",
            ])
        );
        assert_eq!(
            sorted_expressions("http://1.2.3.4/1/"),
            sorted(&["1.2.3.4/1/", "1.2.3.4/"])
        );
    }

    #[test]
    fn at_most_thirty_expressions() {
        let long = "http://a.b.c.d.e.f.g.h/1/2/3/4/5/6/7.html?q=1";
        let count = canonicalize(long.as_bytes()).map(|c| c.expressions().len());
        assert_eq!(count, Ok(30));
    }

    #[test]
    fn credentials_and_ports_never_reach_expressions() {
        let c = canonicalize(b"https://user:pass@Login.Example.com:8443/a").ok();
        assert_eq!(
            c.as_ref().map(CanonicalUrl::host),
            Some("login.example.com")
        );
        assert!(c.is_some_and(|c| {
            c.expressions()
                .iter()
                .all(|e| !e.contains("user") && !e.contains(':'))
        }));
    }

    #[test]
    fn internationalized_hosts_become_punycode() {
        let c = canonicalize("http://bücher.example/".as_bytes()).map(|c| c.host().to_owned());
        assert_eq!(c.as_deref(), Ok("xn--bcher-kva.example"));
    }

    #[test]
    fn inet_aton_forms_are_normalized() {
        for (input, expected) in [
            ("http://0x7f.1/", "127.0.0.1"),
            ("http://0177.0.0.01/", "127.0.0.1"),
            ("http://127.1/", "127.0.0.1"),
            ("http://1.2.65535/", "1.2.255.255"),
        ] {
            assert_eq!(
                canonicalize(input.as_bytes())
                    .map(|c| c.host().to_owned())
                    .as_deref(),
                Ok(expected),
                "{input}"
            );
        }
        assert_eq!(
            canonicalize(b"http://1.2.3.4.5/").map(|c| c.host_is_ip()),
            Ok(false)
        );
        assert_eq!(
            canonicalize(b"http://256.1.1.1/").map(|c| c.host_is_ip()),
            Ok(false)
        );
    }

    #[test]
    fn rejects_oversized_and_hostless_input() {
        assert_eq!(
            canonicalize(&vec![b'a'; MAX_URL_BYTES + 1]),
            Err(CanonError::TooLong)
        );
        assert_eq!(canonicalize(b"http://.../path"), Err(CanonError::NoHost));
        assert_eq!(canonicalize(b""), Err(CanonError::NoHost));
    }

    mod properties {
        use super::super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(4000))]

            /// Canonical output is ASCII and stable under re-canonicalization.
            #[test]
            fn canonical_form_is_ascii_and_idempotent(input in proptest::collection::vec(any::<u8>(), 0..256)) {
                if let Ok(first) = canonicalize(&input) {
                    let text = first.to_string();
                    prop_assert!(text.is_ascii());
                    let second = canonicalize(text.as_bytes());
                    prop_assert_eq!(second.map(|c| c.to_string()), Ok(text));
                    prop_assert!(first.expressions().len() <= 30);
                }
            }

            #[test]
            fn url_shaped_input_is_idempotent(
                host in "[a-zA-Z0-9.%-]{1,40}",
                path in "[a-zA-Z0-9./%?#;=&-]{0,60}",
            ) {
                let input = format!("http://{host}/{path}");
                if let Ok(first) = canonicalize(input.as_bytes()) {
                    let text = first.to_string();
                    prop_assert_eq!(canonicalize(text.as_bytes()).map(|c| c.to_string()), Ok(text));
                }
            }
        }
    }
}
