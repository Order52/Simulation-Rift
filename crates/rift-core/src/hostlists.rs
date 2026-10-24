//! Host lists for Check (§10.12): community-maintained lists of dangerous
//! hosts (HaGeZi's Threat Intelligence Feeds, Phishing Army, uBlock Origin's
//! badware list, StevenBlack's hosts), which the user downloads. Rift writes
//! none of them.
//!
//! The lists are untrusted text. Each line is one host in one of the usual
//! formats: a hosts file (`0.0.0.0 host`), a plain domain, a wildcard
//! (`*.host`) or an adblock host rule (`||host^`, with options). Anything
//! else (paths, exceptions, element rules, addresses) is skipped and counted.
//! Hosts are kept as keyed 64-bit hashes, with a key drawn when the lists are
//! loaded, so a list cannot be built to collide with a host it does not name.
//! A list can only add a warning: nothing here allows anything.

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;

/// The largest list accepted: HaGeZi's medium feed is about 12 MB.
pub const MAX_LIST_BYTES: usize = 48 * 1024 * 1024;
const MAX_ENTRIES: usize = 3_000_000;
const MAX_HOST_LEN: usize = 253;
/// Lists in one set.
const MAX_LISTS: usize = 16;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HostListError {
    #[error("the list is larger than {MAX_LIST_BYTES} bytes")]
    TooLarge,
    #[error("the list has more than {MAX_ENTRIES} hosts")]
    TooMany,
    #[error("the list has no hosts")]
    Empty,
    #[error("more than {MAX_LISTS} lists")]
    TooManyLists,
}

/// One list to load: `id` names it in results; with `wildcard`, every host
/// in it also covers its subdomains (as HaGeZi's wildcard lists mean).
#[derive(Debug, Clone)]
pub struct Source<'a> {
    pub id: &'a str,
    pub text: &'a str,
    pub wildcard: bool,
}

#[derive(Debug)]
struct List {
    id: String,
    /// Sorted hashes of hosts that match only themselves.
    exact: Vec<u64>,
    /// Sorted hashes of hosts that match themselves and their subdomains.
    covering: Vec<u64>,
}

/// What loading a list found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loaded {
    pub id: String,
    pub hosts: usize,
    /// Lines that were not a host in a format this reads.
    pub skipped: usize,
}

/// A set of loaded lists.
#[derive(Debug)]
pub struct HostLists {
    hasher: RandomState,
    lists: Vec<List>,
}

impl HostLists {
    /// Loads `sources`, one result each. A list that is too large, has no
    /// host or comes after the first [`MAX_LISTS`] is an error for that list
    /// only; the others load.
    pub fn load(sources: &[Source<'_>]) -> (Self, Vec<Result<Loaded, HostListError>>) {
        let hasher = RandomState::new();
        let mut lists = Vec::new();
        let mut results = Vec::new();
        for (i, source) in sources.iter().enumerate() {
            if i >= MAX_LISTS {
                results.push(Err(HostListError::TooManyLists));
                continue;
            }
            match parse(&hasher, source) {
                Ok((list, loaded)) => {
                    lists.push(list);
                    results.push(Ok(loaded));
                }
                Err(error) => results.push(Err(error)),
            }
        }
        (Self { hasher, lists }, results)
    }

    /// The ids of the lists that name `host` (lower case, ASCII: the
    /// engine's form), in load order.
    pub fn lookup(&self, host: &str) -> Vec<String> {
        let host = host.trim_end_matches('.');
        if host.is_empty() || host.len() > MAX_HOST_LEN {
            return Vec::new();
        }
        let own = self.hasher.hash_one(host);
        // The host and each parent domain, as far as a two-label one.
        let parents: Vec<u64> =
            std::iter::successors(Some(host), |h| h.split_once('.').map(|(_, rest)| rest))
                .filter(|h| h.contains('.') || *h == host)
                .map(|h| self.hasher.hash_one(h))
                .collect();
        self.lists
            .iter()
            .filter(|list| {
                list.exact.binary_search(&own).is_ok()
                    || parents
                        .iter()
                        .any(|h| list.covering.binary_search(h).is_ok())
            })
            .map(|list| list.id.clone())
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.lists.is_empty()
    }
}

fn parse(hasher: &RandomState, source: &Source<'_>) -> Result<(List, Loaded), HostListError> {
    if source.text.len() > MAX_LIST_BYTES {
        return Err(HostListError::TooLarge);
    }
    let mut exact = Vec::new();
    let mut covering = Vec::new();
    let mut skipped = 0usize;
    for line in source.text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(['#', '!', '[']) {
            continue;
        }
        match entry(line) {
            Some((host, covers)) => {
                if exact.len().saturating_add(covering.len()) >= MAX_ENTRIES {
                    return Err(HostListError::TooMany);
                }
                let hash = hasher.hash_one(host.as_str());
                if covers || source.wildcard {
                    covering.push(hash);
                } else {
                    exact.push(hash);
                }
            }
            None => skipped = skipped.saturating_add(1),
        }
    }
    exact.sort_unstable();
    exact.dedup();
    exact.shrink_to_fit();
    covering.sort_unstable();
    covering.dedup();
    covering.shrink_to_fit();
    let hosts = exact.len().saturating_add(covering.len());
    if hosts == 0 {
        return Err(HostListError::Empty);
    }
    let loaded = Loaded {
        id: source.id.to_owned(),
        hosts,
        skipped,
    };
    Ok((
        List {
            id: source.id.to_owned(),
            exact,
            covering,
        },
        loaded,
    ))
}

/// One line's host, lower-cased, and whether it covers subdomains.
fn entry(line: &str) -> Option<(String, bool)> {
    // A hosts file's line may end in a comment, after a space; `#` inside a
    // word is an element rule (`site##.ad`), which names no host.
    let line = line
        .split_once(|c: char| c.is_whitespace())
        .map_or(line, |(first, rest)| match rest.find('#') {
            Some(at) => line
                .get(..first.len().saturating_add(1).saturating_add(at))
                .unwrap_or(line),
            None => line,
        })
        .trim();
    if line.contains('#') {
        return None;
    }
    if let Some(rule) = line.strip_prefix("||") {
        // `||host^` or `||host^$options`; a path or wildcard is not a host.
        let (host, rest) = rule.split_once('^')?;
        if !(rest.is_empty() || rest.starts_with('$')) {
            return None;
        }
        return host_name(host).map(|h| (h, true));
    }
    if let Some(host) = line.strip_prefix("*.") {
        return host_name(host).map(|h| (h, true));
    }
    let mut fields = line.split_whitespace();
    let first = fields.next()?;
    let host = match fields.next() {
        // `address host`, as hosts files have it; one host per line.
        Some(second) if first.parse::<std::net::IpAddr>().is_ok() && fields.next().is_none() => {
            second
        }
        Some(_) => return None,
        None => first,
    };
    host_name(host).map(|h| (h, false))
}

/// `host` as a lower-case ASCII name with at least two labels; addresses and
/// single names (`localhost`) are not hosts a list can usefully name.
fn host_name(host: &str) -> Option<String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let valid = !host.is_empty()
        && host.len() <= MAX_HOST_LEN
        && host.contains('.')
        && host.parse::<std::net::IpAddr>().is_err()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    valid.then_some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lists(sources: &[(&str, &str, bool)]) -> HostLists {
        let sources: Vec<Source<'_>> = sources
            .iter()
            .map(|(id, text, wildcard)| Source {
                id,
                text,
                wildcard: *wildcard,
            })
            .collect();
        HostLists::load(&sources).0
    }

    #[test]
    fn reads_the_usual_formats() {
        let set = lists(&[(
            "mixed",
            "# a comment\n! another\n0.0.0.0 hosts.example # inline\n127.0.0.1 localhost\n\
             plain.example\n*.wild.example\n||rule.example^\n||opts.example^$doc\n\
             ||path.example/x^\n@@||allowed.example^\nsite.example##.ad\n1.2.3.4\n",
            false,
        )]);
        for (host, listed) in [
            ("hosts.example", true),
            ("sub.hosts.example", false),
            ("plain.example", true),
            ("www.plain.example", false),
            ("wild.example", true),
            ("a.b.wild.example", true),
            ("rule.example", true),
            ("x.rule.example", true),
            ("opts.example", true),
            ("path.example", false),
            ("allowed.example", false),
            ("site.example", false),
            ("localhost", false),
            ("other.example", false),
        ] {
            assert_eq!(!set.lookup(host).is_empty(), listed, "{host}");
        }
    }

    #[test]
    fn a_wildcard_list_covers_subdomains() {
        let set = lists(&[
            ("tif", "bad.example\n", true),
            ("pa", "bad.example\n", false),
        ]);
        assert_eq!(set.lookup("bad.example"), ["tif", "pa"]);
        assert_eq!(set.lookup("login.bad.example"), ["tif"]);
        assert!(set.lookup("example").is_empty());
        assert_eq!(
            set.lookup("BAD.example".to_ascii_lowercase().as_str()),
            ["tif", "pa"]
        );
    }

    #[test]
    fn a_list_cannot_name_a_whole_suffix_by_a_single_label() {
        let set = lists(&[("l", "*.com\n||net^\ncom\nok.example\n", true)]);
        assert!(set.lookup("anything.com").is_empty());
        assert!(set.lookup("x.net").is_empty());
    }

    #[test]
    fn bad_lists_are_refused_one_by_one() {
        let big = "a".repeat(MAX_LIST_BYTES + 1);
        let sources = [
            Source {
                id: "empty",
                text: "# nothing\n",
                wildcard: false,
            },
            Source {
                id: "big",
                text: &big,
                wildcard: false,
            },
            Source {
                id: "good",
                text: "x.example\n",
                wildcard: false,
            },
        ];
        let (set, results) = HostLists::load(&sources);
        assert_eq!(results[0], Err(HostListError::Empty));
        assert_eq!(results[1], Err(HostListError::TooLarge));
        assert_eq!(results[2].as_ref().unwrap().hosts, 1);
        assert_eq!(set.lookup("x.example"), ["good"]);
    }

    #[test]
    fn odd_hosts_are_bounded() {
        let set = lists(&[("l", "x.example\n", true)]);
        assert!(set.lookup(&"a.".repeat(200)).is_empty());
        assert!(set.lookup("").is_empty());
        assert_eq!(set.lookup("x.example."), ["l"]);
    }
}
