//! Navigation policy (docs/architecture.md §10.2–§10.4, INV-6, INV-7).
//!
//! A pure function of its inputs: no I/O, no clocks, no globals, so every
//! combination can be tested. The browser host asks before each main-frame
//! navigation it can observe and must follow the decision.

use crate::heuristics::{self, Flag, HeuristicConfig, Severity};
use crate::intel::UrlTable;
use crate::urlcanon::{self, CanonError};

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
    /// The URL could not be assessed (e.g. longer than the checker accepts).
    NotChecked(CanonError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    Heuristic(Flag),
    IntelStale,
    IntelMissing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockReason {
    SandboxUnavailable,
    SchemeNotAllowed(String),
    InvalidUrl,
    /// Matched indicators: (expression that matched, pack metadata index).
    KnownMalicious(Vec<(String, u32)>),
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

    let mut notes = match ctx.intel_state {
        IntelState::Current => Vec::new(),
        IntelState::Stale => vec![Note::IntelStale],
        IntelState::Missing => vec![Note::IntelMissing],
    };
    let url = match urlcanon::canonicalize(raw) {
        Ok(url) => url,
        Err(CanonError::NoHost) => return block(BlockReason::InvalidUrl),
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

/// The scheme the input explicitly names, if any (`javascript:`, `intent:`, …).
/// `host:8080`-style input is not a scheme. Inputs without one are treated as
/// web addresses by canonicalization.
fn explicit_scheme(raw: &[u8]) -> Option<String> {
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
        assert!(matches!(
            decide("example.org", None, true),
            Decision::Proceed { .. }
        ));
        assert!(matches!(
            decide("localhost:8080/x", None, true),
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
            };
            match decide_navigation(b"https://example.org/", &ctx) {
                Decision::Proceed { notes } => assert!(notes.contains(&note)),
                other => panic!("expected proceed, got {other:?}"),
            }
        }
    }
}
