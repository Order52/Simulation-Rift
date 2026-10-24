//! Threat lists for Check (docs/architecture.md §10.12): community host lists
//! the user downloaded, loaded in the core and consulted by
//! [`Navigator::check`]. They can only add a finding.

use std::sync::Arc;

use rift_core::hostlists::{HostListError, HostLists, Source};

/// One downloaded list.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ThreatListText {
    pub id: String,
    pub text: String,
    /// Each host also covers its subdomains (HaGeZi's wildcard lists).
    pub wildcard: bool,
}

/// What loading one list found.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ThreatListLoaded {
    pub id: String,
    pub hosts: u64,
    /// Why the list is not in use; None when it is.
    pub error: Option<String>,
}

/// Loaded threat lists.
#[derive(Debug, uniffi::Object)]
pub struct ThreatLists {
    pub(crate) lists: HostLists,
    loaded: Vec<ThreatListLoaded>,
}

#[uniffi::export]
impl ThreatLists {
    /// Loads `lists`; one that is unusable is reported in [`ThreatLists::loaded`]
    /// and the others are used.
    #[uniffi::constructor]
    pub fn load(lists: Vec<ThreatListText>) -> Arc<Self> {
        let sources: Vec<Source<'_>> = lists
            .iter()
            .map(|list| Source {
                id: &list.id,
                text: &list.text,
                wildcard: list.wildcard,
            })
            .collect();
        let (set, results) = HostLists::load(&sources);
        let loaded = lists
            .iter()
            .zip(results)
            .map(|(list, result)| match result {
                Ok(found) => ThreatListLoaded {
                    id: found.id,
                    hosts: u64::try_from(found.hosts).unwrap_or(u64::MAX),
                    error: None,
                },
                Err(error) => failure(&list.id, &error),
            })
            .collect();
        Arc::new(Self { lists: set, loaded })
    }

    pub fn loaded(&self) -> Vec<ThreatListLoaded> {
        self.loaded.clone()
    }
}

fn failure(id: &str, error: &HostListError) -> ThreatListLoaded {
    ThreatListLoaded {
        id: id.to_owned(),
        hosts: 0,
        error: Some(error.to_string()),
    }
}

/// Fetches one threat list over HTTPS, as [`crate::fetch_filter_list`] does
/// but with the host lists' larger bound.
#[uniffi::export]
pub fn fetch_threat_list(url: String) -> Result<String, crate::FilterFetchFailure> {
    crate::filters::fetch_text(&url, rift_core::hostlists::MAX_LIST_BYTES as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Navigator;

    fn navigator() -> Arc<Navigator> {
        let ai = crate::Ai::load(include_bytes!("../../../models/url-model.bin").to_vec()).unwrap();
        Navigator::with_ai(Vec::new(), Vec::new(), Vec::new(), Some(ai))
    }

    fn lists() -> Arc<ThreatLists> {
        ThreatLists::load(vec![
            ThreatListText {
                id: "tif".into(),
                text: "bad.example\ndocs.google.com\n".into(),
                wildcard: true,
            },
            ThreatListText {
                id: "hosts".into(),
                text: "0.0.0.0 bad.example\n".into(),
                wildcard: false,
            },
            ThreatListText {
                id: "empty".into(),
                text: "# none\n".into(),
                wildcard: false,
            },
        ])
    }

    #[test]
    fn check_names_the_lists_that_list_a_host() {
        let navigator = navigator();
        assert!(
            navigator
                .check("https://bad.example/".into(), None, 0)
                .listed
                .is_empty()
        );
        let loaded = lists();
        assert_eq!(loaded.loaded()[0].hosts, 2);
        assert!(loaded.loaded()[2].error.is_some());
        navigator.set_threat_lists(Some(loaded));
        assert_eq!(
            navigator
                .check("https://bad.example/login".into(), None, 0)
                .listed,
            ["tif", "hosts"]
        );
        assert_eq!(
            navigator
                .check("https://www.bad.example/".into(), None, 0)
                .listed,
            ["tif"]
        );
        assert!(
            navigator
                .check("https://good.example/".into(), None, 0)
                .listed
                .is_empty()
        );
        navigator.set_threat_lists(None);
        assert!(
            navigator
                .check("https://bad.example/".into(), None, 0)
                .listed
                .is_empty()
        );
    }

    #[test]
    fn a_most_visited_site_is_not_flagged_by_a_list() {
        let navigator = navigator();
        navigator.set_threat_lists(Some(lists()));
        assert!(
            navigator
                .check("https://docs.google.com/forms/d/x".into(), None, 0)
                .listed
                .is_empty()
        );
    }

    #[test]
    fn a_trace_hop_is_checked_against_the_lists_too() {
        // Hops are checked by `check` (link.rs); the lists come with the navigator.
        let navigator = navigator();
        navigator.set_threat_lists(Some(lists()));
        let check = navigator.check("http://bad.example:8080/x".into(), None, 0);
        assert_eq!(check.listed, ["tif", "hosts"]);
    }
}
