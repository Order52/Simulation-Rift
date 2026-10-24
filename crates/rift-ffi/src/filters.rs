//! Content filters for the Android controller (docs/architecture.md §10.9):
//! the lists live in the main process; the browser app asks over Binder
//! whether to block a request and what to hide, and gets a yes or no and
//! some CSS. Lists are fetched here, with the same checked fetcher as every
//! other transfer of the controller's.

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};

use rift_core::download::{self, DownloadPolicy};
use rift_core::filters::Filters;

/// The most one list may be: the largest upstream list is about 2 MB, and the engine's
/// memory grows with what it is given.
const MAX_LIST_BYTES: u64 = 6 * 1024 * 1024;

/// What to hide on a page: see [`rift_core::filters::Cosmetic`].
#[derive(Debug, uniffi::Record)]
pub struct Hiding {
    pub css: String,
    pub exceptions: Vec<String>,
    pub generic_hidden: bool,
    /// Changes beyond hiding, as JSON for the browser's script (empty if none).
    pub actions: String,
}

/// The compiled lists. Replaced as a whole by [`ContentFilters::load`]; a request in flight uses the set it started with.
#[derive(Debug, uniffi::Object)]
pub struct ContentFilters {
    current: RwLock<Option<Arc<Filters>>>,
}

#[uniffi::export]
impl ContentFilters {
    /// No lists yet: nothing is blocked or hidden.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            current: RwLock::new(None),
        })
    }

    /// Compiles `lists` (each the text of one list) and uses them from now on; no lists turns filtering off.
    /// Takes a moment: call it away from the main thread.
    pub fn load(&self, lists: Vec<String>) {
        let compiled = (!lists.is_empty()).then(|| Arc::new(Filters::new(lists)));
        if let Ok(mut current) = self.current.write() {
            *current = compiled;
        }
    }

    /// Keeps the compiled lists in the file at `path` (written whole, then moved into place), so
    /// that the next start loads them instead of compiling them again. False if it could not be written.
    pub fn save(&self, path: String) -> bool {
        let Some(filters) = self.get() else {
            return false;
        };
        let target = std::path::Path::new(&path);
        let temporary = target.with_extension("tmp");
        std::fs::write(&temporary, filters.save()).is_ok()
            && std::fs::rename(&temporary, target).is_ok()
    }

    /// Loads the lists kept by [`ContentFilters::save`]; false if there is no such file or the engine
    /// does not accept it (another version of Rift, a damaged file): compile the lists then.
    pub fn load_saved(&self, path: String) -> bool {
        let Ok(bytes) = std::fs::read(&path) else {
            return false;
        };
        let Some(filters) = Filters::from_saved(&bytes) else {
            return false;
        };
        if let Ok(mut current) = self.current.write() {
            *current = Some(Arc::new(filters));
            return true;
        }
        false
    }

    /// Whether the lists are loaded.
    pub fn is_loaded(&self) -> bool {
        self.get().is_some()
    }

    /// Whether the request is blocked; false without lists.
    pub fn blocks(&self, url: String, page: String, kind: String) -> bool {
        self.get().is_some_and(|f| f.blocks(&url, &page, &kind))
    }

    /// What to hide on the page at `url`.
    pub fn hiding(&self, url: String) -> Hiding {
        match self.get() {
            Some(f) => {
                let found = f.cosmetic(&url);
                Hiding {
                    css: found.css,
                    exceptions: found.exceptions,
                    generic_hidden: found.generic_hidden,
                    actions: found.actions,
                }
            }
            None => Hiding {
                css: String::new(),
                exceptions: Vec::new(),
                generic_hidden: false,
                actions: String::new(),
            },
        }
    }

    /// The rules for the class names and ids a page uses.
    pub fn generic_css(
        &self,
        classes: Vec<String>,
        ids: Vec<String>,
        exceptions: Vec<String>,
    ) -> String {
        self.get()
            .map(|f| f.generic_css(&classes, &ids, &exceptions))
            .unwrap_or_default()
    }
}

impl ContentFilters {
    fn get(&self) -> Option<Arc<Filters>> {
        self.current.read().ok().and_then(|c| c.clone())
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FilterFetchFailure {
    #[error("{reason}")]
    Failed { reason: String },
}

/// Fetches one list over HTTPS, checked like a download (every hop, no local addresses).
#[uniffi::export]
pub fn fetch_filter_list(url: String) -> Result<String, FilterFetchFailure> {
    fetch_text(&url, MAX_LIST_BYTES)
}

pub(crate) fn fetch_text(url: &str, max_bytes: u64) -> Result<String, FilterFetchFailure> {
    if !url.starts_with("https://") {
        return Err(FilterFetchFailure::Failed {
            reason: "a list is fetched over HTTPS only".into(),
        });
    }
    let bytes = download::fetch(
        url,
        &DownloadPolicy::default(),
        "Rift-update",
        max_bytes,
        &AtomicBool::new(false),
    )
    .map_err(|e| FilterFetchFailure::Failed {
        reason: e.to_string(),
    })?;
    String::from_utf8(bytes).map_err(|_| FilterFetchFailure::Failed {
        reason: "the list is not text".into(),
    })
}
