//! Threat lists are text from the network and hosts come from any link:
//! neither may panic the controller, and a lookup names only lists that
//! loaded (docs/architecture.md §10.12).
#![no_main]

use libfuzzer_sys::fuzz_target;
use rift_core::hostlists::{HostLists, Source};

fuzz_target!(|data: &[u8]| {
    // list \0 host
    let mut parts = data.splitn(2, |b| *b == 0).map(String::from_utf8_lossy);
    let (Some(text), Some(host)) = (parts.next(), parts.next()) else {
        return;
    };
    let sources = [
        Source { id: "exact", text: &text, wildcard: false },
        Source { id: "wildcard", text: &text, wildcard: true },
    ];
    let (lists, loaded) = HostLists::load(&sources);
    for id in lists.lookup(&host) {
        let i = sources.iter().position(|s| s.id == id).expect("a known list");
        assert!(loaded[i].is_ok(), "{id} named but did not load");
    }
});
