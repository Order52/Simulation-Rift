//! The navigation decision combines canonicalization, heuristics, indicator
//! lookups and policy on a URL chosen by a website. It must never panic, and
//! it must never let a navigation proceed without a verified sandbox (INV-7)
//! or to a URL the indicator table lists.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rift_core::heuristics::HeuristicConfig;
use rift_core::intel::UrlTable;
use rift_core::policy::{
    BlockReason, Decision, IntelState, NavigationContext, decide_navigation, engine_address,
};
use rift_core::urlcanon::canonicalize;

fuzz_target!(|data: &[u8]| {
    let Some((&flags, raw)) = data.split_first() else {
        return;
    };
    let heuristics = HeuristicConfig {
        protected_domains: vec!["paypal.com".into(), "example-bank.com".into()],
        shorteners: vec!["bit.ly".into()],
        ..HeuristicConfig::default()
    };
    // An indicator table listing the expressions of a fixed URL, so the
    // "known malicious" path is reachable.
    let listed = canonicalize(b"http://evil.example/login").expect("fixed URL canonicalizes");
    let mut entries: Vec<([u8; 16], u32)> = listed
        .expression_hashes()
        .into_iter()
        .map(|hash| (hash, 0))
        .collect();
    entries.sort_unstable();
    entries.dedup_by(|a, b| a.0 == b.0);
    let table = UrlTable::parse(&UrlTable::encode(entries).expect("encodes"), 1).expect("parses");

    let sandbox_verified = flags & 1 != 0;
    let ctx = NavigationContext {
        sandbox_verified,
        indicators: (flags & 2 != 0).then_some(&table),
        intel_state: match flags >> 2 & 3 {
            0 => IntelState::Current,
            1 => IntelState::Stale,
            _ => IntelState::Missing,
        },
        heuristics: &heuristics,
        model: None,
    };
    let decision = decide_navigation(raw, &ctx);
    if !sandbox_verified {
        assert_eq!(
            decision,
            Decision::Block {
                reason: BlockReason::SandboxUnavailable,
                inspect_anyway: false
            }
        );
    }
    // A page loads without a prompt only if it was assessed, as the engine
    // reads it, and matched no indicator.
    if matches!(decision, Decision::Proceed { .. }) {
        let address =
            engine_address(raw).expect("proceeded with an address the engine cannot load");
        let url = canonicalize(address.as_bytes())
            .expect("proceeded with a URL that does not canonicalize");
        if let Some(table) = ctx.indicators {
            assert!(
                table.matches(&url).is_empty(),
                "proceeded to a listed URL: {url}"
            );
        }
    }
});
