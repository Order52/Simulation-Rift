//! PoC X3 benchmark: URL decision latency against a 1,000,000-entry table.
//!
//! Measures, per URL: canonicalize + all lookup expressions + hashing + table
//! lookups — the complete local indicator check on the navigation path.
//! Run with: cargo run --release -p rift-core --example x3_lookup_bench

// A measurement tool over its own counters, not an untrusted-input path.
#![allow(clippy::arithmetic_side_effects, clippy::cast_precision_loss)]

use std::time::Instant;

use rift_core::intel::UrlTable;
use rift_core::urlcanon::{canonicalize, expression_hash};

const TABLE_ENTRIES: u32 = 1_000_000;
const SAMPLES: usize = 200_000;

fn main() {
    let build = Instant::now();
    let entries = (0..TABLE_ENTRIES)
        .map(|i| (expression_hash(&format!("bad{i}.example/")), i % 1000))
        .collect();
    let bytes = UrlTable::encode(entries).unwrap_or_default();
    println!(
        "encoded table: {} entries, {} bytes in {:?}",
        TABLE_ENTRIES,
        bytes.len(),
        build.elapsed()
    );

    let parse = Instant::now();
    let Ok(table) = UrlTable::parse(&bytes, 1000) else {
        eprintln!("table failed validation");
        std::process::exit(1);
    };
    println!("parse + full validation: {:?}", parse.elapsed());

    // Realistic mix: deep URLs with queries, 1 in 10 hitting a domain indicator.
    let urls: Vec<String> = (0..SAMPLES)
        .map(|i| {
            let host = if i % 10 == 0 {
                format!("www.bad{}.example", i % 999_983)
            } else {
                format!("cdn{i}.news.site{}.org", i % 97)
            };
            format!("https://{host}/a/b%20c/d/article-{i}.html?utm_source=x&id={i}#top")
        })
        .collect();

    let mut nanos: Vec<u128> = Vec::with_capacity(SAMPLES);
    let mut hits = 0usize;
    for url in &urls {
        let started = Instant::now();
        let matched = canonicalize(url.as_bytes())
            .map(|c| !table.matches(&c).is_empty())
            .unwrap_or(false);
        nanos.push(started.elapsed().as_nanos());
        hits += usize::from(matched);
    }
    nanos.sort_unstable();
    let pct = |p: usize| {
        nanos
            .get(nanos.len() * p / 100)
            .copied()
            .unwrap_or_default() as f64
            / 1000.0
    };
    println!("samples: {SAMPLES}, hits: {hits}");
    println!(
        "decision latency µs: p50={:.1} p95={:.1} p99={:.1} max={:.1}",
        pct(50),
        pct(95),
        pct(99),
        nanos.last().copied().unwrap_or_default() as f64 / 1000.0
    );
    println!(
        "in-memory table: ~{} MiB (keys + metadata indices)",
        (table.len() * 20) / (1024 * 1024)
    );
}
