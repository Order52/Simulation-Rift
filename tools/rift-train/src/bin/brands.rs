//! The gate for a new brand list (docs/architecture.md §10.3; brands.py):
//! it runs Check's own address checks with the shipped and the new list
//! over ordinary and phishing addresses, and refuses the new list if it
//! warns about more ordinary addresses than the shipped one by more than
//! 0.05 points, or about more than 0.5% of them.
//!
//!   brands <shipped.txt> <new.txt> --legit <urls>... --phishing <urls>...
//!
//! Exit status 2: refused.
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

use std::fs;
use std::process::ExitCode;

use rift_core::heuristics::{HeuristicConfig, Severity, assess, parse_brands};
use rift_core::urlcanon::canonicalize;

/// The share of `urls` with a brand warning under `brands`, and some examples.
fn warned(brands: &[String], urls: &[String]) -> (f64, Vec<String>) {
    let config = HeuristicConfig {
        protected_domains: brands.to_vec(),
        ..HeuristicConfig::default()
    };
    let mut hits = Vec::new();
    let mut n = 0usize;
    let mut count = 0usize;
    for raw in urls {
        let Ok(url) = canonicalize(raw.as_bytes()) else {
            continue;
        };
        n += 1;
        let brand_warning = assess(raw.as_bytes(), &url, &config).iter().any(|f| {
            f.severity() == Severity::Warn
                && matches!(
                    f.code(),
                    "lookalike"
                        | "protected-name-in-subdomain"
                        | "protected-name-in-path"
                        | "brand-in-host"
                )
        });
        if brand_warning {
            count += 1;
            if hits.len() < 10 {
                hits.push(url.host().to_owned());
            }
        }
    }
    (count as f64 / n.max(1) as f64, hits)
}

fn read_urls(paths: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for path in paths {
        let text = fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        for line in text.lines() {
            let url = line.split('\t').next().unwrap_or_default().trim();
            if url.is_empty() || url.starts_with('#') {
                continue;
            }
            out.push(if url.contains("://") {
                url.to_owned()
            } else {
                format!("http://{url}/")
            });
        }
    }
    Ok(out)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(l), Some(p)) = (
        args.iter().position(|a| a == "--legit"),
        args.iter().position(|a| a == "--phishing"),
    ) else {
        eprintln!("usage: brands <shipped.txt> <new.txt> --legit <urls>... --phishing <urls>...");
        return ExitCode::FAILURE;
    };
    if l < 2 || p < 2 {
        eprintln!("usage: brands <shipped.txt> <new.txt> --legit <urls>... --phishing <urls>...");
        return ExitCode::FAILURE;
    }
    let part = |from: usize, other: usize| -> Vec<String> {
        let end = if other > from { other } else { args.len() };
        args.get(from + 1..end).unwrap_or_default().to_vec()
    };
    let lists = match (fs::read_to_string(&args[0]), fs::read_to_string(&args[1])) {
        (Ok(a), Ok(b)) => [a, b].map(|t| {
            parse_brands(&t)
                .into_iter()
                .map(|b| b.domain)
                .collect::<Vec<_>>()
        }),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("brands: {e}");
            return ExitCode::FAILURE;
        }
    };
    let (legit, phishing) = match (read_urls(&part(l, p)), read_urls(&part(p, l))) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("brands: {e}");
            return ExitCode::FAILURE;
        }
    };
    let [shipped, new] = &lists;
    let (old_legit, _) = warned(shipped, &legit);
    let (new_legit, examples) = warned(new, &legit);
    let (old_phish, _) = warned(shipped, &phishing);
    let (new_phish, _) = warned(new, &phishing);
    println!(
        "brands: {} shipped, {} new; ordinary addresses warned {:.3}% -> {:.3}% of {}; phishing addresses {:.1}% -> {:.1}% of {}",
        shipped.len(),
        new.len(),
        old_legit * 100.0,
        new_legit * 100.0,
        legit.len(),
        old_phish * 100.0,
        new_phish * 100.0,
        phishing.len()
    );
    if new_legit > old_legit + 0.0005 || new_legit > 0.005 {
        println!(
            "refused: too many ordinary addresses warned, such as {}",
            examples.join(", ")
        );
        return ExitCode::from(2);
    }
    println!("passed the gate");
    ExitCode::SUCCESS
}
