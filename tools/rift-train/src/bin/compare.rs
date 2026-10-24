//! Compares ways of checking a link on the same addresses (docs/reports/check-accuracy.md):
//! URLCheck's hosts check (StevenBlack's list, exact host), Rift's Check
//! without threat lists (threat database, address checks, Rift AI), and
//! Rift's Check with them.
//!
//!   compare <model> <pack-dir> <positives> <negatives> <id>=<path>[:wildcard]...
//!
//! The list named `stevenblack` stands for URLCheck; `tif` and
//! `phishing-army` are the lists the app calls dangerous. Prints one table.
//!
//! An offline maintainer tool over files the maintainer chose: counts are of
//! lines in those files.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use rift_core::heuristics::HeuristicConfig;
use rift_core::hostlists::{HostLists, Source};
use rift_core::pack::Pack;
use rift_core::policy::{self, Decision, IntelState, NavigationContext};
use rift_core::urlcanon;
use rift_core::urlmodel::{Level, UrlModel, View};

#[derive(Default)]
struct Found {
    database: bool,
    address_checks: bool,
    ai_high: bool,
    ai_elevated: bool,
    lists: Vec<String>,
    urlcheck: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("compare: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [model, pack, positives, negatives, lists @ ..] = args.as_slice() else {
        return Err(
            "usage: compare <model> <pack-dir> <positives> <negatives> <id>=<path>[:wildcard]..."
                .to_owned(),
        );
    };
    let model = fs::read(model).map_err(|e| format!("{model}: {e}"))?;
    let model = UrlModel::parse(&model).map_err(|e| format!("model: {e:?}"))?;
    let pack = read_pack(Path::new(pack))?;
    let texts = lists
        .iter()
        .map(|spec| {
            let (id, rest) = spec
                .split_once('=')
                .ok_or_else(|| format!("{spec}: not id=path"))?;
            let (path, wildcard) = rest
                .strip_suffix(":wildcard")
                .map_or((rest, false), |p| (p, true));
            let text = fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
            Ok((id.to_owned(), text, wildcard))
        })
        .collect::<Result<Vec<(String, String, bool)>, String>>()?;
    let sources: Vec<Source<'_>> = texts
        .iter()
        .map(|(id, text, wildcard)| Source {
            id,
            text,
            wildcard: *wildcard,
        })
        .collect();
    let (hostlists, loaded) = HostLists::load(&sources);
    for (source, result) in sources.iter().zip(&loaded) {
        match result {
            Ok(found) => eprintln!(
                "{}: {} hosts, {} lines skipped",
                source.id, found.hosts, found.skipped
            ),
            Err(error) => eprintln!("{}: {error}", source.id),
        }
    }
    // As the Android app configures Check (Core.kt).
    let heuristics = HeuristicConfig {
        protected_domains: [
            "paypal.com",
            "google.com",
            "apple.com",
            "microsoft.com",
            "amazon.com",
            "facebook.com",
            "instagram.com",
            "whatsapp.com",
            "netflix.com",
            "github.com",
        ]
        .map(str::to_owned)
        .to_vec(),
        shorteners: [
            "bit.ly",
            "t.co",
            "tinyurl.com",
            "goo.gl",
            "ow.ly",
            "is.gd",
            "buff.ly",
            "rb.gy",
            "cutt.ly",
            "shorturl.at",
        ]
        .map(str::to_owned)
        .to_vec(),
        ..HeuristicConfig::default()
    };
    let ctx = NavigationContext {
        sandbox_verified: true,
        indicators: Some(&pack.urls),
        intel_state: IntelState::Current,
        heuristics: &heuristics,
        model: Some(&model),
    };
    println!(
        "| Set | Links | URLCheck (StevenBlack hosts) | Rift 2.8: red | Rift 2.8: any warning | Rift 2.9: red | Rift 2.9: any warning | Each list |"
    );
    println!("|---|---|---|---|---|---|---|---|");
    for (name, path) in [("phishing", positives), ("ordinary", negatives)] {
        let links: Vec<String> = fs::read_to_string(path)
            .map_err(|e| format!("{path}: {e}"))?
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect();
        let found: Vec<Found> = links
            .iter()
            .filter_map(|l| check(l, &ctx, &model, &hostlists))
            .collect();
        let n = found.len();
        let pct =
            |count: usize| format!("{:.1}% ({count})", 100.0 * count as f64 / n.max(1) as f64);
        let count = |f: &dyn Fn(&Found) -> bool| found.iter().filter(|x| f(x)).count();
        // As the app's verdicts: red is Known malicious, Listed as dangerous
        // or Looks dangerous; the rest are Warning signs (LinkCheckViews.kt).
        let danger = |x: &Found| {
            x.lists
                .iter()
                .any(|id| id == "tif" || id == "phishing-army")
        };
        let red = |x: &Found| x.database || x.ai_high;
        let warned = |x: &Found| red(x) || x.address_checks || x.ai_elevated;
        let mut each: BTreeMap<&str, usize> = BTreeMap::new();
        for x in &found {
            for id in &x.lists {
                *each.entry(id).or_default() += 1;
            }
        }
        let each = each
            .iter()
            .map(|(id, c)| format!("{id} {}", pct(*c)))
            .collect::<Vec<_>>()
            .join("; ");
        println!(
            "| {name} | {n} | {} | {} | {} | {} | {} | {each} |",
            pct(count(&|x| x.urlcheck)),
            pct(count(&red)),
            pct(count(&warned)),
            pct(count(&|x| red(x) || danger(x))),
            pct(count(&|x| warned(x) || !x.lists.is_empty())),
        );
    }
    Ok(())
}

fn check(
    link: &str,
    ctx: &NavigationContext<'_>,
    model: &UrlModel,
    lists: &HostLists,
) -> Option<Found> {
    let address = policy::engine_address(link.as_bytes())?;
    let canonical = urlcanon::canonicalize(address.as_bytes()).ok()?;
    let mut found = Found::default();
    match policy::decide_navigation(link.as_bytes(), ctx) {
        Decision::Block { reason, .. } => {
            found.database = format!("{reason:?}").contains("KnownMalicious")
        }
        Decision::Confirm { reasons, .. } => {
            found.address_checks = reasons.iter().any(|r| !r.code().starts_with("ai-"));
        }
        Decision::Proceed { .. } => {}
    }
    let assessment = model.assess(&canonical, View::Address);
    found.ai_high = assessment.level == Level::High;
    found.ai_elevated = assessment.level == Level::Elevated;
    // URLCheck checks every host against its hosts file, popular or not.
    found.urlcheck = lists
        .lookup(canonical.host())
        .iter()
        .any(|id| id == "stevenblack");
    if !model.abstains(&canonical) {
        found.lists = lists.lookup(canonical.host());
    }
    Some(found)
}

fn read_pack(dir: &Path) -> Result<Pack, String> {
    let files = fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .map(|entry| {
            let path = entry.map_err(|e| e.to_string())?.path();
            let bytes = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
            Ok((name.unwrap_or_default(), bytes))
        })
        .collect::<Result<Vec<(String, Vec<u8>)>, String>>()?;
    Pack::validate(files.iter().map(|(n, b)| (n.as_str(), b.as_slice())))
        .map_err(|e| format!("pack: {e:?}"))
}
