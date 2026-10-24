//! `rift-train`: trains Rift's URL model and reports how well it does on
//! sites it never saw (docs/architecture.md §16, docs/reports/rift-ai.md).
//!
//! ```text
//! rift-train [--bits N] [--epochs N] [--l2 X] [--seed N] --out <model.bin> --report <report.json>
//!            --suffixes <psl-ascii.txt> [--popular <hosts-file>:<n>]
//!            [--platforms <suffixes-file>]
//!            --source <name>:<malicious|benign>:<urls|hosts>:<file>[:eval] ...
//! ```
//!
//! Each source is a text file with one URL (or host) per line; blank lines
//! and lines starting with `#` or `!` are skipped. `prepare.py` makes these
//! files from the public feeds. A source marked `eval` is only measured,
//! never trained on: a feed collected by other people, at another time, is
//! the fairest test of what the model learned.
//!
//! A site is what the Public Suffix List says it is (`--suffixes`, the list
//! in ASCII as `prepare.py` writes it, both sections): `example.co.uk`, and
//! also `someone.workers.dev`, since hosting platforms list themselves as
//! suffixes. The rules ship in the model, so the app finds sites the same way.
//!
//! `--popular` names the most visited sites (the sites of the first `n`
//! hosts of a ranking). They ship in the model, which does not score them
//! (§16): a phishing form hosted on a large platform (Google Docs, Forms,
//! Drive) has the same kind of address as that platform's real pages, and
//! an earlier model learned that google.com itself looks malicious. Those
//! pages are for the threat database's exact entries. Malicious examples on
//! them are dropped; benign ones are kept, as examples of ordinary pages.
//!
//! `--platforms` lists hosting platforms (github.io, workers.dev...) the
//! benign sources sampled ordinary pages from, at most `PER_PLATFORM` each.
//! A malicious source trains on at most as many pages per platform as the
//! benign sources do (none, on a platform with no ordinary pages): the feeds
//! list tens of thousands of fakes on some platforms, and without the
//! balance the platform's name alone decided the score of its ordinary sites.
//!
//! Examples are split by site, never by URL: 80% train, 10% validation
//! (which chooses the training settings and sets the thresholds), 10% test.
//! A site is therefore only ever in one of them, and the test measures how
//! the model does on sites it has not seen. The model evaluated is the
//! quantized file that ships, read back through `UrlModel::parse`.
//!
//! Model selection: unless `--l2` fixes it, each L2 strength in `L2_GRID`
//! is trained for up to `--epochs` epochs, and the strength and epoch with
//! the best validation recall at a 0.1% false-positive rate are kept (ties
//! to the lower validation loss). Too strong a penalty or too few epochs
//! underfits; too weak or too many overfits sites it saw; the validation
//! sites decide, and the test sites play no part. The report lists every
//! setting tried and the fit on train, validation and test, so a gap
//! between them shows.
//!
//! An offline maintainer tool over files the maintainer chose: numeric loops
//! index weight tables by masked hashes, which are in range by construction.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod fm;

use std::collections::{HashMap, HashSet};
use std::process::ExitCode;
use std::time::Instant;

use rift_core::heuristics::{self, HeuristicConfig, Severity};
use rift_core::urlcanon::{self, CanonicalUrl};
use rift_core::urlmodel::{self, Factors, Level, ModelParts, Suffixes, UrlModel, View};
use serde_json::{Value, json};

/// At most this many examples per domain and source, so that a few
/// platforms with thousands of pages each do not decide the model.
const PER_GROUP: usize = 200;
/// At most this many training examples per hosting platform and malicious
/// source, and never more than the benign sources have on that platform.
const PER_PLATFORM: usize = 2_500;
/// Benign hosts given as a list are many and alike: at most this many.
const MAX_HOST_LIST: usize = 200_000;
/// Share of URL examples also trained as a host alone (the live watch sees
/// a page's HTTPS requests as hosts).
const HOST_ONLY_SHARE: u64 = 4; // one in four
/// Validation false-positive rates the two thresholds are set at: the
/// average over the benign sources, each kind of page counting the same.
const HIGH_FPR: f64 = 0.001;
const ELEVATED_FPR: f64 = 0.01;
/// A benign source with fewer scored validation pages than this does not
/// set the thresholds: its 0.1% would be its single highest score.
const MIN_THRESHOLD_SCORES: usize = 2_000;

/// The L2 strengths model selection tries, weakest first.
const L2_GRID: [f32; 5] = [0.0, 1e-4, 1e-3, 3e-3, 1e-2];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Split {
    Train,
    Validation,
    Test,
}

#[derive(Debug)]
struct Example {
    url: CanonicalUrl,
    raw: String,
    malicious: bool,
    view: View,
    source: usize,
    split: Split,
}

#[derive(Debug)]
struct Source {
    name: String,
    malicious: bool,
    hosts: bool,
    path: String,
    eval_only: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("rift-train: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut bits = 19u32;
    let mut epochs = 10usize;
    let mut fixed_l2: Option<f32> = None;
    let mut seed = 0x5eed_u64;
    let (mut out, mut report) = (None, None);
    let mut sources = Vec::new();
    let mut popular_spec = None;
    let mut suffixes_path = None;
    let mut platforms = HashSet::new();
    // Factors per feature (0: a linear model), factor table bits, factor L2.
    let mut factors = (0usize, 16u32, 0f32);
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "--bits" => bits = value()?.parse().map_err(|e| format!("--bits: {e}"))?,
            "--epochs" => epochs = value()?.parse().map_err(|e| format!("--epochs: {e}"))?,
            "--seed" => seed = value()?.parse().map_err(|e| format!("--seed: {e}"))?,
            "--l2" => fixed_l2 = Some(value()?.parse().map_err(|e| format!("--l2: {e}"))?),
            "--out" => out = Some(value()?),
            "--report" => report = Some(value()?),
            "--source" => sources.push(parse_source(&value()?)?),
            "--popular" => popular_spec = Some(value()?),
            "--factors" => {
                let v = value()?;
                let parts: Vec<&str> = v.split(',').collect();
                let [k, b, l2] = parts[..] else {
                    return Err("--factors k,factor_bits,factor_l2".into());
                };
                factors = (
                    k.parse().map_err(|e| format!("--factors: {e}"))?,
                    b.parse().map_err(|e| format!("--factors: {e}"))?,
                    l2.parse().map_err(|e| format!("--factors: {e}"))?,
                );
                if factors.0 > urlmodel::MAX_FACTORS || !urlmodel::FACTOR_BITS.contains(&factors.1)
                {
                    return Err(format!(
                        "--factors: k at most {}, factor_bits in {:?}",
                        urlmodel::MAX_FACTORS,
                        urlmodel::FACTOR_BITS
                    ));
                }
            }
            "--suffixes" => suffixes_path = Some(value()?),
            "--platforms" => {
                let path = value()?;
                platforms = std::fs::read_to_string(&path)
                    .map_err(|e| format!("{path}: {e}"))?
                    .lines()
                    .map(|l| l.trim().to_owned())
                    .filter(|l| !l.is_empty())
                    .collect();
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let out = out.ok_or("--out is required")?;
    let report_path = report.ok_or("--report is required")?;
    if !(urlmodel::MIN_BITS..=urlmodel::MAX_BITS).contains(&bits) {
        return Err(format!(
            "--bits must be {}..={}",
            urlmodel::MIN_BITS,
            urlmodel::MAX_BITS
        ));
    }

    let suffixes_path = suffixes_path.ok_or("--suffixes is required")?;
    let suffixes = Suffixes::parse(
        &std::fs::read_to_string(&suffixes_path).map_err(|e| format!("{suffixes_path}: {e}"))?,
    )
    .map_err(|e| format!("{suffixes_path}: {e}"))?;
    let popular = match &popular_spec {
        Some(spec) => read_popular(spec, &suffixes)?,
        None => HashSet::new(),
    };

    let started = Instant::now();
    let examples = load(&sources, &suffixes, &popular, &platforms)?;
    let count = |split, malicious| {
        examples
            .iter()
            .filter(|e| e.split == split && e.malicious == malicious)
            .count()
    };
    eprintln!(
        "{} examples: train {}+{}, validation {}+{}, test {}+{} (malicious+benign), {:.0?}",
        examples.len(),
        count(Split::Train, true),
        count(Split::Train, false),
        count(Split::Validation, true),
        count(Split::Validation, false),
        count(Split::Test, true),
        count(Split::Test, false),
        started.elapsed()
    );

    // Pages the model will not score (the most visited sites) take no part
    // in choosing it, as in setting its thresholds.
    let scored: Vec<bool> = examples
        .iter()
        .map(|e| !popular.contains(&group(&e.url, &suffixes)))
        .collect();
    let validation = Measure::new(&examples, &sources, &scored, Split::Validation, bits);
    let mut tried = Vec::new();
    let mut best: Option<Chosen> = None;
    for l2 in fixed_l2.map_or_else(|| L2_GRID.to_vec(), |l2| vec![l2]) {
        train(
            &examples,
            &sources,
            bits,
            factors,
            epochs,
            seed,
            l2,
            |epoch, model| {
                let (recall, loss) = validation.recall_and_loss(|f| model.score(f));
                eprintln!(
                    "  l2 {l2:e} epoch {epoch}: validation recall at 0.1% {:.2}%, loss {loss:.4}",
                    recall * 100.0
                );
                tried.push(json!({ "l2": l2, "epochs": epoch, "validation_recall_at_0.1%_fpr": recall, "validation_loss": loss }));
                let better = best.as_ref().is_none_or(|c| {
                    recall > c.recall + 1e-9 || (recall >= c.recall - 1e-9 && loss < c.loss)
                });
                if better {
                    best = Some(Chosen {
                        l2,
                        epochs: epoch,
                        recall,
                        loss,
                        model: model.clone(),
                    });
                }
            },
        );
    }
    let chosen = best.ok_or("no training examples")?;
    eprintln!(
        "chosen: l2 {:e}, {} epochs (validation recall at 0.1% {:.2}%)",
        chosen.l2,
        chosen.epochs,
        chosen.recall * 100.0
    );
    let fm::Fm {
        bias,
        weights,
        factors: factor_values,
        ..
    } = chosen.model;
    // Thresholds from the validation split, then the shipped file is made
    // and read back: everything below measures exactly that file.
    let unquantized = ModelParts {
        bits,
        bias,
        elevated: 0.5,
        high: 0.9,
        weights,
        suffixes,
        factors: (factors.0 > 0).then_some(Factors {
            k: factors.0,
            bits: factors.1,
            values: factor_values,
        }),
        popular: {
            let mut sites: Vec<String> = popular.into_iter().collect();
            sites.sort();
            sites
        },
    };
    let popular_sites = unquantized.popular.len();
    let draft = UrlModel::parse(&UrlModel::encode(&unquantized).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let (elevated, high) = thresholds(&draft, &examples, &sources);
    let parts = ModelParts {
        elevated,
        high,
        ..unquantized
    };
    let bytes = UrlModel::encode(&parts).map_err(|e| e.to_string())?;
    let model = UrlModel::parse(&bytes).map_err(|e| e.to_string())?;
    std::fs::write(&out, &bytes).map_err(|e| format!("{out}: {e}"))?;

    let mut summary = evaluate(&model, &examples, &sources);
    summary["selection"] = json!({
        "by": "validation recall at a 0.1% false-positive rate (benign validation pages pooled), ties to lower validation loss",
        "max_epochs": epochs,
        "tried": tried,
    });
    summary["fit"] = fit(&model, &examples, &sources, &scored, high);
    summary["model"] = json!({
        "file": file_name(&out),
        "bytes": bytes.len(),
        "sha256": model.digest_hex(),
        "feature_schema": urlmodel::FEATURE_SCHEMA,
        "bits": bits,
        "epochs": chosen.epochs,
        "l2": chosen.l2,
        "factors": (factors.0 > 0).then(|| json!({ "k": factors.0, "bits": factors.1, "l2": factors.2 })),
        "seed": seed,
        "thresholds": { "elevated": elevated, "high": high },
        "popular_sites_not_scored": popular_sites,
        "popular_from": popular_spec.as_deref().map(file_name),
    });
    summary["sources"] = Value::Array(
        sources
            .iter()
            .map(|s| json!({ "name": s.name, "label": if s.malicious { "malicious" } else { "benign" }, "kind": if s.hosts { "hosts" } else { "urls" }, "eval_only": s.eval_only }))
            .collect(),
    );
    let text = serde_json::to_string_pretty(&summary).map_err(|e| e.to_string())?;
    std::fs::write(&report_path, &text).map_err(|e| format!("{report_path}: {e}"))?;
    println!("{text}");
    eprintln!("done in {:.0?}", started.elapsed());
    Ok(())
}

/// A path's last part: reports name the files, not where they were.
fn file_name(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .map_or_else(|| path.to_owned(), |n| n.to_string_lossy().into_owned())
}

fn parse_source(spec: &str) -> Result<Source, String> {
    let parts: Vec<&str> = spec.split(':').collect();
    let (name, label, kind, path, eval_only) = match parts.as_slice() {
        [n, l, k, p] => (*n, *l, *k, *p, false),
        [n, l, k, p, "eval"] => (*n, *l, *k, *p, true),
        _ => {
            return Err(format!(
                "--source {spec}: expected name:label:kind:file[:eval]"
            ));
        }
    };
    let malicious = match label {
        "malicious" => true,
        "benign" => false,
        _ => {
            return Err(format!(
                "--source {spec}: label must be malicious or benign"
            ));
        }
    };
    let hosts = match kind {
        "urls" => false,
        "hosts" => true,
        _ => return Err(format!("--source {spec}: kind must be urls or hosts")),
    };
    Ok(Source {
        name: name.to_owned(),
        malicious,
        hosts,
        path: path.to_owned(),
        eval_only,
    })
}

/// The site a URL is on; an IP address is its own.
fn group(url: &CanonicalUrl, suffixes: &Suffixes) -> String {
    let host = url.host().trim_end_matches('.');
    if url.host_is_ip() {
        host.to_owned()
    } else {
        suffixes.site(host)
    }
}

/// The listed hosting platform `host` is under, if any.
fn platform_of<'a>(host: &str, platforms: &'a HashSet<String>) -> Option<&'a str> {
    let mut rest = host.trim_end_matches('.');
    while let Some((_, parent)) = rest.split_once('.') {
        if let Some(p) = platforms.get(parent) {
            return Some(p.as_str());
        }
        rest = parent;
    }
    None
}

fn fnv(text: &str, seed: u64) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64 ^ seed;
    for b in text.bytes() {
        h = (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    h ^ (h >> 29)
}

fn split_of(group: &str) -> Split {
    // Fixed (not seeded): the same domain is in the same split in every run.
    match fnv(group, 0) % 10 {
        0 => Split::Test,
        1 => Split::Validation,
        _ => Split::Train,
    }
}

fn read_popular(spec: &str, suffixes: &Suffixes) -> Result<HashSet<String>, String> {
    let (path, n) = spec
        .rsplit_once(':')
        .ok_or("--popular: expected <file>:<n>")?;
    let n: usize = n.parse().map_err(|e| format!("--popular: {e}"))?;
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let mut groups = HashSet::new();
    for host in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .take(n)
    {
        if let Ok(url) = urlcanon::canonicalize(format!("http://{host}/").as_bytes()) {
            groups.insert(group(&url, suffixes));
        }
    }
    eprintln!("popular: {} sites", groups.len());
    Ok(groups)
}

fn load(
    sources: &[Source],
    suffixes: &Suffixes,
    popular: &HashSet<String>,
    platforms: &HashSet<String>,
) -> Result<Vec<Example>, String> {
    let mut examples = Vec::new();
    let mut seen: HashSet<(String, bool)> = HashSet::new();
    // Hosts some benign source has pages on: a malicious URL there is not
    // also trained as "this host is malicious" (a phishing page on a large
    // platform does not make the platform malicious).
    let mut benign_hosts: HashSet<String> = HashSet::new();
    // Benign training pages per platform, which bound the malicious ones.
    let mut benign_on_platform: HashMap<&str, usize> = HashMap::new();
    for pass_benign in [true, false] {
        for (index, source) in sources.iter().enumerate() {
            if source.malicious == pass_benign {
                continue;
            }
            let text = std::fs::read_to_string(&source.path)
                .map_err(|e| format!("{}: {e}", source.path))?;
            let mut per_group: HashMap<String, usize> = HashMap::new();
            let mut per_platform: HashMap<&str, usize> = HashMap::new();
            let (mut kept, mut skipped, mut on_popular) = (0usize, 0usize, 0usize);
            let mut over_platform = 0usize;
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
                    continue;
                }
                if source.hosts && kept >= MAX_HOST_LIST && !source.malicious {
                    break;
                }
                let raw = if source.hosts {
                    format!("http://{line}/")
                } else {
                    line.to_owned()
                };
                if !raw.starts_with("http://") && !raw.starts_with("https://") {
                    skipped += 1;
                    continue;
                }
                let Ok(url) = urlcanon::canonicalize(raw.as_bytes()) else {
                    skipped += 1;
                    continue;
                };
                let key = format!("{}{}", url.host(), url.path());
                if !seen.insert((key, source.malicious)) {
                    continue;
                }
                let g = group(&url, suffixes);
                if source.malicious && popular.contains(&g) {
                    on_popular += 1;
                    continue;
                }
                if *per_group.get(&g).unwrap_or(&0) >= PER_GROUP {
                    continue;
                }
                let split = if source.eval_only {
                    Split::Test
                } else {
                    split_of(&g)
                };
                // Training only: validation and test keep every listed page.
                if source.malicious
                    && split == Split::Train
                    && let Some(platform) = platform_of(url.host(), platforms)
                {
                    let cap =
                        PER_PLATFORM.min(benign_on_platform.get(platform).copied().unwrap_or(0));
                    let n = per_platform.entry(platform).or_insert(0);
                    if *n >= cap {
                        over_platform += 1;
                        continue;
                    }
                    *n += 1;
                }
                if !source.malicious
                    && split == Split::Train
                    && let Some(platform) = platform_of(url.host(), platforms)
                {
                    *benign_on_platform.entry(platform).or_insert(0) += 1;
                }
                *per_group.entry(g.clone()).or_insert(0) += 1;
                if !source.malicious {
                    benign_hosts.insert(url.host().to_owned());
                }
                let host_only = source.hosts
                    || fnv(&raw, 7).is_multiple_of(HOST_ONLY_SHARE)
                        && (!source.malicious || !benign_hosts.contains(url.host()));
                if host_only {
                    examples.push(Example {
                        url: url.clone(),
                        raw: raw.clone(),
                        malicious: source.malicious,
                        view: View::HostOnly,
                        source: index,
                        split,
                    });
                }
                examples.push(Example {
                    url,
                    raw,
                    malicious: source.malicious,
                    view: View::Address,
                    source: index,
                    split,
                });
                kept += 1;
            }
            eprintln!(
                "{}: {kept} kept, {skipped} not http(s) or not a URL, {on_popular} on popular sites and {over_platform} over a platform's share dropped",
                source.name
            );
        }
    }
    Ok(examples)
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// The setting model selection kept, with its weights.
struct Chosen {
    l2: f32,
    epochs: usize,
    recall: f64,
    loss: f64,
    model: fm::Fm,
}

/// Logistic regression, with factors if `factors.0` > 0, by AdaGrad,
/// classes weighted to count equally; `after_epoch` sees the model after
/// each epoch.
#[allow(clippy::too_many_arguments)]
fn train(
    examples: &[Example],
    sources: &[Source],
    bits: u32,
    (k, factor_bits, factor_l2): (usize, u32, f32),
    epochs: usize,
    seed: u64,
    l2: f32,
    mut after_epoch: impl FnMut(usize, &fm::Fm),
) {
    let mut model = fm::Fm::new(bits, factor_bits, k, seed);
    let mut state = model.trainer();
    let mut order: Vec<usize> = (0..examples.len())
        .filter(|&i| examples[i].split == Split::Train && !sources[examples[i].source].eval_only)
        .collect();
    let positives = order
        .iter()
        .filter(|&&i| examples[i].malicious)
        .count()
        .max(1) as f32;
    let negatives = (order.len() as f32 - positives).max(1.0);
    let total = positives + negatives;
    let (weight_pos, weight_neg) = (total / (2.0 * positives), total / (2.0 * negatives));
    let mut rng = Rng(seed | 1);
    let mut features: Vec<(usize, f32)> = Vec::with_capacity(512);
    for epoch in 0..epochs {
        for i in (1..order.len()).rev() {
            let j = (rng.next() % (i as u64 + 1)) as usize;
            order.swap(i, j);
        }
        let mut loss = 0f64;
        for &i in &order {
            let e = &examples[i];
            features.clear();
            urlmodel::for_each_feature(&e.url, e.view, |f| {
                let (index, sign) = f.bucket(bits);
                features.push((index, sign * f.value));
            });
            let cw = if e.malicious { weight_pos } else { weight_neg };
            loss += f64::from(model.step(&mut state, &features, e.malicious, cw, l2, factor_l2));
        }
        eprintln!(
            "l2 {l2:e} epoch {}: training loss {:.4}",
            epoch + 1,
            loss / order.len().max(1) as f64
        );
        after_epoch(epoch + 1, &model);
    }
}

/// One split's scored address-view examples, their features worked out
/// once, for measuring weights during model selection.
struct Measure {
    examples: Vec<(Vec<(usize, f32)>, bool)>,
    weight_pos: f64,
    weight_neg: f64,
}

impl Measure {
    fn new(
        examples: &[Example],
        sources: &[Source],
        scored: &[bool],
        split: Split,
        bits: u32,
    ) -> Self {
        let examples: Vec<(Vec<(usize, f32)>, bool)> = examples
            .iter()
            .zip(scored)
            .filter(|(e, scored)| {
                **scored
                    && e.split == split
                    && e.view == View::Address
                    && !sources[e.source].eval_only
            })
            .map(|(e, _)| {
                let mut features = Vec::new();
                urlmodel::for_each_feature(&e.url, e.view, |f| {
                    let (index, sign) = f.bucket(bits);
                    features.push((index, sign * f.value));
                });
                (features, e.malicious)
            })
            .collect();
        let positives = examples.iter().filter(|e| e.1).count().max(1) as f64;
        let negatives = (examples.len() as f64 - positives).max(1.0);
        let total = positives + negatives;
        Self {
            examples,
            weight_pos: total / (2.0 * positives),
            weight_neg: total / (2.0 * negatives),
        }
    }

    /// The share of malicious pages above the score that 0.1% of benign
    /// pages reach, and the class-weighted log loss.
    fn recall_and_loss(&self, score: impl Fn(&[(usize, f32)]) -> f32) -> (f64, f64) {
        let mut benign = Vec::new();
        let mut malicious = Vec::new();
        let mut loss = 0f64;
        for (features, is_malicious) in &self.examples {
            let p = score(features);
            if *is_malicious {
                loss -= self.weight_pos * f64::from(p.max(1e-7).ln());
                malicious.push(p);
            } else {
                loss -= self.weight_neg * f64::from((1.0 - p).max(1e-7).ln());
                benign.push(p);
            }
        }
        benign.sort_by(f32::total_cmp);
        let k = ((benign.len() as f64) * (1.0 - HIGH_FPR)).ceil() as usize;
        let threshold = benign
            .get(k.min(benign.len().saturating_sub(1)))
            .copied()
            .unwrap_or(1.0);
        let caught = malicious.iter().filter(|&&p| p > threshold).count();
        (
            caught as f64 / malicious.len().max(1) as f64,
            loss / self.examples.len().max(1) as f64,
        )
    }
}

/// How the shipped model fits each split of the trained sources (address
/// view, scored pages): log loss, malicious pages at High, and benign pages
/// at High. Close numbers on train and test mean it neither memorised the
/// sites it saw nor missed what they share.
fn fit(
    model: &UrlModel,
    examples: &[Example],
    sources: &[Source],
    scored: &[bool],
    high: f32,
) -> Value {
    let mut out = serde_json::Map::new();
    for (name, split) in [
        ("train", Split::Train),
        ("validation", Split::Validation),
        ("test", Split::Test),
    ] {
        let (mut loss, mut n) = (0f64, 0usize);
        let (mut caught, mut malicious, mut flagged, mut benign) = (0usize, 0usize, 0usize, 0usize);
        for (e, _) in examples.iter().zip(scored).filter(|(e, scored)| {
            **scored && e.split == split && e.view == View::Address && !sources[e.source].eval_only
        }) {
            let score = model.assess(&e.url, e.view).score;
            n += 1;
            if e.malicious {
                loss -= f64::from(score.max(1e-7).ln());
                malicious += 1;
                caught += usize::from(score >= high);
            } else {
                loss -= f64::from((1.0 - score).max(1e-7).ln());
                benign += 1;
                flagged += usize::from(score >= high);
            }
        }
        let row = json!({
            "n": n,
            "log_loss": loss / n.max(1) as f64,
            "malicious_at_high": caught as f64 / malicious.max(1) as f64,
            "benign_at_high": flagged as f64 / benign.max(1) as f64,
        });
        eprintln!("fit {name:<10} {row}");
        out.insert(name.to_owned(), row);
    }
    Value::Object(out)
}

/// Thresholds at the validation false-positive rates (averaged over the
/// benign sources); at least 0.5 and 0.9 so the levels keep their meaning
/// on a model that separates very well.
fn thresholds(model: &UrlModel, examples: &[Example], sources: &[Source]) -> (f32, f32) {
    let mut per_source: HashMap<usize, Vec<f32>> = HashMap::new();
    // Pages the model does not score (the most visited sites) would only
    // make the rates look better than they are on the pages it does.
    for e in examples
        .iter()
        .filter(|e| e.split == Split::Validation && !e.malicious && e.view == View::Address)
    {
        let a = model.assess(&e.url, e.view);
        if !a.abstained {
            per_source.entry(e.source).or_default().push(a.score);
        }
    }
    for scores in per_source.values_mut() {
        scores.sort_by(f32::total_cmp);
    }
    let quantile = |scores: &[f32], fpr: f64| {
        let k = ((scores.len() as f64) * (1.0 - fpr)).ceil() as usize;
        scores
            .get(k.min(scores.len().saturating_sub(1)))
            .copied()
            .unwrap_or(0.5)
    };
    let counted: Vec<&Vec<f32>> = per_source
        .values()
        .filter(|scores| scores.len() >= MIN_THRESHOLD_SCORES)
        .collect();
    let mean_rate = |t: f32| {
        counted
            .iter()
            .map(|s| (s.len() - s.partition_point(|&x| x <= t)) as f64 / s.len() as f64)
            .sum::<f64>()
            / counted.len().max(1) as f64
    };
    // The rate falls as the threshold rises: bisect for the lowest
    // threshold at or under the target.
    let at = |fpr: f64| {
        let (mut lo, mut hi) = (0f32, 1f32);
        for _ in 0..40 {
            let mid = (lo + hi) / 2.0;
            if mean_rate(mid) <= fpr {
                hi = mid;
            } else {
                lo = mid;
            }
        }
        hi
    };
    let high = at(HIGH_FPR).clamp(0.9, 0.995);
    let elevated = at(ELEVATED_FPR).clamp(0.5, high);
    for (index, scores) in &per_source {
        eprintln!(
            "validation benign {:<16} {:>6} scored, at 0.1% {:.4}, at 1% {:.4}{}",
            sources[*index].name,
            scores.len(),
            quantile(scores, HIGH_FPR),
            quantile(scores, ELEVATED_FPR),
            if scores.len() < MIN_THRESHOLD_SCORES {
                " (too few to set thresholds)"
            } else {
                ""
            }
        );
    }
    (elevated, high)
}

fn evaluate(model: &UrlModel, examples: &[Example], sources: &[Source]) -> Value {
    let heuristics_config = HeuristicConfig::default();
    let mut rows = Vec::new();
    let mut timings = Vec::new();
    for (index, source) in sources.iter().enumerate() {
        for view in [View::Address, View::HostOnly] {
            let mut scores = Vec::new();
            let mut abstained = 0usize;
            let mut heuristic_warned = 0usize;
            for e in examples
                .iter()
                .filter(|e| e.split == Split::Test && e.source == index && e.view == view)
            {
                let started = Instant::now();
                let a = model.assess(&e.url, e.view);
                timings.push(started.elapsed().as_nanos() as f64 / 1000.0);
                scores.push(a.level);
                abstained += usize::from(a.abstained);
                if view == View::Address
                    && heuristics::assess(e.raw.as_bytes(), &e.url, &heuristics_config)
                        .iter()
                        .any(|f| f.severity() == Severity::Warn)
                {
                    heuristic_warned += 1;
                }
            }
            if scores.is_empty() {
                continue;
            }
            let n = scores.len() as f64;
            let high = scores.iter().filter(|l| **l == Level::High).count() as f64 / n;
            let flagged = scores.iter().filter(|l| **l >= Level::Elevated).count() as f64 / n;
            let rate = if source.malicious {
                "caught"
            } else {
                "falsely flagged"
            };
            eprintln!(
                "test {:<16} {:<8} n={:<7} {rate}: high {:.2}%  elevated-or-high {:.2}%  not scored {:.2}%",
                source.name,
                if view == View::Address {
                    "address"
                } else {
                    "host"
                },
                scores.len(),
                high * 100.0,
                flagged * 100.0,
                abstained as f64 / n * 100.0
            );
            rows.push(json!({
                "source": source.name,
                "label": if source.malicious { "malicious" } else { "benign" },
                "view": if view == View::Address { "address" } else { "host only" },
                "eval_only": source.eval_only,
                "n": scores.len(),
                "high_rate": high,
                "elevated_or_high_rate": flagged,
                "not_scored_rate": abstained as f64 / n,
                "heuristics_warn_rate": if view == View::Address { json!(heuristic_warned as f64 / n) } else { Value::Null },
            }));
        }
    }
    // Sites that were in the feeds (the training split): what the model
    // does for a link on a site it learned, which is most of what a feed
    // lists on any one day.
    let mut seen = Vec::new();
    for (index, source) in sources.iter().enumerate().filter(|(_, s)| !s.eval_only) {
        let levels: Vec<Level> = examples
            .iter()
            .filter(|e| e.split == Split::Train && e.source == index && e.view == View::Address)
            .map(|e| model.assess(&e.url, e.view).level)
            .collect();
        let n = levels.len().max(1) as f64;
        let high = levels.iter().filter(|l| **l == Level::High).count() as f64 / n;
        let flagged = levels.iter().filter(|l| **l >= Level::Elevated).count() as f64 / n;
        eprintln!(
            "seen {:<16} address  n={:<7} high {:.2}%  elevated-or-high {:.2}%",
            source.name,
            levels.len(),
            high * 100.0,
            flagged * 100.0
        );
        seen.push(json!({ "source": source.name, "n": levels.len(), "high_rate": high, "elevated_or_high_rate": flagged }));
    }
    let auc = auc(model, examples, sources);
    timings.sort_by(f64::total_cmp);
    let pct = |p: f64| {
        timings
            .get(((timings.len() as f64) * p) as usize)
            .copied()
            .unwrap_or(0.0)
    };
    eprintln!(
        "test AUC (trained sources, address view): {auc:.4}; scoring p50 {:.1} us, p95 {:.1} us",
        pct(0.5),
        pct(0.95)
    );
    json!({
        "split": "by site (Public Suffix List): 80% train, 10% validation, 10% test; eval-only sources are all test",
        "test": rows,
        "seen_sites_address_view": seen,
        "auc_trained_sources_address_view": auc,
        "scoring_microseconds_on_this_machine": { "p50": pct(0.5), "p95": pct(0.95), "max": timings.last().copied().unwrap_or(0.0) },
    })
}

/// Area under the ROC curve on the test split of the trained sources.
fn auc(model: &UrlModel, examples: &[Example], sources: &[Source]) -> f64 {
    let mut scored: Vec<(f32, bool)> = examples
        .iter()
        .filter(|e| {
            e.split == Split::Test && e.view == View::Address && !sources[e.source].eval_only
        })
        .map(|e| (model.assess(&e.url, e.view).score, e.malicious))
        .collect();
    scored.sort_by(|a, b| a.0.total_cmp(&b.0));
    let positives = scored.iter().filter(|s| s.1).count() as f64;
    let negatives = scored.len() as f64 - positives;
    if positives == 0.0 || negatives == 0.0 {
        return f64::NAN;
    }
    // Rank sum, ties counted as half.
    let (mut rank_sum, mut i) = (0f64, 0usize);
    while i < scored.len() {
        let mut j = i;
        while j < scored.len() && scored[j].0 == scored[i].0 {
            j += 1;
        }
        let average_rank = (i + j + 1) as f64 / 2.0;
        rank_sum += average_rank * scored[i..j].iter().filter(|s| s.1).count() as f64;
        i = j;
    }
    (rank_sum - positives * (positives + 1.0) / 2.0) / (positives * negatives)
}
