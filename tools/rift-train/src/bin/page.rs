//! Trains Rift AI's page model (docs/architecture.md §16.1) on saved pages.
//!
//!   page <index.sql> <pages-dir> <out-model> [--limit N]
//!
//! The data is the Phishing Websites Dataset (Ariyadasa, Fernando and
//! Fernando, Mendeley Data, 2021, CC BY 4.0): an `index.sql` naming each
//! page's URL, file and label (1 phishing, 0 legitimate), and the pages'
//! HTML. Each page is counted here as the browser's script counts it in a
//! live page (`PAGE_COUNTS` in BrowserActivity.kt), and turned into features
//! by `rift_core::pagemodel::features`, the code the app runs.
//!
//! Splits are by site (80/10/10), so the test measures sites the model never
//! saw. The L2 strength is chosen on validation, thresholds are set there
//! (High at 0.5% of legitimate pages, Elevated at 2%), and the test split is
//! used once, for the figures printed at the end.
//!
//! An offline maintainer tool over files the maintainer chose.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::process::ExitCode;

use rift_core::pagemodel::{self, FEATURES, PageCounts, site_key};
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
    let n = data.len() as f32;
    for t in 1..=epochs {
        let mut g = vec![0.0f32; d + 1];
        for ex in data {
            let mut z = w[d];
            for j in 0..d {
                z += w[j] * (ex.x[j] - mean[j]) / std[j];
            }
            let err = sigmoid(z) - ex.y;
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

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: page <index.sql> <pages-dir> <out-model> [--limit N]");
        return ExitCode::FAILURE;
    }
    let limit = args
        .iter()
        .position(|a| a == "--limit")
        .and_then(|i| args.get(i + 1))
        .and_then(|n| n.parse::<usize>().ok())
        .unwrap_or(usize::MAX);
    let sql = match fs::read(&args[1]) {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(e) => {
            eprintln!("page: {}: {e}", args[1]);
            return ExitCode::FAILURE;
        }
    };
    let dir = Path::new(&args[2]);
    let mut splits: [Vec<Example>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    let (mut read, mut missing) = (0usize, 0usize);
    for row in rows(&sql).into_iter().take(limit) {
        let Ok(url) = Url::parse(row.url.trim()) else {
            continue;
        };
        let Some(host) = url.host_str().map(str::to_owned) else {
            continue;
        };
        let Ok(bytes) = fs::read(dir.join(&row.file)) else {
            missing += 1;
            continue;
        };
        let bytes = &bytes[..bytes.len().min(MAX_HTML_BYTES)];
        let html = String::from_utf8_lossy(bytes);
        let counts = count(&url, &html);
        let x = pagemodel::features(&host, &counts);
        let split = match split_of(&site_key(&host)) {
            0..=7 => 0,
            8 => 1,
            _ => 2,
        };
        splits[split].push(Example {
            x,
            y: if row.phishing { 1.0 } else { 0.0 },
        });
        read += 1;
        if read % 5000 == 0 {
            eprintln!("page: {read} pages counted");
        }
    }
    let [train_set, valid, test] = &splits;
    eprintln!(
        "page: {read} pages ({missing} files missing): train {}, validation {}, test {}",
        train_set.len(),
        valid.len(),
        test.len()
    );
    let d = FEATURES.len();
    let n = train_set.len().max(1) as f32;
    let mean: Vec<f32> = (0..d)
        .map(|j| train_set.iter().map(|e| e.x[j]).sum::<f32>() / n)
        .collect();
    let std: Vec<f32> = (0..d)
        .map(|j| {
            let var = train_set
                .iter()
                .map(|e| (e.x[j] - mean[j]).powi(2))
                .sum::<f32>()
                / n;
            var.sqrt().max(1e-3)
        })
        .collect();
    let mut best: Option<(f64, f32, Vec<f32>)> = None;
    for l2 in [0.0f32, 1e-4, 1e-3, 1e-2] {
        let w = train(train_set, &mean, &std, l2, 400);
        let (raw, bias) = fold(&w, &mean, &std);
        let s = scores(valid, &raw, bias);
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
    let s = scores(valid, &raw, bias);
    let high = threshold(&s, 0.005);
    let elevated = threshold(&s, 0.02).min(high);
    let t = scores(test, &raw, bias);
    let (tp_h, fp_h) = rates(&t, high);
    let (tp_e, fp_e) = rates(&t, elevated);
    let summary = format!(
        "test (sites never seen): {} pages, AUC {:.4}; High: {:.1}% of phishing, {:.2}% of legitimate; Elevated or High: {:.1}% of phishing, {:.2}% of legitimate",
        test.len(),
        auc(&t),
        tp_h * 100.0,
        fp_h * 100.0,
        tp_e * 100.0,
        fp_e * 100.0
    );
    println!("{summary}");
    // Means of legitimate training pages: what the reasons compare against.
    let legit: Vec<&Example> = train_set.iter().filter(|e| e.y < 0.5).collect();
    let ln = legit.len().max(1) as f32;
    let mut out = format!(
        "# Rift AI page model (docs/architecture.md §16.1), written by tools/rift-train page.\n\
         # Data: Phishing Websites Dataset, Ariyadasa, Fernando and Fernando, Mendeley Data 2021, CC BY 4.0\n\
         # (doi:10.17632/n96ncsr5g4.1). {read} pages; split by site 80/10/10; l2 {l2}.\n\
         # {summary}\n\
         bias {bias}\nhigh {high}\nelevated {elevated}\n"
    );
    for (j, name) in FEATURES.iter().enumerate() {
        let m = legit.iter().map(|e| e.x[j]).sum::<f32>() / ln;
        out.push_str(&format!("feature {name} {} {m}\n", raw[j]));
    }
    if let Err(e) = fs::write(&args[3], out) {
        eprintln!("page: {}: {e}", args[3]);
        return ExitCode::FAILURE;
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
