//! Rift AI's page model (docs/architecture.md §16.1): logistic regression
//! over what a loaded page is made of (its forms, links, scripts and words),
//! plus boosted trees over the counts (3.3), to warn about a phishing page
//! before anything is typed into it.
//!
//! The counts come from a script in the page ([`PageCounts`], read by the
//! browser) and the page can change them, so the model can only add a
//! warning, never clear one. Training (`tools/rift-train`, `page` binary)
//! counts the same things in saved pages and calls [`features`] here, so the
//! two cannot disagree about what a feature is.

use serde::{Deserialize, Serialize};

use crate::text::escape_for_display;

/// The longest text sample read; the rest is ignored.
pub const MAX_TEXT_CHARS: usize = 2000;
/// The longest report the browser may send, in bytes of JSON.
pub const MAX_REPORT_BYTES: usize = 8 * 1024;
const MAX_COUNT: u32 = 100_000;

/// What the page script counts. Field names are the script's JSON keys.
/// "Another site" is decided by [`site_key`], in the script as here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct PageCounts {
    /// Password inputs.
    pub pw: u32,
    /// Forms; those whose action is another site's; empty, `#`, `javascript:`
    /// or `about:blank`; `mailto:`; ending in `.php`.
    pub fm: u32,
    pub fx: u32,
    pub fnull: u32,
    pub fmail: u32,
    pub fphp: u32,
    /// Hidden inputs.
    pub hi: u32,
    /// Links (`a[href]`); to another site; going nowhere (`#…`, `javascript:`, empty).
    pub a: u32,
    pub ax: u32,
    pub an: u32,
    /// Resources (`img`, `script`, `iframe`, `link` with an address); from another site.
    pub r: u32,
    pub rx: u32,
    /// The icon comes from another site.
    pub fv: u32,
    /// Frames; frames marked invisible (zero size, `display:none`, `visibility:hidden`).
    pub ifr: u32,
    pub ih: u32,
    /// Scripts; from another site.
    pub sc: u32,
    pub sx: u32,
    /// `eval(`, `atob(`, `unescape(`, `fromCharCode`, `document.write(` in inline scripts.
    pub ob: u32,
    /// A `<meta http-equiv=refresh>`.
    pub mr: u32,
    /// The context menu is blocked (`oncontextmenu`, or `event.button==2` in a script).
    pub rc: u32,
    /// Characters of HTML and elements in the document.
    pub hb: u32,
    pub el: u32,
    /// A ©, ® or ™ sign in the text.
    pub cp: u32,
    /// The document's title.
    pub title: String,
    /// The start of the page's visible text.
    pub text: String,
}

impl PageCounts {
    /// Parses the browser's report; None if it is too long or malformed.
    /// Counts are capped and texts cut, so nothing here is unbounded.
    pub fn from_report(json: &str) -> Option<Self> {
        if json.len() > MAX_REPORT_BYTES {
            return None;
        }
        let mut counts: Self = serde_json::from_str(json).ok()?;
        counts.bound();
        Some(counts)
    }

    pub fn bound(&mut self) {
        for count in [
            &mut self.pw,
            &mut self.fm,
            &mut self.fx,
            &mut self.fnull,
            &mut self.fmail,
            &mut self.fphp,
            &mut self.hi,
            &mut self.a,
            &mut self.ax,
            &mut self.an,
            &mut self.r,
            &mut self.rx,
            &mut self.fv,
            &mut self.ifr,
            &mut self.ih,
            &mut self.sc,
            &mut self.sx,
            &mut self.ob,
            &mut self.mr,
            &mut self.rc,
            &mut self.el,
            &mut self.cp,
        ] {
            *count = (*count).min(MAX_COUNT);
        }
        self.hb = self.hb.min(100 * MAX_COUNT);
        self.title = self.title.chars().take(256).collect();
        self.text = self.text.chars().take(MAX_TEXT_CHARS).collect();
    }
}

/// The part of a host that decides "the same site", without the Public
/// Suffix List (the page script has none): the last two labels, or three
/// when the last is a two-letter country code under a short second level
/// (`co.uk`, `com.au`). `www.` is ignored.
pub fn site_key(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    let n = labels.len();
    let keep = match labels.as_slice() {
        [.., second, last] if n >= 3 && last.len() == 2 && second.len() <= 3 => 3,
        _ => 2,
    };
    labels
        .get(n.saturating_sub(keep)..)
        .unwrap_or(&labels)
        .join(".")
}

/// Brands phishing pages most often copy (looked for as whole words).
const BRANDS: &[&str] = &[
    "paypal",
    "microsoft",
    "office 365",
    "outlook",
    "onedrive",
    "sharepoint",
    "apple",
    "icloud",
    "amazon",
    "netflix",
    "facebook",
    "instagram",
    "whatsapp",
    "google",
    "gmail",
    "dhl",
    "fedex",
    "usps",
    "ups",
    "chase",
    "wells fargo",
    "bank of america",
    "citibank",
    "hsbc",
    "coinbase",
    "binance",
    "metamask",
    "trust wallet",
    "adobe",
    "docusign",
    "dropbox",
    "linkedin",
    "steam",
    "roblox",
    "spotify",
    "yahoo",
    "aol",
    "att",
    "verizon",
    "ebay",
    "walmart",
    "irs",
    "hmrc",
];

const CREDENTIAL_WORDS: &[&str] = &[
    "password",
    "passcode",
    "sign in",
    "log in",
    "login",
    "verify",
    "verification",
    "account",
    "social security",
    "card number",
    "cvv",
    "expiry",
    "expiration",
    "pin",
    "seed phrase",
    "recovery phrase",
    "private key",
    "wallet",
    "one-time",
    "otp",
    "billing",
];

const URGENCY_WORDS: &[&str] = &[
    "suspend",
    "locked",
    "unusual",
    "unauthorized",
    "unauthorised",
    "immediately",
    "within 24",
    "24 hours",
    "48 hours",
    "expire",
    "confirm your",
    "update your",
    "limited",
    "restricted",
    "verify your",
    "security alert",
    "action required",
    "failed delivery",
    "has been disabled",
];

/// The model's inputs, in a fixed order; the model file names each one.
pub const FEATURES: &[&str] = &[
    "has_password",
    "passwords_log",
    "forms_log",
    "form_other_site_ratio",
    "form_nowhere",
    "form_mailto",
    "form_php",
    "password_to_other_site",
    "hidden_inputs_log",
    "links_log",
    "no_links",
    "link_other_site_ratio",
    "link_nowhere_ratio",
    "resource_other_site_ratio",
    "icon_other_site",
    "frames_log",
    "frame_hidden",
    "scripts_log",
    "script_other_site_ratio",
    "obfuscation_log",
    "meta_refresh",
    "context_menu_blocked",
    "html_log",
    "elements_log",
    "copyright",
    "title_empty",
    "site_in_title",
    "site_in_text",
    "brand_elsewhere",
    "brands_elsewhere_log",
    "credential_words_log",
    "urgency_words_log",
    "text_log",
];

fn ln1p(x: u32) -> f32 {
    (f64::from(x)).ln_1p() as f32
}

fn ratio(part: u32, whole: u32) -> f32 {
    if whole == 0 {
        0.0
    } else {
        (f64::from(part.min(whole)) / f64::from(whole)) as f32
    }
}

fn flag(on: bool) -> f32 {
    if on { 1.0 } else { 0.0 }
}

/// Distinct terms of `terms` found in `text` as whole words.
fn count_terms(text: &str, terms: &[&str]) -> u32 {
    let found = terms
        .iter()
        .filter(|t| crate::page::names_word(text, t))
        .count();
    u32::try_from(found).unwrap_or(u32::MAX)
}

/// The feature vector, in [`FEATURES`]' order, for a page on `host`.
pub fn features(host: &str, counts: &PageCounts) -> Vec<f32> {
    let title = counts.title.to_lowercase();
    let text = counts.text.to_lowercase();
    let both = format!("{title} {text}");
    let site = site_key(host);
    let label = site.split('.').next().unwrap_or_default().to_owned();
    let elsewhere = BRANDS
        .iter()
        .filter(|brand| {
            let squashed: String = brand.chars().filter(|c| !c.is_whitespace()).collect();
            !host.contains(&squashed) && crate::page::names_word(&both, brand)
        })
        .count();
    let elsewhere = u32::try_from(elsewhere).unwrap_or(u32::MAX);
    let has_label = label.chars().count() >= 3;
    vec![
        flag(counts.pw > 0),
        ln1p(counts.pw),
        ln1p(counts.fm),
        ratio(counts.fx, counts.fm),
        flag(counts.fnull > 0),
        flag(counts.fmail > 0),
        flag(counts.fphp > 0),
        flag(counts.pw > 0 && counts.fx > 0),
        ln1p(counts.hi),
        ln1p(counts.a),
        flag(counts.a == 0),
        ratio(counts.ax, counts.a),
        ratio(counts.an, counts.a),
        ratio(counts.rx, counts.r),
        flag(counts.fv > 0),
        ln1p(counts.ifr),
        flag(counts.ih > 0),
        ln1p(counts.sc),
        ratio(counts.sx, counts.sc),
        ln1p(counts.ob),
        flag(counts.mr > 0),
        flag(counts.rc > 0),
        ln1p(counts.hb),
        ln1p(counts.el),
        flag(counts.cp > 0),
        flag(title.trim().is_empty()),
        flag(has_label && title.contains(&label)),
        flag(has_label && text.contains(&label)),
        flag(elsewhere > 0),
        ln1p(elsewhere),
        ln1p(count_terms(&both, CREDENTIAL_WORDS)),
        ln1p(count_terms(&both, URGENCY_WORDS)),
        ln1p(u32::try_from(text.chars().count()).unwrap_or(u32::MAX)),
    ]
}

/// Most distinct words read from a page, and the longest word.
const MAX_PAGE_WORDS: usize = 400;
const MAX_WORD_CHARS: usize = 32;

/// The distinct words of the page's title and text, lower-cased, of two to
/// [`MAX_WORD_CHARS`] letters or digits, sorted: what a model's `word` lines
/// are looked up in.
pub fn words(counts: &PageCounts) -> Vec<String> {
    // Lower-cased before splitting: lower-casing can add a mark that is not
    // a letter (İ becomes i and a combining dot), which then splits there.
    let both = format!("{} {}", counts.title, counts.text).to_lowercase();
    let mut found: Vec<String> = both
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| (2..=MAX_WORD_CHARS).contains(&w.chars().count()) && w.to_lowercase() == *w)
        .map(str::to_owned)
        .collect();
    found.sort_unstable();
    found.dedup();
    found.truncate(MAX_PAGE_WORDS);
    found
}

/// What a feature that raised the score says about the page.
fn reason(feature: &str) -> Option<&'static str> {
    Some(match feature {
        "has_password" | "passwords_log" => "it asks for a password",
        "form_other_site_ratio" => "its form sends what you type to another site",
        "password_to_other_site" => "its password form sends to another site",
        "form_nowhere" => "its form has no real destination (scripts send it)",
        "form_mailto" => "its form sends what you type by email",
        "form_php" => "its form posts to a bare PHP script, as phishing kits do",
        "hidden_inputs_log" => "it carries many hidden form fields",
        "no_links" => "it has no links to the rest of a site",
        "link_nowhere_ratio" => "most of its links go nowhere",
        "link_other_site_ratio" => "most of its links lead to another site",
        "resource_other_site_ratio" => "its images and scripts come from another site",
        "icon_other_site" => "its icon is taken from another site",
        "frame_hidden" => "it has an invisible frame",
        "obfuscation_log" => "its scripts hide what they do (eval, atob, fromCharCode)",
        "meta_refresh" => "it redirects itself after loading",
        "context_menu_blocked" => "it blocks the long-press menu",
        "title_empty" => "it has no title",
        "brand_elsewhere" | "brands_elsewhere_log" => {
            "it names a well-known brand that is not this site"
        }
        "credential_words_log" => "its text asks for sign-in or payment details",
        "urgency_words_log" => "its text pushes you to act now (locked, suspended, expires)",
        WORDING => "its wording is that of recent phishing pages",
        _ => return None,
    })
}

/// How strongly the page resembles phishing pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PageLevel {
    Low,
    Elevated,
    High,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PageScore {
    /// The model's probability, 0 to 1.
    pub score: f32,
    pub level: PageLevel,
    /// What raised the score most, in plain words, at most three.
    pub reasons: Vec<&'static str>,
}

impl PageScore {
    /// One sentence for the watch. Never says "safe".
    pub fn explain(&self, host: &str) -> String {
        let host = escape_for_display(host);
        let because = if self.reasons.is_empty() {
            String::new()
        } else {
            format!(": {}", self.reasons.join("; "))
        };
        match self.level {
            PageLevel::High => format!(
                "Rift AI reads this page on {host} as closely resembling phishing pages{because}. A resemblance, not proof; do not type anything into it unless you are sure of the site."
            ),
            PageLevel::Elevated => format!(
                "Rift AI sees some signs of a phishing page on {host}{because}. Look closely before you type anything."
            ),
            PageLevel::Low => {
                format!("Rift AI sees nothing it recognises as phishing on {host}.")
            }
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PageModelError {
    #[error("line {0} of the page model is malformed")]
    Malformed(usize),
    #[error("the page model has no weight for {0}")]
    Missing(&'static str),
}

/// The name the reasons give the page's words, taken together.
const WORDING: &str = "wording";
/// Most `word` and `tree` lines a model may have.
pub const MAX_WORDS: usize = 5000;
pub const MAX_TREES: usize = 1000;
/// Each tree is complete and three splits deep: 7 splits, 8 leaves.
pub const TREE_SPLITS: usize = 7;
pub const TREE_LEAVES: usize = 8;

/// One regression tree over [`features`]: split `i` sends a page to `2i+1`
/// when its feature is below the threshold, else to `2i+2`; past the third
/// split, to a leaf. `values` are each split's mean output in training, so a
/// page's path says which features moved the score (Saabas).
#[derive(Debug, Clone, PartialEq)]
struct Tree {
    features: [usize; TREE_SPLITS],
    thresholds: [f32; TREE_SPLITS],
    values: [f32; TREE_SPLITS],
    leaves: [f32; TREE_LEAVES],
}

impl Tree {
    /// `tree` then, per split, `<feature> <threshold> <value>`, then the leaves.
    fn parse(parts: &[&str], number: &dyn Fn(&str) -> Option<f32>) -> Option<Self> {
        if parts.len() != 3 * TREE_SPLITS + TREE_LEAVES {
            return None;
        }
        let (splits, leaves) = parts.split_at(3 * TREE_SPLITS);
        let mut tree = Tree {
            features: [0; TREE_SPLITS],
            thresholds: [0.0; TREE_SPLITS],
            values: [0.0; TREE_SPLITS],
            leaves: [0.0; TREE_LEAVES],
        };
        for (((split, f), t), v) in splits
            .as_chunks::<3>()
            .0
            .iter()
            .zip(&mut tree.features)
            .zip(&mut tree.thresholds)
            .zip(&mut tree.values)
        {
            let [name, threshold, value] = split;
            *f = FEATURES.iter().position(|known| known == name)?;
            *t = number(threshold)?;
            *v = number(value)?;
        }
        for (leaf, text) in tree.leaves.iter_mut().zip(leaves) {
            *leaf = number(text)?;
        }
        Some(tree)
    }

    /// The leaf's output, and each split's change on the way there, by feature.
    fn walk(&self, x: &[f32], mut credit: impl FnMut(usize, f32)) -> f32 {
        let mut node = 0usize;
        loop {
            let (Some(&f), Some(&t), Some(&here)) = (
                self.features.get(node),
                self.thresholds.get(node),
                self.values.get(node),
            ) else {
                return 0.0;
            };
            let left = x.get(f).is_some_and(|v| *v < t);
            let next = node
                .saturating_mul(2)
                .saturating_add(if left { 1 } else { 2 });
            let after = match self.values.get(next) {
                Some(v) => *v,
                None => {
                    let leaf = self
                        .leaves
                        .get(next.saturating_sub(TREE_SPLITS))
                        .copied()
                        .unwrap_or(here);
                    credit(f, leaf - here);
                    return leaf;
                }
            };
            credit(f, after - here);
            node = next;
        }
    }
}

/// Logistic regression over [`features`] and the page's [`words`], plus
/// boosted trees over the features (3.3); a model with neither words nor
/// trees is the plain regression of 3.0.
#[derive(Debug, Clone, PartialEq)]
pub struct PageModel {
    bias: f32,
    weights: Vec<f32>,
    means: Vec<f32>,
    high: f32,
    elevated: f32,
    words: std::collections::HashMap<String, f32>,
    /// The words' summed weight on an average legitimate training page.
    words_mean: f32,
    trees: Vec<Tree>,
}

/// The model the app ships, trained by `tools/rift-train` (§16.1).
pub const SHIPPED: &str = include_str!("../../../models/page-model.txt");

impl PageModel {
    /// Reads the text form: `bias`, `high` and `elevated` lines with one
    /// number, then `feature <name> <weight> <mean>` per feature; optionally
    /// `words_mean <m>`, `word <word> <weight>` and `tree …` lines ([`Tree`]).
    /// `#` starts a comment. Every feature in [`FEATURES`] must be present.
    pub fn parse(text: &str) -> Result<Self, PageModelError> {
        let mut bias = None;
        let mut high = None;
        let mut elevated = None;
        let mut found: Vec<Option<(f32, f32)>> = vec![None; FEATURES.len()];
        let mut words = std::collections::HashMap::new();
        let mut words_mean = 0.0;
        let mut trees = Vec::new();
        for (i, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            let bad = || PageModelError::Malformed(i.saturating_add(1));
            let parts: Vec<&str> = line.split_whitespace().collect();
            let finite = |s: &str| s.parse::<f32>().ok().filter(|x| x.is_finite());
            let number = |s: &str| finite(s).ok_or_else(bad);
            match parts.as_slice() {
                ["bias", x] => bias = Some(number(x)?),
                ["high", x] => high = Some(number(x)?),
                ["elevated", x] => elevated = Some(number(x)?),
                ["words_mean", x] => words_mean = number(x)?,
                ["feature", name, w, mean] => {
                    let at = FEATURES.iter().position(|f| f == name).ok_or_else(bad)?;
                    if let Some(slot) = found.get_mut(at) {
                        *slot = Some((number(w)?, number(mean)?));
                    }
                }
                ["word", word, w] => {
                    let fits = (2..=MAX_WORD_CHARS).contains(&word.chars().count())
                        && word.chars().all(char::is_alphanumeric)
                        && word.to_lowercase() == *word;
                    if !fits || words.len() >= MAX_WORDS {
                        return Err(bad());
                    }
                    words.insert((*word).to_owned(), number(w)?);
                }
                ["tree", rest @ ..] => {
                    if trees.len() >= MAX_TREES {
                        return Err(bad());
                    }
                    trees.push(Tree::parse(rest, &finite).ok_or_else(bad)?);
                }
                _ => return Err(bad()),
            }
        }
        let mut weights = Vec::with_capacity(FEATURES.len());
        let mut means = Vec::with_capacity(FEATURES.len());
        for (name, slot) in FEATURES.iter().zip(found) {
            let (w, m) = slot.ok_or(PageModelError::Missing(name))?;
            weights.push(w);
            means.push(m);
        }
        let high = high.ok_or(PageModelError::Missing("high"))?;
        let elevated = elevated.ok_or(PageModelError::Missing("elevated"))?;
        if !(0.0..=1.0).contains(&elevated) || !(elevated..=1.0).contains(&high) {
            return Err(PageModelError::Malformed(0));
        }
        Ok(Self {
            bias: bias.ok_or(PageModelError::Missing("bias"))?,
            weights,
            means,
            high,
            elevated,
            words,
            words_mean,
            trees,
        })
    }

    pub fn shipped() -> Result<Self, PageModelError> {
        Self::parse(SHIPPED)
    }

    /// The model's log-odds for a page, and what each feature (and the
    /// words, under [`WORDING`]) added to it against an average legitimate page.
    fn logit(&self, x: &[f32], words: &[String]) -> (f32, Vec<(&'static str, f32)>) {
        let mut pushes: Vec<(&'static str, f32)> = FEATURES
            .iter()
            .zip(self.weights.iter().zip(&self.means))
            .zip(x)
            .map(|((name, (w, mean)), v)| (*name, w * (v - mean)))
            .collect();
        let mut z = self
            .weights
            .iter()
            .zip(x)
            .fold(self.bias, |z, (w, v)| z + w * v);
        let said: f32 = words.iter().filter_map(|w| self.words.get(w)).sum();
        z += said;
        pushes.push((WORDING, said - self.words_mean));
        for tree in &self.trees {
            z += tree.walk(x, |f, change| {
                if let Some(push) = pushes.get_mut(f) {
                    push.1 += change;
                }
            });
        }
        (z, pushes)
    }

    pub fn score(&self, host: &str, counts: &PageCounts) -> PageScore {
        let x = features(host, counts);
        let (z, mut pushes) = self.logit(&x, &words(counts));
        let score = 1.0 / (1.0 + (-z).exp());
        let level = if score >= self.high {
            PageLevel::High
        } else if score >= self.elevated {
            PageLevel::Elevated
        } else {
            PageLevel::Low
        };
        pushes.retain(|(_, push)| *push > 0.25);
        pushes.sort_by(|a, b| b.1.total_cmp(&a.1));
        let mut reasons: Vec<&'static str> = Vec::new();
        for text in pushes.iter().filter_map(|(name, _)| reason(name)) {
            if !reasons.contains(&text) && reasons.len() < 3 {
                reasons.push(text);
            }
        }
        if level == PageLevel::Low {
            reasons.clear();
        }
        PageScore {
            score,
            level,
            reasons,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kit() -> PageCounts {
        PageCounts {
            pw: 1,
            fm: 1,
            fx: 1,
            fphp: 1,
            hi: 3,
            a: 4,
            an: 4,
            r: 6,
            rx: 5,
            fv: 1,
            sc: 2,
            sx: 1,
            ob: 2,
            hb: 4_000,
            el: 60,
            title: "PayPal: Log in to your account".into(),
            text: "Your account has been limited. Verify your identity within 24 hours. Email Password Log In".into(),
            ..PageCounts::default()
        }
    }

    #[test]
    fn site_keys_ignore_subdomains_and_keep_country_seconds() {
        assert_eq!(site_key("www.login.paypal.com"), "paypal.com");
        assert_eq!(site_key("shop.example.co.uk"), "example.co.uk");
        assert_eq!(site_key("localhost"), "localhost");
        assert_eq!(site_key("Example.COM."), "example.com");
    }

    #[test]
    fn reports_are_bounded() {
        assert!(PageCounts::from_report(&"x".repeat(MAX_REPORT_BYTES + 1)).is_none());
        assert!(PageCounts::from_report("not json").is_none());
        let long = format!(
            r#"{{"pw":4294967295,"text":"{}","extra":1}}"#,
            "a".repeat(5000)
        );
        let counts = PageCounts::from_report(&long).unwrap();
        assert_eq!(counts.pw, MAX_COUNT);
        assert_eq!(counts.text.chars().count(), MAX_TEXT_CHARS);
    }

    #[test]
    fn features_read_the_brand_and_the_words() {
        let x = features("paypa1-secure.example", &kit());
        let at = |name: &str| x[FEATURES.iter().position(|f| *f == name).unwrap()];
        assert_eq!(x.len(), FEATURES.len());
        assert_eq!(at("brand_elsewhere"), 1.0);
        assert_eq!(at("password_to_other_site"), 1.0);
        assert!(at("urgency_words_log") > 1.0);
        let real = features("www.paypal.com", &kit());
        assert_eq!(
            real[FEATURES
                .iter()
                .position(|f| *f == "brand_elsewhere")
                .unwrap()],
            0.0
        );
        assert_eq!(
            real[FEATURES.iter().position(|f| *f == "site_in_title").unwrap()],
            1.0
        );
    }

    #[test]
    fn the_shipped_model_reads_and_flags_a_kit_but_not_an_ordinary_page() {
        let model = PageModel::shipped().unwrap();
        let kit = model.score("paypa1-secure.example", &kit());
        assert_eq!(kit.level, PageLevel::High, "{kit:?}");
        assert!(!kit.reasons.is_empty());
        assert!(
            !kit.explain("paypa1-secure.example")
                .to_lowercase()
                .contains("safe")
        );
        let ordinary = PageCounts {
            a: 120,
            ax: 20,
            r: 40,
            rx: 10,
            sc: 12,
            sx: 4,
            hb: 180_000,
            el: 2_500,
            cp: 1,
            title: "Example News: today's stories".into(),
            text: "Example News Home World Business Sport Weather Today's stories from around the world".into(),
            ..PageCounts::default()
        };
        assert_eq!(
            model.score("www.example.com", &ordinary).level,
            PageLevel::Low
        );
    }

    #[test]
    fn damaged_models_are_refused() {
        assert!(PageModel::parse("bias 1\nhigh 0.9\nelevated 0.5\n").is_err());
        assert!(PageModel::parse(&SHIPPED.replace("bias", "bias NaN #")).is_err());
        assert!(PageModel::parse(&SHIPPED.replace("high", "high 0.1 #")).is_err());
        let plain = regression_only();
        for extra in [
            "word Seed 1",
            "word seed phrase 1",
            "word x 1",
            "word seed inf",
            "tree has_password 0.5 0",
            &format!(
                "tree {}",
                "nosuchfeature 0.5 0 ".repeat(7) + &"0 ".repeat(8)
            ),
        ] {
            assert!(
                PageModel::parse(&format!("{plain}{extra}\n")).is_err(),
                "{extra}"
            );
        }
    }

    #[test]
    fn words_are_distinct_lower_case_and_of_two_letters_or_more() {
        let counts = PageCounts {
            title: "Sign-In | PayPal".into(),
            text: "Enter your PayPal password. a 2 Ünïcode İzmir".into(),
            ..PageCounts::default()
        };
        assert_eq!(
            words(&counts),
            [
                "enter",
                "in",
                "password",
                "paypal",
                "sign",
                "your",
                "zmir",
                "ünïcode"
            ]
        );
    }

    /// The shipped model's regression, without its words and trees.
    fn regression_only() -> String {
        SHIPPED
            .lines()
            .filter(|l| !l.starts_with("word") && !l.starts_with("tree"))
            .map(|l| format!("{l}\n"))
            .collect()
    }

    /// A model with one word and one tree beside the shipped regression.
    fn with_word_and_tree(base: &str) -> PageModel {
        let leaf = |v: &str| format!("has_password 3e38 {v} ");
        let tree = format!(
            "tree context_menu_blocked 0.5 0 {}{}{}{}{}{}-0.1 -0.1 -0.1 -0.1 2 2 2 2",
            leaf("-0.1"),
            leaf("2"),
            leaf("-0.1"),
            leaf("-0.1"),
            leaf("2"),
            leaf("2"),
        );
        PageModel::parse(&format!(
            "{base}words_mean 0.5\nword seedphrase 3\n{tree}\n"
        ))
        .unwrap()
    }

    #[test]
    fn words_and_trees_add_to_the_score_and_name_their_reasons() {
        let plain = PageModel::parse(&regression_only()).unwrap();
        let model = with_word_and_tree(&regression_only());
        let logit = |p: f32| (p / (1.0 - p)).ln();
        let page = PageCounts {
            pw: 1,
            fm: 1,
            a: 30,
            el: 300,
            hb: 20_000,
            title: "Wallet".into(),
            text: "Enter your seedphrase".into(),
            ..PageCounts::default()
        };
        let blocked = PageCounts {
            rc: 1,
            ..page.clone()
        };
        let gap = |c: &PageCounts| {
            logit(model.score("w.example", c).score) - logit(plain.score("w.example", c).score)
        };
        // The word (3) and the tree's leaf: -0.1 without the block, 2 with it.
        assert!((gap(&page) - 2.9).abs() < 1e-3, "{}", gap(&page));
        assert!((gap(&blocked) - 5.0).abs() < 1e-3, "{}", gap(&blocked));
        let scored = model.score("w.example", &blocked);
        assert!(
            scored
                .reasons
                .contains(&"its wording is that of recent phishing pages"),
            "{scored:?}"
        );
        assert!(
            scored.reasons.contains(&"it blocks the long-press menu"),
            "{scored:?}"
        );
    }
}
