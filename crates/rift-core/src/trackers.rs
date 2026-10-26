//! Well-known trackers, by the hosts they load from and the link parameters
//! they add (docs/architecture.md §10.14), with what each one does in plain
//! words.
//!
//! The list is Rift's own and small on purpose: it names the services a
//! person is most likely to meet and explains them. It is not a blocker:
//! blocking is the content filters' job (§10.9, EasyPrivacy), and a host not
//! named here is not "not a tracker".

/// What a tracker is for, which decides what it learns about the visitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    Analytics,
    Advertising,
    /// Records what the visitor does on the page, to be played back later.
    SessionReplay,
    Social,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Analytics => "Analytics",
            Kind::Advertising => "Advertising",
            Kind::SessionReplay => "Session recording",
            Kind::Social => "Social network",
        }
    }

    /// What this kind of tracker does, for someone who has not met one.
    pub fn explain(self) -> &'static str {
        match self {
            Kind::Analytics => {
                "Counts visits and records which pages you view, for how long, where you came from, and your device and rough location. The site's owner sees it, and so does the company running the service."
            }
            Kind::Advertising => {
                "Recognises your browser across the sites that use the same company, to build an interest profile, show you targeted ads and measure whether an ad made you buy or sign up."
            }
            Kind::SessionReplay => {
                "Records your mouse or finger movements, taps, scrolling and what you type into the page, so the site can replay your visit like a video. Typed text, passwords included on badly set-up sites, can be captured."
            }
            Kind::Social => {
                "Tells the social network that you visited this page. If you are signed in to it elsewhere, the visit can be linked to your account, even if you never tap its buttons."
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tracker {
    pub name: &'static str,
    pub company: &'static str,
    pub kind: Kind,
}

/// Hosts (a host and every name under it) and the tracker they serve.
const HOSTS: &[(&str, Tracker)] = &[
    (
        "google-analytics.com",
        t("Google Analytics", "Google", Kind::Analytics),
    ),
    (
        "analytics.google.com",
        t("Google Analytics", "Google", Kind::Analytics),
    ),
    (
        "googletagmanager.com",
        t("Google Tag Manager", "Google", Kind::Analytics),
    ),
    (
        "doubleclick.net",
        t("DoubleClick", "Google", Kind::Advertising),
    ),
    (
        "googlesyndication.com",
        t("Google AdSense", "Google", Kind::Advertising),
    ),
    (
        "googleadservices.com",
        t("Google Ads", "Google", Kind::Advertising),
    ),
    (
        "adservice.google.com",
        t("Google Ads", "Google", Kind::Advertising),
    ),
    (
        "connect.facebook.net",
        t("Meta Pixel", "Meta", Kind::Advertising),
    ),
    (
        "facebook.com/tr",
        t("Meta Pixel", "Meta", Kind::Advertising),
    ),
    (
        "analytics.tiktok.com",
        t("TikTok Pixel", "TikTok", Kind::Advertising),
    ),
    (
        "ads.linkedin.com",
        t("LinkedIn Insight Tag", "LinkedIn", Kind::Advertising),
    ),
    (
        "snap.licdn.com",
        t("LinkedIn Insight Tag", "LinkedIn", Kind::Advertising),
    ),
    (
        "ads-twitter.com",
        t("X (Twitter) Pixel", "X", Kind::Advertising),
    ),
    (
        "analytics.twitter.com",
        t("X (Twitter) Pixel", "X", Kind::Advertising),
    ),
    ("sc-static.net", t("Snap Pixel", "Snap", Kind::Advertising)),
    (
        "ct.pinterest.com",
        t("Pinterest Tag", "Pinterest", Kind::Advertising),
    ),
    (
        "bat.bing.com",
        t(
            "Microsoft Advertising (UET)",
            "Microsoft",
            Kind::Advertising,
        ),
    ),
    ("criteo.com", t("Criteo", "Criteo", Kind::Advertising)),
    ("criteo.net", t("Criteo", "Criteo", Kind::Advertising)),
    ("taboola.com", t("Taboola", "Taboola", Kind::Advertising)),
    ("outbrain.com", t("Outbrain", "Outbrain", Kind::Advertising)),
    ("adnxs.com", t("Xandr", "Microsoft", Kind::Advertising)),
    (
        "rubiconproject.com",
        t("Magnite", "Magnite", Kind::Advertising),
    ),
    ("pubmatic.com", t("PubMatic", "PubMatic", Kind::Advertising)),
    (
        "amazon-adsystem.com",
        t("Amazon Ads", "Amazon", Kind::Advertising),
    ),
    (
        "scorecardresearch.com",
        t("Comscore", "Comscore", Kind::Analytics),
    ),
    (
        "quantserve.com",
        t("Quantcast", "Quantcast", Kind::Advertising),
    ),
    (
        "hotjar.com",
        t("Hotjar", "Contentsquare", Kind::SessionReplay),
    ),
    (
        "hotjar.io",
        t("Hotjar", "Contentsquare", Kind::SessionReplay),
    ),
    (
        "clarity.ms",
        t("Microsoft Clarity", "Microsoft", Kind::SessionReplay),
    ),
    (
        "fullstory.com",
        t("FullStory", "FullStory", Kind::SessionReplay),
    ),
    (
        "mouseflow.com",
        t("Mouseflow", "Mouseflow", Kind::SessionReplay),
    ),
    (
        "smartlook.com",
        t("Smartlook", "Cisco", Kind::SessionReplay),
    ),
    (
        "contentsquare.net",
        t("Contentsquare", "Contentsquare", Kind::SessionReplay),
    ),
    (
        "logrocket.io",
        t("LogRocket", "LogRocket", Kind::SessionReplay),
    ),
    (
        "mc.yandex.ru",
        t("Yandex Metrica", "Yandex", Kind::SessionReplay),
    ),
    ("mixpanel.com", t("Mixpanel", "Mixpanel", Kind::Analytics)),
    ("segment.com", t("Segment", "Twilio", Kind::Analytics)),
    ("segment.io", t("Segment", "Twilio", Kind::Analytics)),
    (
        "amplitude.com",
        t("Amplitude", "Amplitude", Kind::Analytics),
    ),
    (
        "heapanalytics.com",
        t("Heap", "Contentsquare", Kind::Analytics),
    ),
    ("newrelic.com", t("New Relic", "New Relic", Kind::Analytics)),
    ("nr-data.net", t("New Relic", "New Relic", Kind::Analytics)),
    ("hs-analytics.net", t("HubSpot", "HubSpot", Kind::Analytics)),
    ("hs-scripts.com", t("HubSpot", "HubSpot", Kind::Analytics)),
    ("matomo.cloud", t("Matomo", "InnoCraft", Kind::Analytics)),
    (
        "platform.twitter.com",
        t("X (Twitter) embeds", "X", Kind::Social),
    ),
    (
        "platform.linkedin.com",
        t("LinkedIn embeds", "LinkedIn", Kind::Social),
    ),
    ("addthis.com", t("AddThis", "Oracle", Kind::Social)),
    ("sharethis.com", t("ShareThis", "ShareThis", Kind::Social)),
];

const fn t(name: &'static str, company: &'static str, kind: Kind) -> Tracker {
    Tracker {
        name,
        company,
        kind,
    }
}

/// The tracker `host` belongs to, if it is one named here. `host` is
/// matched as itself and every parent name, ASCII case-insensitively;
/// entries with a path (`facebook.com/tr`) need [`tracker_for_url`].
pub fn tracker_for_host(host: &str) -> Option<Tracker> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    HOSTS
        .iter()
        .filter(|(entry, _)| !entry.contains('/'))
        .find(|(entry, _)| {
            host == *entry
                || host
                    .strip_suffix(entry)
                    .is_some_and(|rest| rest.ends_with('.'))
        })
        .map(|(_, tracker)| *tracker)
}

/// [`tracker_for_host`], plus the entries that name a path on a host.
pub fn tracker_for_url(host: &str, path: &str) -> Option<Tracker> {
    let lower = format!("{}{}", host.trim_end_matches('.'), path).to_ascii_lowercase();
    tracker_for_host(host).or_else(|| {
        HOSTS
            .iter()
            .filter(|(entry, _)| entry.contains('/'))
            .find(|(entry, _)| lower.starts_with(entry) || lower.contains(&format!(".{entry}")))
            .map(|(_, tracker)| *tracker)
    })
}

/// A tracking parameter in a link: who adds it and what it lets them know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Param {
    pub name: &'static str,
    pub who: &'static str,
    pub what: &'static str,
}

const CLICK_ID: &str = "A unique click ID: it ties this visit to the exact ad or post you tapped and, through it, to you.";
const CAMPAIGN: &str = "Says which campaign, newsletter or post the link came from. It identifies the source, not usually you.";
const MAIL_ID: &str = "Identifies the email it was sent in and often you as the recipient, so the sender knows you opened the link.";

/// Exact names, then prefixes (`utm_` covers `utm_source` and the rest).
const PARAMS: &[Param] = &[
    p("fbclid", "Meta (Facebook, Instagram)", CLICK_ID),
    p("gclid", "Google Ads", CLICK_ID),
    p("gbraid", "Google Ads", CLICK_ID),
    p("wbraid", "Google Ads", CLICK_ID),
    p("dclid", "Google Display ads", CLICK_ID),
    p("msclkid", "Microsoft Advertising", CLICK_ID),
    p("ttclid", "TikTok ads", CLICK_ID),
    p("twclid", "X (Twitter) ads", CLICK_ID),
    p("li_fat_id", "LinkedIn ads", CLICK_ID),
    p("yclid", "Yandex ads", CLICK_ID),
    p("epik", "Pinterest ads", CLICK_ID),
    p(
        "igshid",
        "Instagram",
        "Identifies the share, and through it the account that shared the link.",
    ),
    p(
        "igsh",
        "Instagram",
        "Identifies the share, and through it the account that shared the link.",
    ),
    p(
        "si",
        "YouTube or Spotify (share link)",
        "Identifies who shared the link, so the service can link the sharer and the people who open it.",
    ),
    p("mc_eid", "Mailchimp", MAIL_ID),
    p("mc_cid", "Mailchimp", CAMPAIGN),
    p("_hsenc", "HubSpot", MAIL_ID),
    p("_hsmi", "HubSpot", MAIL_ID),
    p("mkt_tok", "Marketo", MAIL_ID),
    p("vero_id", "Vero", MAIL_ID),
    p("oly_enc_id", "Omeda", MAIL_ID),
    p(
        "_ga",
        "Google Analytics",
        "Carries your Google Analytics ID from another site, so both sites see the same visitor.",
    ),
    p(
        "_gl",
        "Google Analytics",
        "Carries your Google Analytics ID from another site, so both sites see the same visitor.",
    ),
    p("ref_src", "X (Twitter)", CAMPAIGN),
    p("s_cid", "Adobe Analytics", CAMPAIGN),
];

const PREFIXES: &[Param] = &[
    p(
        "utm_",
        "Campaign tagging (Google Analytics and others)",
        CAMPAIGN,
    ),
    p("pk_", "Matomo or Piwik", CAMPAIGN),
];

const fn p(name: &'static str, who: &'static str, what: &'static str) -> Param {
    Param { name, who, what }
}

/// The tracking parameter `name` is, if it is one named here (compared
/// ASCII case-insensitively, whole names or the listed prefixes).
pub fn param(name: &str) -> Option<Param> {
    let lower = name.to_ascii_lowercase();
    PARAMS
        .iter()
        .find(|p| p.name == lower)
        .or_else(|| PREFIXES.iter().find(|p| lower.starts_with(p.name)))
        .copied()
}

/// The query parameters of `query` (without the `?`) that are named here,
/// each with its explanation, in the order they appear, at most once each.
pub fn params_in(query: &str) -> Vec<(String, Param)> {
    let mut found: Vec<(String, Param)> = Vec::new();
    for pair in query.split('&').take(256) {
        let name = pair.split('=').next().unwrap_or_default();
        if let Some(param) = param(name)
            && !found.iter().any(|(n, _)| n.eq_ignore_ascii_case(name))
        {
            found.push((crate::text::escape_for_display(name), param));
        }
    }
    found
}

/// `query` without the parameters [`params_in`] names; None if it has none.
pub fn without_params(query: &str) -> Option<String> {
    let kept: Vec<&str> = query
        .split('&')
        .filter(|pair| param(pair.split('=').next().unwrap_or_default()).is_none())
        .collect();
    let removed = query.split('&').count() != kept.len();
    removed.then(|| kept.join("&"))
}

/// [`params_in`] for a whole web address; empty if it does not parse.
pub fn link_params(address: &str) -> Vec<(String, Param)> {
    url::Url::parse(address)
        .ok()
        .and_then(|url| url.query().map(params_in))
        .unwrap_or_default()
}

/// `address` without the parameters [`link_params`] names; None if it has
/// none or does not parse. The rest of the query keeps its order and spelling.
pub fn link_without_tracking(address: &str) -> Option<String> {
    let mut url = url::Url::parse(address).ok()?;
    let kept = without_params(url.query()?)?;
    url.set_query((!kept.is_empty()).then_some(kept.as_str()));
    Some(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_match_themselves_and_names_under_them_only() {
        assert_eq!(
            tracker_for_host("www.google-analytics.com").map(|t| t.name),
            Some("Google Analytics")
        );
        assert_eq!(
            tracker_for_host("STATIC.HOTJAR.COM.").map(|t| t.kind),
            Some(Kind::SessionReplay)
        );
        assert_eq!(tracker_for_host("notgoogle-analytics.com"), None);
        assert_eq!(tracker_for_host("google-analytics.com.evil.example"), None);
        assert_eq!(
            tracker_for_host("facebook.com"),
            None,
            "only the pixel's path is a tracker"
        );
        assert_eq!(
            tracker_for_url("www.facebook.com", "/tr?id=1").map(|t| t.name),
            Some("Meta Pixel")
        );
        assert_eq!(tracker_for_url("www.facebook.com", "/login"), None);
    }

    #[test]
    fn link_parameters_are_named_and_explained() {
        let found = params_in("q=shoes&utm_source=news&FBCLID=abc&utm_medium=mail&fbclid=x");
        let names: Vec<&str> = found.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["utm_source", "FBCLID", "utm_medium"]);
        assert!(found[1].1.what.contains("click ID"));
        assert_eq!(
            without_params("q=shoes&utm_source=news&fbclid=abc").as_deref(),
            Some("q=shoes")
        );
        assert_eq!(without_params("q=shoes&page=2"), None);
        assert_eq!(param("utmost"), None);
        assert_eq!(
            link_without_tracking("https://shop.example/p?id=7&utm_source=x&gclid=y#top")
                .as_deref(),
            Some("https://shop.example/p?id=7#top")
        );
        assert_eq!(
            link_without_tracking("https://shop.example/?fbclid=y").as_deref(),
            Some("https://shop.example/")
        );
        assert_eq!(link_without_tracking("https://shop.example/?id=7"), None);
    }

    #[test]
    fn every_kind_is_explained() {
        for (_, tracker) in HOSTS {
            assert!(tracker.kind.explain().len() > 40);
            assert!(!tracker.kind.explain().to_lowercase().contains("safe"));
        }
    }
}
