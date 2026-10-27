//! What a link that leaves the web would do (docs/architecture.md §10.15).
//!
//! Rift never opens these links (§10.2); this says, in plain words, which
//! app such a link would open and what it would ask that app to do: send a
//! payment or a text, approve a sign-in, open a settings screen malware
//! asks for, install an app. It reads only the link; nothing is opened or
//! asked of the phone. Every value shown is cut short and escaped.

use url::Url;

use crate::policy::explicit_scheme;
use crate::text::escape_for_display;
use crate::urlcanon::MAX_URL_BYTES;

/// The longest value shown from a link, in characters.
const MAX_SHOWN: usize = 120;

/// Schemes whose links can start with a digit after the colon.
const DIGIT_SCHEMES: &[&str] = &["tel", "sms", "smsto", "mms", "mmsto", "wc", "geo"];

/// How serious what the link asks for is, least first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Risk {
    Note,
    Warning,
    Danger,
}

/// One link that leaves the web, explained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppLink {
    /// The link's scheme, lower case (`intent`, `upi`, …).
    pub scheme: String,
    /// The app it names, when the link says ("WhatsApp", or a package name).
    pub app: Option<String>,
    /// What it would do, as one sentence.
    pub does: String,
    /// What it carries (the number, the amount, the message), one per line.
    pub details: Vec<String>,
    pub risk: Risk,
    /// The web address an `intent:` link sends the browser to when the app
    /// is not installed; for Check to judge as any address.
    pub fallback: Option<String>,
}

/// Explains `raw` if it is a link to something other than a web page;
/// None for `http(s)` addresses and text without a scheme.
pub fn explain(raw: &[u8]) -> Option<AppLink> {
    // `tel:5551234` reads as a host and port to the web check; not here.
    let scheme = explicit_scheme(raw).or_else(|| {
        let text = String::from_utf8_lossy(raw.get(..16).unwrap_or(raw)).to_ascii_lowercase();
        let (scheme, _) = text.trim_start().split_once(':')?;
        DIGIT_SCHEMES.contains(&scheme).then(|| scheme.to_owned())
    })?;
    if scheme == "http" || scheme == "https" {
        return None;
    }
    let text = String::from_utf8_lossy(raw.get(..MAX_URL_BYTES).unwrap_or(raw));
    let url = Url::parse(text.trim()).ok();
    Some(describe(&scheme, url.as_ref(), true))
}

fn describe(scheme: &str, url: Option<&Url>, outer: bool) -> AppLink {
    let link = |app: Option<&str>, does: String, details: Vec<String>, risk: Risk| AppLink {
        scheme: scheme.to_owned(),
        app: app.map(show),
        does,
        details,
        risk,
        fallback: None,
    };
    let param = |name: &str| url.and_then(|u| query(u, name));
    let target = url.map(|u| decoded(u.path())).unwrap_or_default();
    match scheme {
        "intent" | "android-app" if outer => intent(scheme, url),
        "upi" => {
            let mandate = url.is_some_and(|u| u.host_str() == Some("mandate"));
            let to = param("pa").unwrap_or_default();
            let name = param("pn").map(|n| format!(" ({})", show(&n))).unwrap_or_default();
            let amount = match (param("am"), param("cu")) {
                (Some(am), cu) => format!("{} {}", show(&am), show(&cu.unwrap_or_else(|| "INR".into()))),
                (None, _) => "an amount you would type".to_owned(),
            };
            let does = if mandate {
                format!("Asks your payment app to set up repeated payments of {amount} to {}{name}.", show(&to))
            } else {
                format!("Asks your payment app to pay {amount} to {}{name}.", show(&to))
            };
            let mut details = vec![
                "This is a payment request: money leaves your account if you approve it with your PIN. You never need your PIN to receive money.".to_owned(),
            ];
            if let Some(note) = param("tn") {
                details.push(format!("Its note: {}", show(&note)));
            }
            link(None, does, details, Risk::Danger)
        }
        "bitcoin" | "ethereum" | "litecoin" | "dogecoin" | "bitcoincash" | "monero" | "solana"
        | "tron" | "ripple" => {
            let address = target.split(['@', '/']).next().unwrap_or_default().to_owned();
            let amount = param("amount")
                .or_else(|| param("value"))
                .or_else(|| param("tx_amount"))
                .map(|a| format!("{} ", show(&a)))
                .unwrap_or_default();
            link(
                None,
                format!("Asks your crypto wallet to send {amount}{scheme} to {}.", show(&address)),
                vec!["Crypto payments cannot be undone.".to_owned()],
                Risk::Danger,
            )
        }
        "wc" => link(
            None,
            "Connects your crypto wallet to a website (WalletConnect).".to_owned(),
            vec!["Sites that empty wallets ask for exactly this. Connect only to a site you opened yourself.".to_owned()],
            Risk::Danger,
        ),
        "tel" if target.contains(['*', '#']) => link(
            None,
            format!("Dials the phone code {}.", show(&target)),
            vec!["Phone codes can change settings such as call forwarding, so that someone else gets your calls and sign-in codes.".to_owned()],
            Risk::Danger,
        ),
        "tel" => link(
            None,
            format!("Calls {}.", show(&target)),
            vec!["Some scams use numbers that cost a lot to call.".to_owned()],
            Risk::Warning,
        ),
        "sms" | "smsto" | "mms" | "mmsto" => {
            let mut details = Vec::new();
            if let Some(body) = param("body") {
                details.push(format!("The message: {}", show(&body)));
            }
            details.push("Nothing is sent until you press send; texts to short or premium numbers can cost money or sign you up to paid services.".to_owned());
            link(None, format!("Writes a text message to {}.", show(&target)), details, Risk::Warning)
        }
        "mailto" => {
            let mut details = Vec::new();
            if let Some(subject) = param("subject") {
                details.push(format!("Subject: {}", show(&subject)));
            }
            link(None, format!("Writes an email to {}.", show(&target)), details, Risk::Note)
        }
        "whatsapp" => match (url.and_then(Url::host_str), param("phone")) {
            (Some("send"), phone) => {
                let mut details = Vec::new();
                if let Some(text) = param("text") {
                    details.push(format!("The message: {}", show(&text)));
                }
                let to = phone.map(|p| format!(" to {}", show(&p))).unwrap_or_default();
                link(Some("WhatsApp"), format!("Opens WhatsApp to send a message{to}."), details, Risk::Warning)
            }
            _ => link(Some("WhatsApp"), "Opens WhatsApp.".to_owned(), Vec::new(), Risk::Warning),
        },
        "tg" => match url.and_then(Url::host_str) {
            Some("login") => link(
                Some("Telegram"),
                "Approves a sign-in to your Telegram account, on a device that may be someone else's.".to_owned(),
                vec!["Accounts are taken over this way: never approve a sign-in you did not start.".to_owned()],
                Risk::Danger,
            ),
            Some("resolve") => link(
                Some("Telegram"),
                format!("Opens the Telegram chat @{}.", show(&param("domain").unwrap_or_default())),
                Vec::new(),
                Risk::Warning,
            ),
            Some("join") => link(Some("Telegram"), "Joins a Telegram group.".to_owned(), Vec::new(), Risk::Warning),
            _ => link(Some("Telegram"), "Opens Telegram.".to_owned(), Vec::new(), Risk::Warning),
        },
        "market" => match param("id") {
            Some(id) => link(
                Some("Google Play"),
                format!("Opens Google Play on the app {}.", show(&id)),
                vec!["Scams often start with an app a link asks you to install; look the app up yourself.".to_owned()],
                Risk::Warning,
            ),
            None => link(Some("Google Play"), "Opens Google Play.".to_owned(), Vec::new(), Risk::Warning),
        },
        "otpauth" => link(
            None,
            format!("Adds a sign-in code account ({}) to your authenticator app.", show(target.trim_start_matches('/'))),
            Vec::new(),
            Risk::Warning,
        ),
        "geo" => link(None, format!("Opens a map at {}.", show(&target)), Vec::new(), Risk::Note),
        "javascript" => link(
            None,
            "Runs code in the page that opened it.".to_owned(),
            vec!["Rift never runs it.".to_owned()],
            Risk::Danger,
        ),
        "data" => {
            let kind = target.split([',', ';']).next().unwrap_or_default().to_owned();
            link(
                None,
                format!("Carries a whole page or file inside the link ({}).", show(&kind)),
                vec!["Fake sign-in pages hide this way, with no address to check.".to_owned()],
                Risk::Warning,
            )
        }
        "file" => link(None, format!("Opens the file {} on this phone.", show(&target)), Vec::new(), Risk::Danger),
        "content" => link(None, "Opens data held by another app on this phone.".to_owned(), Vec::new(), Risk::Warning),
        "about" | "blob" => link(None, "Refers to something inside the browser itself.".to_owned(), Vec::new(), Risk::Note),
        _ => match known_scheme(scheme) {
            Some(app) => link(Some(app), format!("Opens {app}."), Vec::new(), Risk::Warning),
            None => link(
                None,
                format!(
                    "Opens another app that handles \"{}:\" links; Rift cannot tell which app, or what the link asks it to do.",
                    show(scheme)
                ),
                Vec::new(),
                Risk::Warning,
            ),
        },
    }
}

/// `intent://…#Intent;scheme=…;package=…;action=…;end` (Chrome's form) and
/// `android-app://package/scheme/host/path`.
fn intent(scheme: &str, url: Option<&Url>) -> AppLink {
    let mut fields: Vec<(String, String)> = Vec::new();
    let mut data: Option<Url> = None;
    if let Some(url) = url {
        if scheme == "intent" {
            let fragment = url.fragment().unwrap_or_default();
            for field in fragment
                .strip_prefix("Intent;")
                .unwrap_or(fragment)
                .split(';')
                .take(32)
            {
                if let Some((key, value)) = field.split_once('=') {
                    fields.push((key.to_owned(), decoded(value)));
                }
            }
            let get = |k: &str| {
                fields
                    .iter()
                    .find(|(key, _)| key == k)
                    .map(|(_, v)| v.clone())
            };
            if let Some(inner) = get("scheme") {
                let mut rebuilt = url.clone();
                rebuilt.set_fragment(None);
                let rest = rebuilt
                    .as_str()
                    .strip_prefix("intent:")
                    .unwrap_or_default()
                    .to_owned();
                data = Url::parse(&format!("{inner}:{rest}")).ok();
            }
        } else if let Some(package) = url.host_str() {
            fields.push(("package".into(), package.to_owned()));
            let mut parts = url.path().trim_start_matches('/').splitn(2, '/');
            if let Some(inner) = parts.next().filter(|s| !s.is_empty()) {
                let rest = parts.next().unwrap_or_default();
                data = Url::parse(&format!("{inner}://{rest}")).ok();
            }
        }
    }
    let get = |k: &str| {
        fields
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
    };
    let package = get("package")
        .or_else(|| get("component").and_then(|c| c.split('/').next().map(str::to_owned)));
    let app = package
        .as_deref()
        .map(|p| known_package(p).map_or_else(|| p.to_owned(), str::to_owned));
    let fallback = get("S.browser_fallback_url")
        .filter(|f| f.starts_with("https://") || f.starts_with("http://"))
        .map(|f| show(&f));
    let action = get("action").unwrap_or_default();
    let mime = get("type").unwrap_or_default();

    let mut explained = if mime == "application/vnd.android.package-archive"
        || action.ends_with("INSTALL_PACKAGE")
    {
        AppLink {
            scheme: scheme.to_owned(),
            app: None,
            does: "Asks to install an app from outside the Play Store.".to_owned(),
            details: vec!["Phone malware is spread this way.".to_owned()],
            risk: Risk::Danger,
            fallback: None,
        }
    } else if let Some((does, risk)) = settings_action(&action) {
        AppLink {
            scheme: scheme.to_owned(),
            app: Some("Settings".to_owned()),
            does: does.to_owned(),
            details: Vec::new(),
            risk,
            fallback: None,
        }
    } else if let Some(inner) = data
        .as_ref()
        .filter(|d| d.scheme() != "http" && d.scheme() != "https")
    {
        describe(inner.scheme(), Some(inner), false)
    } else {
        let what = match action.rsplit('.').next().unwrap_or_default() {
            "CALL" | "DIAL" => "to make a call",
            "SEND" | "SENDTO" | "SEND_MULTIPLE" => "to send something",
            _ => "",
        };
        let name = app.clone().unwrap_or_else(|| "another app".to_owned());
        let sep = if what.is_empty() { "" } else { " " };
        AppLink {
            scheme: scheme.to_owned(),
            app: None,
            does: format!("Opens {}{sep}{what}.", show(&name)),
            details: Vec::new(),
            risk: Risk::Warning,
            fallback: None,
        }
    };
    explained.scheme = scheme.to_owned();
    if explained.app.is_none() {
        explained.app = app.map(|a| show(&a));
    }
    if let Some(package) = package.filter(|p| known_package(p).is_none()) {
        explained.details.push(format!("App: {}", show(&package)));
    }
    if let Some(fallback) = &fallback {
        explained.details.push(format!(
            "Without the app, it sends the browser to {fallback}"
        ));
    }
    explained.fallback = fallback;
    explained
}

/// Settings screens a link can open, and why one matters.
fn settings_action(action: &str) -> Option<(&'static str, Risk)> {
    Some(match action {
        "android.settings.ACCESSIBILITY_SETTINGS" => (
            "Opens the accessibility settings, where phone malware asks to be given control of the screen.",
            Risk::Danger,
        ),
        "android.app.action.ADD_DEVICE_ADMIN" => (
            "Asks to make an app a device administrator, which can lock or wipe the phone and is hard to remove.",
            Risk::Danger,
        ),
        "android.settings.MANAGE_UNKNOWN_APP_SOURCES" => (
            "Opens the setting that lets apps be installed from outside the Play Store.",
            Risk::Danger,
        ),
        "android.settings.action.MANAGE_OVERLAY_PERMISSION" => (
            "Opens the setting that lets an app draw over other apps, which fake sign-in screens use.",
            Risk::Danger,
        ),
        "android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS"
        | "android.settings.NOTIFICATION_LISTENER_SETTINGS" => (
            "Opens the setting that lets an app read your notifications, sign-in codes included.",
            Risk::Danger,
        ),
        "android.settings.USAGE_ACCESS_SETTINGS" => (
            "Opens the setting that lets an app see which apps you use.",
            Risk::Warning,
        ),
        a if a.starts_with("android.settings.") => ("Opens the phone's settings.", Risk::Warning),
        _ => return None,
    })
}

fn known_package(package: &str) -> Option<&'static str> {
    Some(match package {
        "com.whatsapp" | "com.whatsapp.w4b" => "WhatsApp",
        "org.telegram.messenger" => "Telegram",
        "com.android.vending" => "Google Play",
        "com.android.chrome" => "Chrome",
        "com.google.android.apps.nbu.paisa.user" => "Google Pay",
        "com.phonepe.app" => "PhonePe",
        "net.one97.paytm" => "Paytm",
        "io.metamask" => "MetaMask",
        "com.wallet.crypto.trustapp" => "Trust Wallet",
        "app.phantom" => "Phantom",
        "com.coinbase.android" => "Coinbase",
        "com.binance.dev" => "Binance",
        "com.facebook.katana" => "Facebook",
        "com.facebook.orca" => "Messenger",
        "com.instagram.android" => "Instagram",
        "com.zhiliaoapp.musically" => "TikTok",
        "com.twitter.android" => "X",
        "com.snapchat.android" => "Snapchat",
        "com.google.android.youtube" => "YouTube",
        "com.google.android.gm" => "Gmail",
        "com.android.settings" => "Settings",
        "com.google.zxing.client.android" => "Barcode Scanner",
        _ => return None,
    })
}

fn known_scheme(scheme: &str) -> Option<&'static str> {
    Some(match scheme {
        "fb" => "Facebook",
        "fb-messenger" => "Messenger",
        "instagram" => "Instagram",
        "twitter" | "x" => "X",
        "snapchat" => "Snapchat",
        "tiktok" | "snssdk1233" => "TikTok",
        "youtube" | "vnd.youtube" => "YouTube",
        "spotify" => "Spotify",
        "zoommtg" | "zoomus" => "Zoom",
        "msteams" => "Microsoft Teams",
        "skype" => "Skype",
        "viber" => "Viber",
        "signal" | "sgnl" => "Signal",
        "metamask" => "MetaMask",
        "trust" => "Trust Wallet",
        "phantom" => "Phantom",
        "googlechrome" => "Chrome",
        "paytmmp" => "Paytm",
        "phonepe" => "PhonePe",
        "tez" | "gpay" => "Google Pay",
        _ => return None,
    })
}

fn query(url: &Url, name: &str) -> Option<String> {
    url.query_pairs()
        .take(64)
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.into_owned())
        .filter(|value| !value.is_empty())
}

fn decoded(text: &str) -> String {
    percent_encoding::percent_decode_str(text)
        .decode_utf8_lossy()
        .into_owned()
}

/// `text` cut to [`MAX_SHOWN`] characters and escaped for display.
fn show(text: &str) -> String {
    let mut cut: String = text.chars().take(MAX_SHOWN).collect();
    if text.chars().nth(MAX_SHOWN).is_some() {
        cut.push('…');
    }
    escape_for_display(&cut)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn of(link: &str) -> AppLink {
        explain(link.as_bytes()).unwrap_or_else(|| panic!("{link}: not explained"))
    }

    #[test]
    fn web_addresses_and_plain_text_are_not_app_links() {
        for text in [
            "https://example.com/",
            "http://example.com",
            "example.com",
            "localhost:8080",
        ] {
            assert_eq!(explain(text.as_bytes()), None, "{text}");
        }
    }

    #[test]
    fn a_payment_request_is_danger_with_its_amount_and_payee() {
        let upi = of(
            "upi://pay?pa=scammer@okbank&pn=Prize%20Office&am=4999&cu=INR&tn=Claim%20your%20prize",
        );
        assert_eq!(upi.risk, Risk::Danger);
        assert!(
            upi.does
                .contains("pay 4999 INR to scammer@okbank (Prize Office)"),
            "{upi:?}"
        );
        assert!(upi.details.iter().any(|d| d.contains("Claim your prize")));
        let btc = of("bitcoin:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh?amount=0.5");
        assert_eq!(btc.risk, Risk::Danger);
        assert!(
            btc.does
                .contains("send 0.5 bitcoin to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"),
            "{btc:?}"
        );
        assert_eq!(
            of("wc:8a5e5bdc-a0e4-47@2?relay-protocol=irn&symKey=abc").risk,
            Risk::Danger
        );
    }

    #[test]
    fn intents_name_the_app_and_what_they_ask() {
        let wa = of(
            "intent://send?phone=15551234567&text=hi#Intent;scheme=whatsapp;package=com.whatsapp;end",
        );
        assert_eq!(wa.app.as_deref(), Some("WhatsApp"));
        assert!(wa.does.contains("send a message to 15551234567"), "{wa:?}");
        let pay = of("intent://pay?pa=x@upi&am=10#Intent;scheme=upi;package=com.phonepe.app;end");
        assert_eq!(
            (pay.risk, pay.app.as_deref()),
            (Risk::Danger, Some("PhonePe"))
        );
        let access = of("intent:#Intent;action=android.settings.ACCESSIBILITY_SETTINGS;end");
        assert_eq!(access.risk, Risk::Danger);
        assert!(access.does.contains("accessibility"));
        let apk = of(
            "intent://evil.example/app.apk#Intent;scheme=https;type=application/vnd.android.package-archive;end",
        );
        assert_eq!(apk.risk, Risk::Danger);
        let fallback = of(
            "intent://scan/#Intent;scheme=zxing;package=com.google.zxing.client.android;S.browser_fallback_url=https%3A%2F%2Fevil.example%2Fx;end",
        );
        assert_eq!(fallback.fallback.as_deref(), Some("https://evil.example/x"));
        assert_eq!(fallback.app.as_deref(), Some("Barcode Scanner"));
        let unknown = of("intent://x#Intent;scheme=weird;package=com.unknown.app;end");
        assert!(
            unknown.details.iter().any(|d| d == "App: com.unknown.app"),
            "{unknown:?}"
        );
        let android_app = of("android-app://com.whatsapp/whatsapp/send?phone=1");
        assert_eq!(android_app.app.as_deref(), Some("WhatsApp"));
        // A fallback that is not a web address is not offered for checking.
        assert_eq!(
            of("intent://x#Intent;S.browser_fallback_url=javascript:alert(1);end").fallback,
            None
        );
    }

    #[test]
    fn phone_codes_texts_and_sign_in_approvals() {
        assert_eq!(of("tel:*21*5551234%23").risk, Risk::Danger);
        let call = of("tel:+44 900 123");
        assert_eq!(call.risk, Risk::Warning);
        let sms = of("sms:80080?body=JOIN%20VIP");
        assert!(
            sms.details.iter().any(|d| d.contains("JOIN VIP")),
            "{sms:?}"
        );
        assert_eq!(of("tg://login?token=abc").risk, Risk::Danger);
        assert!(
            of("tg://resolve?domain=freecrypto")
                .does
                .contains("@freecrypto")
        );
        assert_eq!(of("mailto:a@example.com?subject=hello").risk, Risk::Note);
        assert!(
            of("market://details?id=com.fake.bank")
                .does
                .contains("com.fake.bank")
        );
    }

    #[test]
    fn code_files_and_unknown_apps() {
        assert_eq!(of("javascript:alert(document.cookie)").risk, Risk::Danger);
        assert_eq!(of("data:text/html;base64,PGgxPg==").risk, Risk::Warning);
        assert_eq!(of("file:///sdcard/DCIM/x.jpg").risk, Risk::Danger);
        assert_eq!(
            of("zoommtg://zoom.us/join?confno=1").app.as_deref(),
            Some("Zoom")
        );
        let unknown = of("weirdapp://do/thing");
        assert!(unknown.does.contains("\"weirdapp:\""), "{unknown:?}");
    }

    #[test]
    fn what_is_shown_is_cut_short_and_escaped() {
        let long = format!("upi://pay?pa={}&am=1", "a".repeat(5000));
        let upi = of(&long);
        assert!(upi.does.chars().count() < 300, "{}", upi.does.len());
        let tricky = of("sms:1?body=%E2%80%AEevil%0Anext");
        let joined = tricky.details.join(" ");
        assert!(
            !joined.contains('\u{202e}') && !joined.contains('\n'),
            "{joined:?}"
        );
        // Not UTF-8, oversized, or not parseable: still explained by scheme.
        assert!(explain(b"intent:\xff\xfe#Intent;end").is_some());
        assert!(explain(format!("tel:{}", "1".repeat(20_000)).as_bytes()).is_some());
    }
}
