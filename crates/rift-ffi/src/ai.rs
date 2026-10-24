//! Rift AI for the platforms (docs/architecture.md §16): the URL model,
//! loaded from bytes the app ships or from the installed pack (which takes
//! precedence while it is current), and the link check the home screen's
//! "Check" button shows.

use std::sync::Arc;
use std::time::Instant;

use rift_core::policy::{self, AiFinding};
use rift_core::text::escape_for_display;
use rift_core::urlcanon;
use rift_core::urlmodel::{Assessment, Level, ModelError, UrlModel, View};

use crate::{Intel, Navigation, Navigator};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum AiFailure {
    /// The bytes are not a model this build can use; Rift runs without it.
    #[error("Rift AI is unavailable: {reason}")]
    Unusable { reason: String },
}

impl From<ModelError> for AiFailure {
    fn from(error: ModelError) -> Self {
        Self::Unusable {
            reason: error.to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AiLevel {
    /// Nothing the model recognises. Never shown as "safe".
    Low,
    Elevated,
    High,
}

/// What Rift AI says about one address.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AiView {
    /// 0 to 99.
    pub score: u8,
    pub level: AiLevel,
    /// Up to three readable reasons, strongest first; empty when low.
    pub signals: Vec<String>,
    /// The address is on one of the most visited sites, which the model
    /// does not score (§16); the threat database still checks it.
    pub abstained: bool,
}

impl AiView {
    fn of(assessment: &Assessment) -> Self {
        Self {
            score: assessment.risk,
            level: match assessment.level {
                Level::Low => AiLevel::Low,
                Level::Elevated => AiLevel::Elevated,
                Level::High => AiLevel::High,
            },
            signals: assessment.signals.clone(),
            abstained: assessment.abstained,
        }
    }
}

/// A link checked without opening it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LinkCheck {
    /// The address as the engine would load it, escaped for display.
    pub address: String,
    /// What "Open safely" would do with it (nothing is loaded by a check).
    pub navigation: Navigation,
    /// None if Rift AI is not loaded, or the text is not a web address.
    pub ai: Option<AiView>,
    /// How long the whole check took, in microseconds.
    pub micros: u64,
}

/// A loaded, validated URL model.
#[derive(Debug, uniffi::Object)]
pub struct Ai {
    pub(crate) model: UrlModel,
}

#[uniffi::export]
impl Ai {
    /// Reads a model file. Every number in it is checked before use.
    #[uniffi::constructor]
    pub fn load(bytes: Vec<u8>) -> Result<Arc<Self>, AiFailure> {
        Ok(Arc::new(Self {
            model: UrlModel::parse(&bytes)?,
        }))
    }

    /// SHA-256 of the model file, for the protection details.
    pub fn digest(&self) -> String {
        self.model.digest_hex()
    }

    /// The model's view of `url` as an address (a check, or a test).
    pub fn assess(&self, url: String) -> Option<AiView> {
        assess(&self.model, &url, View::Address)
    }
}

pub(crate) fn assess(model: &UrlModel, url: &str, view: View) -> Option<AiView> {
    let address = policy::engine_address(url.as_bytes())?;
    let canonical = urlcanon::canonicalize(address.as_bytes()).ok()?;
    Some(AiView::of(&model.assess(&canonical, view)))
}

/// The proxy's remark on a destination Rift AI rates High (§16: noted in
/// the live watch, never refused for it).
pub(crate) fn remark(model: &UrlModel, url: &urlcanon::CanonicalUrl, view: View) -> Option<String> {
    let assessment = model.assess(url, view);
    if assessment.level != Level::High {
        return None;
    }
    let finding = AiFinding::from_assessment(&assessment);
    let because = if finding.signals.is_empty() {
        String::new()
    } else {
        format!(" What stood out: {}.", finding.signals.join("; "))
    };
    Some(format!(
        "Rift AI: {} closely resembles known malicious {} ({}/100).{because} A resemblance, not proof.",
        escape_for_display(url.host()),
        if view == View::Address {
            "links"
        } else {
            "hosts"
        },
        finding.score,
    ))
}

#[uniffi::export]
impl Navigator {
    /// Checks `url` as "Open safely" would decide it, without loading
    /// anything, and with Rift AI's score whatever its level.
    pub fn check(&self, url: String, intel: Option<Arc<Intel>>, now_unix: u64) -> LinkCheck {
        let started = Instant::now();
        // Nothing is loaded, so the engine's sandbox is not in question.
        let pack = intel.as_ref().and_then(|intel| intel.pack());
        let navigation = self.decide(url.clone(), true, intel, now_unix);
        let model = pack
            .as_ref()
            .and_then(|pack| pack.model.as_deref())
            .or(self.ai.as_ref().map(|ai| &ai.model));
        let ai = model.and_then(|model| assess(model, &url, View::Address));
        let address = policy::engine_address(url.as_bytes()).unwrap_or(url);
        LinkCheck {
            address: escape_for_display(&address),
            navigation,
            ai,
            micros: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        }
    }

    /// Whether Rift AI is loaded in this navigator.
    pub fn has_ai(&self) -> bool {
        self.ai.is_some()
    }
}

#[uniffi::export]
impl Intel {
    /// SHA-256 of the installed pack's model, if it has one: that model is
    /// used in place of the app's own.
    pub fn ai_digest(&self) -> Option<String> {
        Some(self.pack()?.model.as_ref()?.digest_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The model the apps ship (models/url-model.bin, made by rift-train).
    fn shipped() -> Arc<Ai> {
        Ai::load(include_bytes!("../../../models/url-model.bin").to_vec()).unwrap()
    }

    #[test]
    fn the_shipped_model_is_the_one_its_report_describes() {
        let ai = shipped();
        let report = include_str!("../../../models/url-model.json");
        assert!(report.contains(&format!("\"sha256\": \"{}\"", ai.digest())));
    }

    #[test]
    fn the_shipped_model_does_not_score_the_most_visited_sites() {
        let ai = shipped();
        for url in [
            "https://mail.google.com/mail/u/0/",
            "https://accounts.google.com/signin",
            "https://login.microsoftonline.com/common/oauth2/authorize",
            "https://outlook.live.com/mail/0/",
            "https://www.paypal.com/signin",
        ] {
            let view = ai.assess(url.into()).unwrap();
            assert!(
                view.abstained && view.level == AiLevel::Low && view.score == 0,
                "{url}: {view:?}"
            );
        }
    }

    #[test]
    fn the_shipped_model_rates_lookalikes_high_and_ordinary_sites_low() {
        let ai = shipped();
        for url in [
            "http://secure-paypal-login.verify-account.xyz/signin/update.php?id=1",
            "https://appleid.apple.com.account-verify.top/",
            "https://paypa1-secure.workers.dev/login",
            "https://chase-online-verify.netlify.app/login",
            "http://192.168.4.20/bank/login.php",
            "https://metamask-wallet-restore.pages.dev/",
            "https://appleid-verify-account.web.app/",
        ] {
            let view = ai.assess(url.into()).unwrap();
            assert!(
                view.level == AiLevel::High && !view.signals.is_empty(),
                "{url}: {view:?}"
            );
        }
        // Ordinary sites, some on the same platforms the fakes use.
        for url in [
            "https://rust-lang.github.io/rustup/",
            "https://my-portfolio.vercel.app/",
            "https://hello-world.workers.dev/",
            "https://shop.local-hardware.de/kontakt",
            "https://www.uot.edu.ly/",
            "https://my-portfolio.pages.dev/",
            "https://todo-app-3f2a1.web.app/",
        ] {
            let view = ai.assess(url.into()).unwrap();
            assert_eq!(view.level, AiLevel::Low, "{url}: {view:?}");
            assert!(!view.abstained, "{url}");
        }
        assert_eq!(ai.assess("javascript:alert(1)".into()), None);
    }
}
