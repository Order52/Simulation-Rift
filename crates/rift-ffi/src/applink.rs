//! Links that leave the web, explained for Check and the live watch (§10.15).

use rift_core::applink::{self, Risk};

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AppLinkRisk {
    Note,
    Warning,
    Danger,
}

/// What a link to another app would do; Rift never opens it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AppLinkView {
    pub scheme: String,
    pub app: Option<String>,
    pub does: String,
    pub details: Vec<String>,
    pub risk: AppLinkRisk,
    /// The web address used without the app, for Check to judge.
    pub fallback: Option<String>,
}

/// Explains `url` if it opens something other than a web page.
#[uniffi::export]
pub fn explain_app_link(url: String) -> Option<AppLinkView> {
    let link = applink::explain(url.as_bytes())?;
    Some(AppLinkView {
        scheme: link.scheme,
        app: link.app,
        does: link.does,
        details: link.details,
        risk: match link.risk {
            Risk::Note => AppLinkRisk::Note,
            Risk::Warning => AppLinkRisk::Warning,
            Risk::Danger => AppLinkRisk::Danger,
        },
        fallback: link.fallback,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_payment_link_reaches_the_app_as_danger() {
        let view = explain_app_link("upi://pay?pa=x@bank&am=10".into()).unwrap();
        assert_eq!(view.risk, AppLinkRisk::Danger);
        assert_eq!(explain_app_link("https://example.com/".into()), None);
    }
}
