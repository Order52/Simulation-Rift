//! The core as a QML object: QML calls Rust in the same process, with no C
//! ABI layer of Rift's own. Only what the UI needs crosses, as Qt strings.

#[cxx_qt::bridge]
pub mod qobject {
    // cxx's declaration of a C++ type that Rust uses; cxx generates and
    // checks the binding, so no hand-written unsafe code follows from it.
    unsafe extern "C++" {
        include!("cxx-qt-lib/qstring.h");
        type QString = cxx_qt_lib::QString;
    }

    extern "RustQt" {
        #[qobject]
        #[qml_element]
        type RiftCore = super::RiftCoreRust;

        /// The canonical form of `url` (Safe Browsing rules), or the reason
        /// it has none.
        #[qinvokable]
        fn canonicalize(&self, url: &QString) -> QString;
    }
}

use cxx_qt_lib::QString;

#[derive(Default)]
pub struct RiftCoreRust;

impl qobject::RiftCore {
    pub fn canonicalize(&self, url: &QString) -> QString {
        match rift_core::urlcanon::canonicalize(String::from(url).as_bytes()) {
            Ok(canonical) => QString::from(canonical.to_string().as_str()),
            Err(error) => QString::from(format!("refused: {error}").as_str()),
        }
    }
}
