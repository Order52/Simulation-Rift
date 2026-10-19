//! The egress proxy parses request heads sent by the browser app, which an
//! engine escape may control. Parsing must never panic, and whatever it
//! accepts must name one checkable destination and carry no line breaks or
//! control characters into the head that is forwarded upstream.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rift_core::egress::{Form, parse_head};

fuzz_target!(|head: &[u8]| {
    let Ok(request) = parse_head(head) else { return };
    assert_ne!(request.target.port, 0);
    assert!(!request.target.host.is_empty());
    assert!(
        request.target.host.bytes().all(|b| b.is_ascii_graphic()),
        "{:?}",
        request.target.host
    );
    if let Form::Absolute { origin_form } = &request.form {
        assert!(origin_form.starts_with('/'), "{origin_form:?}");
        assert!(!origin_form.bytes().any(|b| b.is_ascii_control() || b == b' '), "{origin_form:?}");
    }
    for (name, value) in &request.headers {
        assert!(!name.is_empty() && name.bytes().all(|b| b.is_ascii_graphic() && !b.is_ascii_uppercase()));
        assert!(!value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0));
    }
});
