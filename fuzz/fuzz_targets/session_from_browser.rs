//! On Linux the browser host runs the engine, so the controller treats every
//! datagram from it as untrusted (docs/architecture.md §9.2). Decoding must
//! never panic, must keep every bound, and a message that decodes must
//! decode the same after encoding again.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rift_protocol::session::{
    FromBrowser, MAX_ENGINE_BYTES, MAX_URL_BYTES, MAX_USER_AGENT_BYTES, decode_from_browser,
    encode_message,
};

fuzz_target!(|data: &[u8]| {
    let Ok(message) = decode_from_browser(data) else {
        return;
    };
    match &message {
        FromBrowser::Hello { engine, .. } => assert!(engine.len() <= MAX_ENGINE_BYTES),
        FromBrowser::Decide { url, .. } => assert!(url.len() <= MAX_URL_BYTES),
        FromBrowser::Download { url, user_agent } => {
            assert!(url.len() <= MAX_URL_BYTES && user_agent.len() <= MAX_USER_AGENT_BYTES);
        }
        FromBrowser::Renderer { .. } | FromBrowser::Connection | FromBrowser::Closing => {}
    }
    let encoded = encode_message(&message).expect("a decoded message encodes");
    assert_eq!(
        decode_from_browser(&encoded).expect("its encoding decodes"),
        message
    );
});
