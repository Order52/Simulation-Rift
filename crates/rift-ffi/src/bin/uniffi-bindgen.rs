//! Generates foreign-language bindings from the compiled rift-ffi library:
//! `cargo run -p rift-ffi --features bindgen --bin uniffi-bindgen -- generate --library <lib> --language kotlin --out-dir <dir>`

fn main() {
    uniffi::uniffi_bindgen_main()
}
