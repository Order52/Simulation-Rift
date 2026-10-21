//! Prints Rift AI's view of each argument (a maintainer's probe).
fn main() {
    let ai = rift_ffi::Ai::load(std::fs::read("models/url-model.bin").unwrap_or_default());
    let Ok(ai) = ai else {
        return eprintln!("no model");
    };
    for url in std::env::args().skip(1) {
        println!("{:?}  {url}", ai.assess(url.clone()));
    }
}
