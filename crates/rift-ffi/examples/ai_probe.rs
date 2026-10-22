//! Prints Rift AI's view of each argument (a maintainer's probe), with the
//! shipped model or the one `RIFT_MODEL` names.
fn main() {
    let path = std::env::var("RIFT_MODEL").unwrap_or_else(|_| "models/url-model.bin".to_owned());
    let ai = rift_ffi::Ai::load(std::fs::read(path).unwrap_or_default());
    let Ok(ai) = ai else {
        return eprintln!("no model");
    };
    for url in std::env::args().skip(1) {
        println!("{:?}  {url}", ai.assess(url.clone()));
    }
}
