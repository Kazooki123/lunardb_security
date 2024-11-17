use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let header_path = PathBuf::from("include/lunar_security.h");

    let config = cbindgen::Config {
        language: cbindgen::Language::C,
        include_guard: Some("LUNAR_SECURITY_H".to_string()),
        pragma_once: true,
        documentation: true,
        cpp_compat: true,
        ..Default::default()
    };

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(&header_path);
}
