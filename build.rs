extern crate cbindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let header_path = PathBuf::from("include/lunar_security.h");

    let config = cbindgen::Config::builder()
        .with_language(cbindgen::Language::Cxx)
        .with_namespace("lunar_security")
        .with_parse_deps(true)
        .with_parse_include(&["lunar_security"])
        .with_documentation(true)
        .with_cpp_compat(true)
        .with_pragma_once(true)
        .build()
        .unwrap();

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(&header_path);
}
