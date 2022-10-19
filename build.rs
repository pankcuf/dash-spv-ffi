extern crate cbindgen;

use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let mut config: cbindgen::Config =
        cbindgen::Config::from_file("./cbindgen.toml").expect("Error config");
    config.language = cbindgen::Language::C;
    config.parse = cbindgen::ParseConfig {
        parse_deps: true,
        include: Some(vec!["dash-spv-models".to_string()]),
        extra_bindings: vec!["dash-spv-models".to_string()],
        ..Default::default()
    };
    cbindgen::generate_with_config(&crate_dir, config)
        .unwrap()
        .write_to_file("target/dash_spv_ffi.h");
}
