use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap_or_else(|_| "target/bpf".to_string());
    let bin_name = env::var("CARGO_BIN_NAME").unwrap_or_else(|_| "haltchain".to_string());
    let src = format!("{}/{}", out_dir, bin_name);
    let dst = format!("{}/haltchain.o", out_dir);

    if Path::new(&src).exists() {
        fs::copy(&src, &dst).ok();
    }

    println!("cargo:rerun-if-changed=src/main.rs");
}
