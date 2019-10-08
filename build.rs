#[cfg(target_os = "windows")]
use bindgen;

use std::env;
#[cfg(target_os = "windows")]
use std::path::PathBuf;

#[cfg(target_os = "windows")]
fn main() {
    let bindings = bindgen::Builder::default()
        .header("src/wrapper-windows.h")
        .whitelist_function("NCryptSignHash")
        .generate()
        .expect("Unable to generate bindings");
    let out_path = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR unset?"));
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings");
}
