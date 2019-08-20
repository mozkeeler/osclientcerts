#[cfg(target_os = "windows")]
use bindgen;

use std::env;
#[cfg(target_os = "windows")]
use std::path::PathBuf;

#[cfg(not(target_os = "windows"))]
fn main() {
    if let Ok(macos_sdk_dir) = env::var("MACOS_SDK_DIR") {
        println!("cargo:rustc-link-search={}", macos_sdk_dir);
        println!("cargo:rustc-link-search={}/System", macos_sdk_dir);
        println!("cargo:rustc-link-search={}/System/Library", macos_sdk_dir);
        println!(
            "cargo:rustc-link-search={}/System/Library/Frameworks",
            macos_sdk_dir
        );
        println!(
            "cargo:rustc-link-search={}/System/Library/Frameworks/Security.framework",
            macos_sdk_dir
        );
    };
    if env::var("TARGET")
        .expect("TARGET unset?")
        .contains("-apple")
    {
        println!("cargo:rustc-link-lib=framework=Security");
    }
}

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
