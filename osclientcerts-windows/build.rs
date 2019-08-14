use bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    let bindings = bindgen::Builder::default()
        .header("src/wrapper.h")
        .whitelist_function("NCryptSignHash")
        .whitelist_type("BCRYPT_PKCS1_PADDING_INFO")
        .whitelist_var("NCRYPT_PAD_PKCS1_FLAG")
        .generate()
        .expect("Unable to generate bindings");
    let out_path = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR unset?"));
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings");
}
