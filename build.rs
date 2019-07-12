use bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    let bindings = bindgen::Builder::default()
        .header("src/wrapper.h")
        .blacklist_type("^CF.*Ref")
        .blacklist_type("^SecIdentity.*")
        .blacklist_type("^SecCertificate.*")
        .whitelist_function("SecItemCopyMatching")
        .whitelist_function("SecCertificateCopyData")
        .whitelist_function("SecCertificateGetTypeID")
        .whitelist_function("SecIdentityCopyCertificate")
        .whitelist_function("^SecKey.*")
        .whitelist_function("^SecIdentity.*")
        .blacklist_function("^SecIdentitySearch.*")
        .whitelist_var("^kSec.*")
        .whitelist_var("^errSec.*")
        .generate()
        .expect("Unable to generate bindings");
    let out_path = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR unset?"));
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings");
}
