use bindgen;

use std::env;
use std::path::PathBuf;

#[cfg(target_os = "macos")]
fn main() {
    let bindings = bindgen::Builder::default()
        .header("src/wrapper-macos.h")
        .blacklist_type("CFDataRef")
        .blacklist_type("CFDictionaryRef")
        .blacklist_type("CFErrorRef")
        .blacklist_type("CFStringRef")
        .blacklist_type("SecCertificateRef")
        .blacklist_type("SecIdentityRef")
        .blacklist_type("SecKeyRef")
        .whitelist_function("SecCertificateCopyData")
        .whitelist_function("SecCertificateCopyKey")
        .whitelist_function("SecCertificateCopyNormalizedIssuerSequence")
        .whitelist_function("SecCertificateCopyNormalizedSubjectSequence")
        .whitelist_function("SecCertificateCopySerialNumberData")
        .whitelist_function("SecCertificateCopySubjectSummary")
        .whitelist_function("SecCertificateGetTypeID")
        .whitelist_function("SecIdentityCopyCertificate")
        .whitelist_function("SecIdentityCopyCertificate")
        .whitelist_function("SecIdentityCopyPrivateKey")
        .whitelist_function("SecIdentityGetTypeID")
        .whitelist_function("SecItemCopyMatching")
        .whitelist_function("SecKeyCopyAttributes")
        .whitelist_function("SecKeyCopyExternalRepresentation")
        .whitelist_function("SecKeyCreateSignature")
        .whitelist_function("SecKeyGetTypeID")
        .whitelist_var("errSecSuccess")
        .whitelist_var("kSecAttrKeySizeInBits")
        .whitelist_var("kSecAttrKeyType")
        .whitelist_var("kSecAttrKeyTypeECSECPrimeRandom")
        .whitelist_var("kSecAttrKeyTypeRSA")
        .whitelist_var("kSecClass")
        .whitelist_var("kSecClassIdentity")
        .whitelist_var("kSecKeyAlgorithmECDSASignatureDigestX962SHA256")
        .whitelist_var("kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256")
        .whitelist_var("kSecMatchLimit")
        .whitelist_var("kSecMatchLimitAll")
        .whitelist_var("kSecReturnRef")
        .generate()
        .expect("Unable to generate bindings");
    let out_path = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR unset?"));
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings");
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
