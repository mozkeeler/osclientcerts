#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_variables)]
#![allow(dead_code)]

use core_foundation::array::*;
use core_foundation::base::*;
use core_foundation::boolean::*;
use core_foundation::data::*;
use core_foundation::dictionary::*;
use core_foundation::error::*;
use core_foundation::string::*;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use std::os::raw::c_void;

#[repr(C)]
pub struct __SecIdentity(c_void);
pub type SecIdentityRef = *const __SecIdentity;
declare_TCFType!(SecIdentity, SecIdentityRef);
impl_TCFType!(SecIdentity, SecIdentityRef, SecIdentityGetTypeID);

#[repr(C)]
pub struct __SecCertificate(c_void);
pub type SecCertificateRef = *const __SecCertificate;
declare_TCFType!(SecCertificate, SecCertificateRef);
impl_TCFType!(SecCertificate, SecCertificateRef, SecCertificateGetTypeID);

// id is a persistent reference that refers to a SecIdentity that was retrieved
// via kSecReturnPersistentRef. It can be used with SecItemCopyMatching with
// kSecItemMatchList to obtain a handle on the original SecIdentity.
// https://developer.apple.com/documentation/security/keychain_services/keychain_items/item_return_result_keys
pub struct Cert {
    id: Vec<u8>,
    label: Vec<u8>,
    der: Vec<u8>,
    issuer: Vec<u8>,
    serial_number: Vec<u8>,
    subject: Vec<u8>,
}

impl Cert {
    pub fn label(&self) -> &[u8] {
        &self.label
    }

    pub fn value(&self) -> &[u8] {
        &self.der
    }

    pub fn issuer(&self) -> &[u8] {
        &self.issuer
    }

    pub fn serial_number(&self) -> &[u8] {
        &self.serial_number
    }

    pub fn subject(&self) -> &[u8] {
        &self.subject
    }
}

pub fn list_certs() -> Vec<Cert> {
    let mut certs = Vec::new();
    if let Some(identities) = list_identities_as_persistent_refs() {
        for identity in identities.iter() {
            if let Some(cert) = get_cert_helper(&identity) {
                certs.push(cert);
            }
        }
    }
    certs
}

fn get_cert_helper(id: &CFData) -> Option<Cert> {
    unsafe {
        let status = SecKeychainUnlock(std::ptr::null_mut(), 0, std::ptr::null(), 0);
        if status != errSecSuccess {
            eprintln!("SecKeychainUnlock failed: {}", status);
            return None;
        }
        let id_data_slice = [id.as_CFType()];
        let ids = CFArray::from_CFTypes(&id_data_slice);

        let class_key = CFString::wrap_under_get_rule(kSecClass);
        let class_value = CFString::wrap_under_get_rule(kSecClassIdentity);
        let match_key = CFString::wrap_under_get_rule(kSecMatchItemList);
        let match_value = ids;
        let return_ref_key = CFString::wrap_under_get_rule(kSecReturnRef);
        let return_ref_value = CFBoolean::wrap_under_get_rule(kCFBooleanTrue);
        let vals = vec![
            (class_key.as_CFType(), class_value.as_CFType()),
            (match_key.as_CFType(), match_value.as_CFType()),
            (return_ref_key.as_CFType(), return_ref_value.as_CFType()),
        ];
        let dict = CFDictionary::from_CFType_pairs(&vals);
        let mut identity = std::ptr::null();
        let status = SecItemCopyMatching(dict.as_CFTypeRef() as CFDictionaryRef, &mut identity);
        if status != errSecSuccess {
            eprintln!("SecItemCopyMatching failed: {}", status);
            return None;
        }
        if identity.is_null() {
            eprintln!("couldn't get ref from id?");
            return None;
        }
        let identity: SecIdentityRef = identity as SecIdentityRef;
        let mut certificate = std::ptr::null();
        let status = SecIdentityCopyCertificate(identity, &mut certificate);
        if status != errSecSuccess {
            eprintln!("SecIdentityCopyCertificate failed: {}", status);
            return None;
        }
        if certificate.is_null() {
            eprintln!("couldn't get certificate from identity?");
            return None;
        }
        let certificate: SecCertificateRef = certificate as SecCertificateRef;
        let label = CFString::wrap_under_create_rule(SecCertificateCopySubjectSummary(certificate));
        let der = CFData::wrap_under_create_rule(SecCertificateCopyData(certificate));
        let issuer =
            CFData::wrap_under_create_rule(SecCertificateCopyNormalizedIssuerSequence(certificate));
        let serial_number = CFData::wrap_under_create_rule(SecCertificateCopySerialNumberData(
            certificate,
            std::ptr::null_mut(),
        ));
        let subject = CFData::wrap_under_create_rule(SecCertificateCopyNormalizedSubjectSequence(
            certificate,
        ));

        Some(Cert {
            id: id.bytes().to_vec(),
            label: label.to_string().into_bytes(),
            der: der.bytes().to_vec(),
            issuer: issuer.bytes().to_vec(),
            serial_number: serial_number.bytes().to_vec(),
            subject: subject.bytes().to_vec(),
        })
    }
}

// Attempt to list all known `SecIdentity`s as persistent identifiers that we
// can cache for use later.
fn list_identities_as_persistent_refs() -> Option<CFArray<CFData>> {
    unsafe {
        let status = SecKeychainUnlock(std::ptr::null_mut(), 0, std::ptr::null(), 0);
        if status != errSecSuccess {
            eprintln!("SecKeychainUnlock failed: {}", status);
            return None;
        }
        let class_key = CFString::wrap_under_get_rule(kSecClass);
        let class_value = CFString::wrap_under_get_rule(kSecClassIdentity);
        let return_ref_key = CFString::wrap_under_get_rule(kSecReturnPersistentRef);
        let return_ref_value = CFBoolean::wrap_under_get_rule(kCFBooleanTrue);
        let match_key = CFString::wrap_under_get_rule(kSecMatchLimit);
        let match_value = CFString::wrap_under_get_rule(kSecMatchLimitAll);
        let vals = vec![
            (class_key.as_CFType(), class_value.as_CFType()),
            (return_ref_key.as_CFType(), return_ref_value.as_CFType()),
            (match_key.as_CFType(), match_value.as_CFType()),
        ];
        let dict = CFDictionary::from_CFType_pairs(&vals);
        let mut result = std::ptr::null();
        let status = SecItemCopyMatching(dict.as_CFTypeRef() as CFDictionaryRef, &mut result);
        if status != errSecSuccess {
            eprintln!("SecItemCopyMatching failed: {}", status);
            return None;
        }
        if result.is_null() {
            eprintln!("no client certs?");
            return None;
        }
        let result: CFArray<CFData> = CFArray::wrap_under_get_rule(result as CFArrayRef);
        eprintln!("{}", result.len());
        Some(result)
    }
}
