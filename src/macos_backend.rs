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

use byteorder::{ByteOrder, NativeEndian, WriteBytesExt};
use std::os::raw::c_void;

use crate::types::*;

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

#[repr(C)]
pub struct __SecKey(c_void);
pub type SecKeyRef = *const __SecKey;
declare_TCFType!(SecKey, SecKeyRef);
impl_TCFType!(SecKey, SecKeyRef, SecKeyGetTypeID);

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

    pub fn matches(&self, attrs: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> bool {
        for (attr_type, attr_value) in attrs {
            match *attr_type {
                CKA_CLASS => {
                    if attr_value.len() > 8 || attr_value.len() < 1 {
                        return false;
                    }
                    if NativeEndian::read_uint(&attr_value, attr_value.len()) != CKO_CERTIFICATE {
                        return false;
                    }
                }
                CKA_TOKEN => {} // TODO: do we need to do anything here?
                CKA_ISSUER => {
                    eprintln!("{:?}", attr_value);
                    eprintln!("{:?}", self.issuer());
                    if attr_value.as_slice() != self.issuer() {
                        return false;
                    }
                }
                CKA_SERIAL_NUMBER => {
                    eprintln!("{:?}", attr_value);
                    eprintln!("{:?}", self.serial_number());
                    if attr_value.as_slice() != self.serial_number() {
                        return false;
                    }
                }
                CKA_SUBJECT => {
                    eprintln!("{:?}", attr_value);
                    eprintln!("{:?}", self.subject());
                    if attr_value.as_slice() != self.subject() {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        true
    }

    fn get_attribute(&self, attribute: CK_ATTRIBUTE_TYPE) -> Option<&[u8]> {
        let result = match attribute {
            CKA_LABEL => self.label(),
            CKA_VALUE => self.value(),
            CKA_ISSUER => self.issuer(),
            CKA_SERIAL_NUMBER => self.serial_number(),
            CKA_SUBJECT => self.subject(),
            _ => return None,
        };
        Some(result)
    }
}

pub struct Key {
    id: Vec<u8>,
    private: Vec<u8>,
    key_type: Vec<u8>,
}

impl Key {
    fn matches(&self, attrs: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> bool {
        for (attr_type, attr_value) in attrs {
            match *attr_type {
                CKA_CLASS => {
                    if attr_value.len() > 8 || attr_value.len() < 1 {
                        return false;
                    }
                    if NativeEndian::read_uint(&attr_value, attr_value.len()) != CKO_PRIVATE_KEY {
                        return false;
                    }
                }
                CKA_TOKEN => {} // TODO: do we need to do anything here?
                _ => return false,
            }
        }
        true
    }

    fn get_attribute(&self, attribute: CK_ATTRIBUTE_TYPE) -> Option<&[u8]> {
        let result = match attribute {
            CKA_PRIVATE => self.private(),
            CKA_KEY_TYPE => self.key_type(),
            _ => return None,
        };
        Some(result)
    }

    fn key_type(&self) -> &[u8] {
        &self.key_type
    }

    fn private(&self) -> &[u8] {
        &self.private
    }
}

pub enum Object {
    Cert(Cert),
    Key(Key),
}

impl Object {
    pub fn matches(&self, attrs: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> bool {
        match self {
            Object::Cert(cert) => cert.matches(attrs),
            Object::Key(key) => key.matches(attrs),
        }
    }

    pub fn get_attribute(&self, attribute: CK_ATTRIBUTE_TYPE) -> Option<&[u8]> {
        match self {
            Object::Cert(cert) => cert.get_attribute(attribute),
            Object::Key(key) => key.get_attribute(attribute),
        }
    }
}

pub fn list_objects() -> Vec<Object> {
    let mut objects = Vec::new();
    if let Some(identities) = list_identities_as_persistent_refs() {
        for identity in identities.iter() {
            if let Some(cert) = get_cert_helper(&identity) {
                objects.push(Object::Cert(cert));
            }
            if let Some(key) = get_key_helper(&identity) {
                objects.push(Object::Key(key));
            }
        }
    }
    objects
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

fn get_key_helper(id: &CFData) -> Option<Key> {
    unsafe {
        // TODO: refactor common code
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
        let mut key = std::ptr::null();
        // I think this is causing an auth prompt to come up. Can we use
        // kSecReturnAttributes when we search instead? (but then we get
        // attributes of the /identity/?
        let status = SecIdentityCopyPrivateKey(identity, &mut key);
        if status != errSecSuccess {
            eprintln!("SecIdentityCopyPrivateKey failed: {}", status);
            return None;
        }
        if key.is_null() {
            eprintln!("couldn't get key from identity?");
            return None;
        }
        let key: SecKeyRef = key as SecKeyRef;
        // TODO: is SecKeyCopyAttributes fallible? will wrap_under_create_rule panic?
        let attributes: CFDictionary<CFString, CFString> =
            CFDictionary::wrap_under_create_rule(SecKeyCopyAttributes(key));
        let key_type = match attributes.find(kSecAttrKeyType as *const _) {
            Some(key_type) => key_type,
            //Some(key_type) => TCFType::wrap_under_get_rule(*key_type as CFStringRef),
            None => {
                eprintln!("couldn't get kSecAttrKeyType?");
                return None;
            }
        };
        let key_type_value = if *key_type == CFString::wrap_under_get_rule(kSecAttrKeyTypeRSA) {
            eprintln!("RSA key");
            CKK_RSA
        } else if *key_type == CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom) {
            eprintln!("EC key");
            CKK_EC
        } else {
            eprintln!("unsupported key type");
            return None;
        };
        let key_type_size = std::mem::size_of::<CK_KEY_TYPE>();
        let mut key_type_buf = Vec::with_capacity(key_type_size);
        match key_type_buf.write_uint::<NativeEndian>(key_type_value, key_type_size) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("error serializing key type: {}", e);
                return None;
            }
        };
        Some(Key {
            id: id.bytes().to_vec(),
            private: vec![1],
            key_type: key_type_buf,
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
