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
use core_foundation::number::*;
use core_foundation::string::*;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use byteorder::{NativeEndian, WriteBytesExt};
use sha2::{Digest, Sha256};
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
    persistent_id: Vec<u8>,
    class: Vec<u8>,
    token: Vec<u8>,
    id: Vec<u8>,
    label: Vec<u8>,
    value: Vec<u8>,
    issuer: Vec<u8>,
    serial_number: Vec<u8>,
    subject: Vec<u8>,
}

impl Cert {
    fn class(&self) -> &[u8] {
        &self.class
    }

    fn token(&self) -> &[u8] {
        &self.token
    }

    fn id(&self) -> &[u8] {
        &self.id
    }

    fn label(&self) -> &[u8] {
        &self.label
    }

    fn value(&self) -> &[u8] {
        &self.value
    }

    fn issuer(&self) -> &[u8] {
        &self.issuer
    }

    fn serial_number(&self) -> &[u8] {
        &self.serial_number
    }

    fn subject(&self) -> &[u8] {
        &self.subject
    }

    fn matches(&self, attrs: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> bool {
        for (attr_type, attr_value) in attrs {
            let comparison = match *attr_type {
                CKA_CLASS => self.class(),
                CKA_TOKEN => self.token(),
                CKA_LABEL => self.label(),
                CKA_ID => self.id(),
                CKA_VALUE => self.value(),
                CKA_ISSUER => self.issuer(),
                CKA_SERIAL_NUMBER => self.serial_number(),
                CKA_SUBJECT => self.subject(),
                _ => return false,
            };
            eprintln!("{:?}", attr_value);
            eprintln!("{:?}", comparison);
            if attr_value.as_slice() != comparison {
                return false;
            }
        }
        true
    }

    fn get_attribute(&self, attribute: CK_ATTRIBUTE_TYPE) -> Option<&[u8]> {
        let result = match attribute {
            CKA_CLASS => self.class(),
            CKA_TOKEN => self.token(),
            CKA_LABEL => self.label(),
            CKA_ID => self.id(),
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
    persistent_id: Vec<u8>,
    class: Vec<u8>,
    token: Vec<u8>,
    id: Vec<u8>,
    private: Vec<u8>,
    key_type: Vec<u8>,
    ec_params: Vec<u8>,
}

impl Key {
    fn class(&self) -> &[u8] {
        &self.class
    }

    fn token(&self) -> &[u8] {
        &self.token
    }

    fn id(&self) -> &[u8] {
        &self.id
    }

    fn private(&self) -> &[u8] {
        &self.private
    }

    fn key_type(&self) -> &[u8] {
        &self.key_type
    }

    fn ec_params(&self) -> &[u8] {
        &self.ec_params
    }

    fn matches(&self, attrs: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> bool {
        for (attr_type, attr_value) in attrs {
            let comparison = match *attr_type {
                CKA_CLASS => self.class(),
                CKA_TOKEN => self.token(),
                CKA_ID => self.id(),
                CKA_PRIVATE => self.private(),
                CKA_KEY_TYPE => self.key_type(),
                CKA_EC_PARAMS => self.ec_params(),
                _ => return false,
            };
            eprintln!("{:?}", attr_value);
            eprintln!("{:?}", comparison);
            if attr_value.as_slice() != comparison {
                return false;
            }
        }
        true
    }

    fn get_attribute(&self, attribute: CK_ATTRIBUTE_TYPE) -> Option<&[u8]> {
        let result = match attribute {
            CKA_CLASS => self.class(),
            CKA_TOKEN => self.token(),
            CKA_ID => self.id(),
            CKA_PRIVATE => self.private(),
            CKA_KEY_TYPE => self.key_type(),
            CKA_EC_PARAMS => self.ec_params(),
            _ => return None,
        };
        Some(result)
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, ()> {
        unsafe {
            // TODO: refactor common code
            let id_data_slice = [CFData::from_buffer(&self.persistent_id).as_CFType()];
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
                return Err(());
            }
            if identity.is_null() {
                eprintln!("couldn't get ref from id?");
                return Err(());
            }
            let identity: SecIdentityRef = identity as SecIdentityRef;
            let mut key = std::ptr::null();
            let status = SecIdentityCopyPrivateKey(identity, &mut key);
            if status != errSecSuccess {
                eprintln!("SecItemCopyPrivateKey failed: {}", status);
                return Err(());
            }
            let data = CFData::from_buffer(data);
            let signature = CFData::wrap_under_create_rule(SecKeyCreateSignature(
                key,
                kSecKeyAlgorithmECDSASignatureRFC4754,
                data.as_concrete_TypeRef(),
                std::ptr::null_mut(),
            ));
            Ok((*signature).to_vec())
        }
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

fn serialize_uint<T: Into<u64>>(value: T) -> Vec<u8> {
    let value_size = std::mem::size_of::<T>();
    let mut value_buf = Vec::with_capacity(value_size);
    match value_buf.write_uint::<NativeEndian>(value.into(), value_size) {
        Ok(()) => value_buf,
        Err(e) => panic!("error serializing value: {}", e),
    }
}

fn get_cert_helper(id: &CFData) -> Option<Cert> {
    unsafe {
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
        let persistent_id = id.bytes().to_vec();
        let id = hex::encode(Sha256::digest(&persistent_id));

        Some(Cert {
            persistent_id,
            class: serialize_uint(CKO_CERTIFICATE),
            token: serialize_uint(CK_TRUE),
            id: id.into_bytes(),
            label: label.to_string().into_bytes(),
            value: der.bytes().to_vec(),
            issuer: issuer.bytes().to_vec(),
            serial_number: serial_number.bytes().to_vec(),
            subject: subject.bytes().to_vec(),
        })
    }
}

fn get_key_attribute<T: TCFType + Clone>(key: &SecKeyRef, attr: CFStringRef) -> Option<T> {
    // TODO: is SecKeyCopyAttributes fallible? will wrap_under_create_rule panic?
    let attributes: CFDictionary<CFString, T> =
        unsafe { CFDictionary::wrap_under_create_rule(SecKeyCopyAttributes(*key)) };
    match attributes.find(attr as *const _) {
        Some(value) => Some((*value).clone()),
        None => None,
    }
}

fn get_key_helper(id: &CFData) -> Option<Key> {
    unsafe {
        // TODO: refactor common code
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
        let key = SecCertificateCopyKey(certificate);
        if key.is_null() {
            eprintln!("couldn't get key from certificate?");
            return None;
        }
        let key: SecKeyRef = key as SecKeyRef;
        let key_type: CFString = match get_key_attribute(&key, kSecAttrKeyType) {
            Some(key_type) => key_type,
            None => {
                eprintln!("couldn't get kSecAttrKeyType?");
                return None;
            }
        };
        let key_size_in_bits: CFNumber = match get_key_attribute(&key, kSecAttrKeySizeInBits) {
            Some(key_size_in_bits) => key_size_in_bits,
            None => {
                eprintln!("couldn't get key size in bits");
                return None;
            }
        };
        let mut ec_params = Vec::new();
        let key_type_value = if key_type == CFString::wrap_under_get_rule(kSecAttrKeyTypeRSA) {
            CKK_RSA
        } else if key_type == CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom) {
            // Assume all EC keys are secp256r1, secp384r1, or secp521r1. This
            // is wrong, but the API doesn't seem to give us a way to determine
            // which curve this key is on.
            // This might not matter in practice, because it seems all NSS uses
            // this for is to get the signature size.
            match key_size_in_bits.to_i64() {
                Some(256) => ec_params.extend_from_slice(OID_BYTES_SECP256R1),
                Some(384) => ec_params.extend_from_slice(OID_BYTES_SECP384R1),
                Some(521) => ec_params.extend_from_slice(OID_BYTES_SECP521R1),
                _ => {
                    eprintln!("unsupported EC key");
                    return None;
                }
            };
            CKK_EC
        } else {
            eprintln!("unsupported key type");
            return None;
        };
        let persistent_id = id.bytes().to_vec();
        let id = hex::encode(Sha256::digest(&persistent_id));

        Some(Key {
            persistent_id,
            class: serialize_uint(CKO_PRIVATE_KEY),
            token: serialize_uint(CK_TRUE),
            id: id.into_bytes(),
            private: serialize_uint(CK_TRUE),
            key_type: serialize_uint(key_type_value),
            ec_params,
        })
    }
}

const OID_BYTES_SECP256R1: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_BYTES_SECP384R1: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_BYTES_SECP521R1: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23];

// Attempt to list all known `SecIdentity`s as persistent identifiers that we
// can cache for use later.
fn list_identities_as_persistent_refs() -> Option<CFArray<CFData>> {
    unsafe {
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
