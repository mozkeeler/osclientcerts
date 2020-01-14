/* -*- Mode: rust; rust-indent-offset: 4 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![allow(non_upper_case_globals)]

use libloading::{Library, Symbol};
use pkcs11::types::*;
use sha2::{Digest, Sha256};
use std::os::raw::c_void;

use core_foundation::array::*;
use core_foundation::base::*;
use core_foundation::boolean::*;
use core_foundation::data::*;
use core_foundation::dictionary::*;
use core_foundation::error::*;
use core_foundation::number::*;
use core_foundation::string::*;

// Normally we would generate this with a build script, but macos is
// cross-compiled on linux, and we'd have to figure out e.g. include paths,
// etc.. This is easier.
include!("bindings_macos.rs");

use crate::util::*;

#[repr(C)]
pub struct __SecIdentity(c_void);
pub type SecIdentityRef = *const __SecIdentity;
declare_TCFType!(SecIdentity, SecIdentityRef);
impl_TCFType!(SecIdentity, SecIdentityRef, SecIdentityGetTypeID);

// The manager runs this code on one thread only, so this should be safe.
pub struct SecIdentityHolder(SecIdentity);
unsafe impl Send for SecIdentityHolder {}
unsafe impl Sync for SecIdentityHolder {}

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

lazy_static! {
    static ref SECURITY_FRAMEWORK: SecurityFramework = SecurityFramework::new();
}

struct SecurityFramework {
    library: Option<Library>,
}

impl SecurityFramework {
    fn new() -> SecurityFramework {
        let library = Library::new("/System/Library/Frameworks/Security.framework/Security").ok();
        SecurityFramework { library }
    }

    fn sec_key_create_signature(
        &self,
        key: SecKeyRef,
        algorithm: SecKeyAlgorithm,
        data_to_sign: CFDataRef,
        error: *mut CFErrorRef,
    ) -> Result<CFDataRef, ()> {
        match &self.library {
            Some(library) => unsafe {
                let func: Symbol<
                    unsafe extern "C" fn(
                        SecKeyRef,
                        SecKeyAlgorithm,
                        CFDataRef,
                        *mut CFErrorRef,
                    ) -> CFDataRef,
                > = library.get(b"SecKeyCreateSignature\0").map_err(|_| ())?;
                Ok(func(key, algorithm, data_to_sign, error))
            },
            None => Err(()),
        }
    }

    fn sec_key_copy_attributes(&self, key: SecKeyRef) -> Result<CFDictionaryRef, ()> {
        match &self.library {
            Some(library) => unsafe {
                let func: Symbol<unsafe extern "C" fn(SecKeyRef) -> CFDictionaryRef> =
                    library.get(b"SecKeyCopyAttributes\0").map_err(|_| ())?;
                Ok(func(key))
            },
            None => Err(()),
        }
    }

    fn sec_key_copy_external_representation(
        &self,
        key: SecKeyRef,
        error: *mut CFErrorRef,
    ) -> Result<CFDataRef, ()> {
        match &self.library {
            Some(library) => unsafe {
                let func: Symbol<unsafe extern "C" fn(SecKeyRef, *mut CFErrorRef) -> CFDataRef> =
                    library
                        .get(b"SecKeyCopyExternalRepresentation\0")
                        .map_err(|_| ())?;
                Ok(func(key, error))
            },
            None => Err(()),
        }
    }

    fn sec_certificate_copy_serial_number_data(
        &self,
        certificate: SecCertificateRef,
        error: *mut CFErrorRef,
    ) -> Result<CFDataRef, ()> {
        match &self.library {
            Some(library) => unsafe {
                let func: Symbol<
                    unsafe extern "C" fn(SecCertificateRef, *mut CFErrorRef) -> CFDataRef,
                > = library
                    .get(b"SecCertificateCopySerialNumberData\0")
                    .map_err(|_| ())?;
                Ok(func(certificate, error))
            },
            None => Err(()),
        }
    }

    fn sec_certificate_copy_normalized_issuer_sequence(
        &self,
        certificate: SecCertificateRef,
    ) -> Result<CFDataRef, ()> {
        match &self.library {
            Some(library) => unsafe {
                let func: Symbol<unsafe extern "C" fn(SecCertificateRef) -> CFDataRef> = library
                    .get(b"SecCertificateCopyNormalizedIssuerSequence\0")
                    .map_err(|_| ())?;
                Ok(func(certificate))
            },
            None => Err(()),
        }
    }

    fn sec_certificate_copy_normalized_subject_sequence(
        &self,
        certificate: SecCertificateRef,
    ) -> Result<CFDataRef, ()> {
        match &self.library {
            Some(library) => unsafe {
                let func: Symbol<unsafe extern "C" fn(SecCertificateRef) -> CFDataRef> = library
                    .get(b"SecCertificateCopyNormalizedSubjectSequence\0")
                    .map_err(|_| ())?;
                Ok(func(certificate))
            },
            None => Err(()),
        }
    }

    fn sec_certificate_copy_key(&self, certificate: SecCertificateRef) -> Result<SecKeyRef, ()> {
        match &self.library {
            Some(library) => unsafe {
                let func: Symbol<unsafe extern "C" fn(SecCertificateRef) -> SecKeyRef> =
                    library.get(b"SecCertificateCopyKey\0").map_err(|_| ())?;
                Ok(func(certificate))
            },
            None => Err(()),
        }
    }

    fn get_sec_string_constant(&self, symbol_id: &[u8]) -> Result<CFStringRef, ()> {
        match &self.library {
            Some(library) => unsafe {
                let symbol: Symbol<*const CFStringRef> = library.get(symbol_id).map_err(|_| ())?;
                Ok(**symbol)
            },
            None => Err(()),
        }
    }
}

pub struct Cert {
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
    fn new(identity: &SecIdentity) -> Result<Cert, ()> {
        let mut certificate = std::ptr::null();
        let status =
            unsafe { SecIdentityCopyCertificate(identity.as_concrete_TypeRef(), &mut certificate) };
        if status != errSecSuccess {
            error!("SecIdentityCopyCertificate failed: {}", status);
            return Err(());
        }
        if certificate.is_null() {
            error!("couldn't get certificate from identity?");
            return Err(());
        }
        let certificate = unsafe { SecCertificate::wrap_under_create_rule(certificate) };
        let label = unsafe {
            CFString::wrap_under_create_rule(SecCertificateCopySubjectSummary(
                certificate.as_concrete_TypeRef(),
            ))
        };
        let der = unsafe {
            CFData::wrap_under_create_rule(SecCertificateCopyData(
                certificate.as_concrete_TypeRef(),
            ))
        };
        let id = Sha256::digest(der.bytes()).to_vec();
        let issuer = unsafe {
            let result = SECURITY_FRAMEWORK.sec_certificate_copy_normalized_issuer_sequence(
                certificate.as_concrete_TypeRef(),
            )?;
            CFData::wrap_under_create_rule(result)
        };
        let serial_number = unsafe {
            let result = SECURITY_FRAMEWORK.sec_certificate_copy_serial_number_data(
                certificate.as_concrete_TypeRef(),
                std::ptr::null_mut(),
            )?;
            CFData::wrap_under_create_rule(result)
        };
        let subject = unsafe {
            let result = SECURITY_FRAMEWORK.sec_certificate_copy_normalized_subject_sequence(
                certificate.as_concrete_TypeRef(),
            )?;
            CFData::wrap_under_create_rule(result)
        };

        Ok(Cert {
            class: serialize_uint(CKO_CERTIFICATE)?,
            token: serialize_uint(CK_TRUE)?,
            id,
            label: label.to_string().into_bytes(),
            value: der.bytes().to_vec(),
            issuer: issuer.bytes().to_vec(),
            serial_number: serial_number.bytes().to_vec(),
            subject: subject.bytes().to_vec(),
        })
    }
    fn class(&self) -> &[u8] {
        &self.class
    }

    fn token(&self) -> &[u8] {
        &self.token
    }

    pub fn id(&self) -> &[u8] {
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

const OID_BYTES_SECP256R1: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_BYTES_SECP384R1: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_BYTES_SECP521R1: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23];

#[derive(Clone, Copy, Debug)]
pub enum KeyType {
    EC,
    RSA,
}

enum SignParams {
    EC(SecKeyAlgorithm),
    RSA(SecKeyAlgorithm),
}

impl SignParams {
    fn new(
        key_type: KeyType,
        data_len: usize,
        params: &Option<CK_RSA_PKCS_PSS_PARAMS>,
    ) -> Result<SignParams, ()> {
        match key_type {
            KeyType::EC => return SignParams::new_ec_params(data_len),
            KeyType::RSA => {}
        }
        let pss_params = match params {
            Some(pss_params) => pss_params,
            None => {
                return Ok(SignParams::RSA(
                    SECURITY_FRAMEWORK.get_sec_string_constant(
                        b"kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw\0".as_ref(),
                    )?,
                ));
            }
        };
        let algorithm = {
            let algorithm_id = match pss_params.hashAlg {
                CKM_SHA_1 => b"kSecKeyAlgorithmRSASignatureDigestPSSSHA1\0".as_ref(),
                CKM_SHA256 => b"kSecKeyAlgorithmRSASignatureDigestPSSSHA256\0".as_ref(),
                CKM_SHA384 => b"kSecKeyAlgorithmRSASignatureDigestPSSSHA384\0".as_ref(),
                CKM_SHA512 => b"kSecKeyAlgorithmRSASignatureDigestPSSSHA512\0".as_ref(),
                _ => {
                    error!(
                        "unsupported algorithm to use with RSA-PSS: {}",
                        unsafe_packed_field_access!(pss_params.hashAlg)
                    );
                    return Err(());
                }
            };
            SECURITY_FRAMEWORK.get_sec_string_constant(algorithm_id)?
        };
        Ok(SignParams::RSA(algorithm))
    }

    fn new_ec_params(data_len: usize) -> Result<SignParams, ()> {
        let algorithm_id = match data_len {
            20 => b"kSecKeyAlgorithmECDSASignatureDigestX962SHA1\0".as_ref(),
            32 => b"kSecKeyAlgorithmECDSASignatureDigestX962SHA256\0".as_ref(),
            48 => b"kSecKeyAlgorithmECDSASignatureDigestX962SHA384\0".as_ref(),
            64 => b"kSecKeyAlgorithmECDSASignatureDigestX962SHA512\0".as_ref(),
            _ => {
                error!(
                    "Unexpected digested signature input length for ECDSA: {}",
                    data_len
                );
                return Err(());
            }
        };
        let algorithm = SECURITY_FRAMEWORK.get_sec_string_constant(algorithm_id)?;
        Ok(SignParams::EC(algorithm))
    }

    fn get_algorithm(&self) -> &SecKeyAlgorithm {
        match self {
            SignParams::EC(algorithm) => &algorithm,
            SignParams::RSA(algorithm) => &algorithm,
        }
    }
}

pub struct Key {
    identity: SecIdentityHolder,
    class: Vec<u8>,
    token: Vec<u8>,
    id: Vec<u8>,
    private: Vec<u8>,
    key_type: Vec<u8>,
    modulus: Option<Vec<u8>>,
    ec_params: Option<Vec<u8>>,
    key_type_enum: KeyType,
}

impl Key {
    fn new(identity: &SecIdentity) -> Result<Key, ()> {
        let mut certificate = std::ptr::null();
        let status =
            unsafe { SecIdentityCopyCertificate(identity.as_concrete_TypeRef(), &mut certificate) };
        if status != errSecSuccess {
            error!("SecIdentityCopyCertificate failed: {}", status);
            return Err(());
        }
        if certificate.is_null() {
            error!("couldn't get certificate from identity?");
            return Err(());
        }
        let certificate = unsafe { SecCertificate::wrap_under_create_rule(certificate) };
        let der = unsafe {
            CFData::wrap_under_create_rule(SecCertificateCopyData(
                certificate.as_concrete_TypeRef(),
            ))
        };
        let id = Sha256::digest(der.bytes()).to_vec();

        let key = SECURITY_FRAMEWORK.sec_certificate_copy_key(certificate.as_concrete_TypeRef())?;
        if key.is_null() {
            error!("couldn't get key from certificate?");
            return Err(());
        }
        let key = unsafe { SecKey::wrap_under_create_rule(key) };
        let key_type: CFString = get_key_attribute(&key, unsafe { kSecAttrKeyType })?;
        let key_size_in_bits: CFNumber = get_key_attribute(&key, unsafe { kSecAttrKeySizeInBits })?;
        let mut modulus = None;
        let mut ec_params = None;
        let sec_attr_key_type_ec = SECURITY_FRAMEWORK
            .get_sec_string_constant(b"kSecAttrKeyTypeECSECPrimeRandom\0".as_ref())?;
        let (key_type_enum, key_type_attribute) =
            if key_type.as_concrete_TypeRef() == unsafe { kSecAttrKeyTypeRSA } {
                // TODO: presumably this is fallible and we should check it before wrapping
                let public_key = unsafe {
                    let result = SECURITY_FRAMEWORK.sec_key_copy_external_representation(
                        key.as_concrete_TypeRef(),
                        std::ptr::null_mut(),
                    )?;
                    CFData::wrap_under_create_rule(result)
                };
                let modulus_value = read_rsa_modulus(public_key.bytes())?;
                modulus = Some(modulus_value);
                (KeyType::RSA, CKK_RSA)
            } else if key_type.as_concrete_TypeRef() == sec_attr_key_type_ec {
                // Assume all EC keys are secp256r1, secp384r1, or secp521r1. This
                // is wrong, but the API doesn't seem to give us a way to determine
                // which curve this key is on.
                // This might not matter in practice, because it seems all NSS uses
                // this for is to get the signature size.
                match key_size_in_bits.to_i64() {
                    Some(256) => ec_params = Some(OID_BYTES_SECP256R1.to_vec()),
                    Some(384) => ec_params = Some(OID_BYTES_SECP384R1.to_vec()),
                    Some(521) => ec_params = Some(OID_BYTES_SECP521R1.to_vec()),
                    _ => {
                        error!("unsupported EC key");
                        return Err(());
                    }
                }
                (KeyType::EC, CKK_EC)
            } else {
                error!("unsupported key type");
                return Err(());
            };

        Ok(Key {
            identity: SecIdentityHolder(identity.clone()),
            class: serialize_uint(CKO_PRIVATE_KEY)?,
            token: serialize_uint(CK_TRUE)?,
            id,
            private: serialize_uint(CK_TRUE)?,
            key_type: serialize_uint(key_type_attribute)?,
            modulus,
            ec_params,
            key_type_enum,
        })
    }

    fn class(&self) -> &[u8] {
        &self.class
    }

    fn token(&self) -> &[u8] {
        &self.token
    }

    pub fn id(&self) -> &[u8] {
        &self.id
    }

    fn private(&self) -> &[u8] {
        &self.private
    }

    fn key_type(&self) -> &[u8] {
        &self.key_type
    }

    fn modulus(&self) -> Option<&[u8]> {
        match &self.modulus {
            Some(modulus) => Some(modulus.as_slice()),
            None => None,
        }
    }

    fn ec_params(&self) -> Option<&[u8]> {
        match &self.ec_params {
            Some(ec_params) => Some(ec_params.as_slice()),
            None => None,
        }
    }

    fn matches(&self, attrs: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> bool {
        for (attr_type, attr_value) in attrs {
            let comparison = match *attr_type {
                CKA_CLASS => self.class(),
                CKA_TOKEN => self.token(),
                CKA_ID => self.id(),
                CKA_PRIVATE => self.private(),
                CKA_KEY_TYPE => self.key_type(),
                CKA_MODULUS => {
                    if let Some(modulus) = self.modulus() {
                        modulus
                    } else {
                        return false;
                    }
                }
                CKA_EC_PARAMS => {
                    if let Some(ec_params) = self.ec_params() {
                        ec_params
                    } else {
                        return false;
                    }
                }
                _ => return false,
            };
            if attr_value.as_slice() != comparison {
                return false;
            }
        }
        true
    }

    fn get_attribute(&self, attribute: CK_ATTRIBUTE_TYPE) -> Option<&[u8]> {
        match attribute {
            CKA_CLASS => Some(self.class()),
            CKA_TOKEN => Some(self.token()),
            CKA_ID => Some(self.id()),
            CKA_PRIVATE => Some(self.private()),
            CKA_KEY_TYPE => Some(self.key_type()),
            CKA_MODULUS => self.modulus(),
            CKA_EC_PARAMS => self.ec_params(),
            _ => None,
        }
    }

    pub fn get_signature_length(
        &self,
        data: &[u8],
        params: &Option<CK_RSA_PKCS_PSS_PARAMS>,
    ) -> Result<usize, ()> {
        // Unfortunately we don't have a way of getting the length of a signature without creating
        // one.
        let signature = self.sign(data, params)?;
        Ok(signature.len())
    }

    // The input data is a hash. What algorithm we use depends on the size of the hash.
    pub fn sign(
        &self,
        data: &[u8],
        params: &Option<CK_RSA_PKCS_PSS_PARAMS>,
    ) -> Result<Vec<u8>, ()> {
        let key = unsafe {
            let mut key = std::ptr::null();
            let status = SecIdentityCopyPrivateKey(self.identity.0.as_concrete_TypeRef(), &mut key);
            if status != errSecSuccess {
                error!("SecIdentityCopyPrivateKey failed: {}", status);
                return Err(());
            }
            if key.is_null() {
                error!("SecIdentityCopyPrivateKey didn't set key?");
                return Err(());
            }
            SecKey::wrap_under_create_rule(key)
        };
        let sign_params = SignParams::new(self.key_type_enum, data.len(), params)?;
        let signing_algorithm = sign_params.get_algorithm();
        let data = CFData::from_buffer(data);
        let signature = unsafe {
            let mut error = std::ptr::null_mut();
            let result = SECURITY_FRAMEWORK.sec_key_create_signature(
                key.as_concrete_TypeRef(),
                *signing_algorithm,
                data.as_concrete_TypeRef(),
                &mut error,
            )?;
            if result.is_null() {
                error!("SecKeyCreateSignature failed");
                let error = CFError::wrap_under_create_rule(error);
                error.show(); // TODO: log contents using logging system, not stderr
                return Err(());
            }
            CFData::wrap_under_create_rule(result)
        };
        let signature_value = match self.key_type_enum {
            KeyType::EC => {
                // We need to convert the DER Ecdsa-Sig-Value to the
                // concatenation of r and s, the coordinates of the point on
                // the curve.
                let (r, s) = read_ec_sig_point(signature.bytes())?;
                // TODO: is there a padding issue here? This should be failing
                // ~half the time (unless SecKeyCreateSignature isn't actually
                // using the shortest possible encoding for the DER
                // INTEGERs...)
                let mut signature_value = Vec::with_capacity(r.len() + s.len());
                signature_value.extend_from_slice(r);
                signature_value.extend_from_slice(s);
                signature_value
            }
            KeyType::RSA => signature.bytes().to_vec(),
        };
        Ok(signature_value)
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
    if let Some(identities) = list_identities() {
        for (cert, key) in identities {
            objects.push(Object::Cert(cert));
            objects.push(Object::Key(key));
        }
    }
    objects
}

fn get_key_attribute<T: TCFType + Clone>(key: &SecKey, attr: CFStringRef) -> Result<T, ()> {
    // TODO: is SecKeyCopyAttributes fallible? will wrap_under_create_rule panic?
    let attributes: CFDictionary<CFString, T> = unsafe {
        let attributes = SECURITY_FRAMEWORK.sec_key_copy_attributes(key.as_concrete_TypeRef())?;
        CFDictionary::wrap_under_create_rule(attributes)
    };
    match attributes.find(attr as *const _) {
        Some(value) => Ok((*value).clone()),
        None => Err(()),
    }
}

fn list_identities() -> Option<Vec<(Cert, Key)>> {
    let identities = unsafe {
        let class_key = CFString::wrap_under_get_rule(kSecClass);
        let class_value = CFString::wrap_under_get_rule(kSecClassIdentity);
        let return_ref_key = CFString::wrap_under_get_rule(kSecReturnRef);
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
            error!("SecItemCopyMatching failed: {}", status);
            return None;
        }
        if result.is_null() {
            debug!("no client certs?");
            return None;
        }
        CFArray::<SecIdentityRef>::wrap_under_create_rule(result as CFArrayRef)
    };
    debug!("found {} identities", identities.len());
    let mut identities_out = Vec::with_capacity(identities.len() as usize);
    for identity in identities.get_all_values().iter() {
        let identity = unsafe { SecIdentity::wrap_under_get_rule(*identity as SecIdentityRef) };
        let cert = Cert::new(&identity);
        let key = Key::new(&identity);
        if let (Ok(cert), Ok(key)) = (cert, key) {
            identities_out.push((cert, key));
        }
    }
    Some(identities_out)
}
