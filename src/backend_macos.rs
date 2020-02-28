/* -*- Mode: rust; rust-indent-offset: 4 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![allow(non_upper_case_globals)]

use libloading::{Library, Symbol};
use pkcs11::types::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
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

type SecKeyCreateSignatureType =
    unsafe extern "C" fn(SecKeyRef, SecKeyAlgorithm, CFDataRef, *mut CFErrorRef) -> CFDataRef;
type SecKeyCopyAttributesType = unsafe extern "C" fn(SecKeyRef) -> CFDictionaryRef;
type SecKeyCopyExternalRepresentationType =
    unsafe extern "C" fn(SecKeyRef, *mut CFErrorRef) -> CFDataRef;
type SecCertificateCopySerialNumberDataType =
    unsafe extern "C" fn(SecCertificateRef, *mut CFErrorRef) -> CFDataRef;
type SecCertificateCopyNormalizedIssuerSequenceType =
    unsafe extern "C" fn(SecCertificateRef) -> CFDataRef;
type SecCertificateCopyNormalizedSubjectSequenceType =
    unsafe extern "C" fn(SecCertificateRef) -> CFDataRef;
type SecCertificateCopyKeyType = unsafe extern "C" fn(SecCertificateRef) -> SecKeyRef;

#[derive(Ord, Eq, PartialOrd, PartialEq, Debug)]
enum SecStringConstant {
    // These are available in macOS 10.12
    SecKeyAlgorithmECDSASignatureDigestX962SHA1,
    SecKeyAlgorithmECDSASignatureDigestX962SHA256,
    SecKeyAlgorithmECDSASignatureDigestX962SHA384,
    SecKeyAlgorithmECDSASignatureDigestX962SHA512,
    SecKeyAlgorithmRSASignatureDigestPKCS1v15Raw,
    SecAttrKeyTypeECSECPrimeRandom,
    // These are available in macOS 10.13
    SecKeyAlgorithmRSASignatureDigestPSSSHA1,
    SecKeyAlgorithmRSASignatureDigestPSSSHA256,
    SecKeyAlgorithmRSASignatureDigestPSSSHA384,
    SecKeyAlgorithmRSASignatureDigestPSSSHA512,
}

// NB: This is not meant to be used outside of this module. It has to be made public because
// `RentedSecurityFramework` must be public in the rental declaration.
pub struct SecurityFrameworkFunctions<'a> {
    sec_key_create_signature: Symbol<'a, SecKeyCreateSignatureType>,
    sec_key_copy_attributes: Symbol<'a, SecKeyCopyAttributesType>,
    sec_key_copy_external_representation: Symbol<'a, SecKeyCopyExternalRepresentationType>,
    sec_certificate_copy_serial_number_data: Symbol<'a, SecCertificateCopySerialNumberDataType>,
    sec_certificate_copy_normalized_issuer_sequence:
        Symbol<'a, SecCertificateCopyNormalizedIssuerSequenceType>,
    sec_certificate_copy_normalized_subject_sequence:
        Symbol<'a, SecCertificateCopyNormalizedSubjectSequenceType>,
    sec_certificate_copy_key: Symbol<'a, SecCertificateCopyKeyType>,
    sec_string_constants: BTreeMap<SecStringConstant, String>,
}

rental! {
    mod rent_libloading {
        use super::*;

        #[rental]
        pub struct RentedSecurityFramework {
            library: Box<Library>, // Library needs to be StableDeref, hence the Box
            functions: SecurityFrameworkFunctions<'library>,
        }
    }
}

/// This implementation uses security framework functions and constants that
/// are not provided by the version of the SDK we build with. To work around
/// this, we attempt to open and dynamically load these functions and symbols
/// at runtime. Unfortunately this does mean that if a user is not on a new
/// enough version of macOS, they will not be able to use client certificates
/// from their keychain in Firefox until they upgrade.
struct SecurityFramework {
    rental: Option<rent_libloading::RentedSecurityFramework>,
}

impl SecurityFramework {
    fn new() -> SecurityFramework {
        let library = match Library::new("/System/Library/Frameworks/Security.framework/Security") {
            Ok(library) => library,
            Err(_) => return SecurityFramework { rental: None },
        };
        match rent_libloading::RentedSecurityFramework::try_new::<_, TracingError>(
            Box::new(library),
            |library| unsafe {
                let sec_key_create_signature = library
                    .get::<SecKeyCreateSignatureType>(b"SecKeyCreateSignature\0")
                    .map_err(|e| {
                        trace_error!(format!("couldn't load SecKeyCreateSignature: {}", e))
                    })?;
                let sec_key_copy_attributes = library
                    .get::<SecKeyCopyAttributesType>(b"SecKeyCopyAttributes\0")
                    .map_err(|e| {
                        trace_error!(format!("couldn't load SecKeyCopyAttributes: {}", e))
                    })?;
                let sec_key_copy_external_representation = library
                    .get::<SecKeyCopyExternalRepresentationType>(
                        b"SecKeyCopyExternalRepresentation\0",
                    )
                    .map_err(|e| {
                        trace_error!(format!(
                            "couldn't load SecKeyCopyExternalRepresentation: {}",
                            e
                        ))
                    })?;
                let sec_certificate_copy_serial_number_data = library
                    .get::<SecCertificateCopySerialNumberDataType>(
                        b"SecCertificateCopySerialNumberData\0",
                    )
                    .map_err(|e| {
                        trace_error!(format!(
                            "couldn't load SecCertificateCopySerialNumberData: {}",
                            e
                        ))
                    })?;
                let sec_certificate_copy_normalized_issuer_sequence = library
                    .get::<SecCertificateCopyNormalizedIssuerSequenceType>(
                        b"SecCertificateCopyNormalizedIssuerSequence\0",
                    )
                    .map_err(|e| {
                        trace_error!(format!(
                            "couldn't load SecCertificateCopyNormalizedIssuerSequence: {}",
                            e
                        ))
                    })?;
                let sec_certificate_copy_normalized_subject_sequence = library
                    .get::<SecCertificateCopyNormalizedSubjectSequenceType>(
                        b"SecCertificateCopyNormalizedSubjectSequence\0",
                    )
                    .map_err(|e| {
                        trace_error!(format!(
                            "couldn't load SecCertificateCopyNormalizedSubjectSequence: {}",
                            e
                        ))
                    })?;
                let sec_certificate_copy_key = library
                    .get::<SecCertificateCopyKeyType>(b"SecCertificateCopyKey\0")
                    .map_err(|e| {
                        trace_error!(format!("couldn't load SecCertificateCopyKey: {}", e))
                    })?;
                let mut sec_string_constants = BTreeMap::new();
                let strings_to_load = vec![
                    (
                        b"kSecKeyAlgorithmECDSASignatureDigestX962SHA1\0".as_ref(),
                        SecStringConstant::SecKeyAlgorithmECDSASignatureDigestX962SHA1,
                    ),
                    (
                        b"kSecKeyAlgorithmECDSASignatureDigestX962SHA256\0".as_ref(),
                        SecStringConstant::SecKeyAlgorithmECDSASignatureDigestX962SHA256,
                    ),
                    (
                        b"kSecKeyAlgorithmECDSASignatureDigestX962SHA384\0".as_ref(),
                        SecStringConstant::SecKeyAlgorithmECDSASignatureDigestX962SHA384,
                    ),
                    (
                        b"kSecKeyAlgorithmECDSASignatureDigestX962SHA512\0".as_ref(),
                        SecStringConstant::SecKeyAlgorithmECDSASignatureDigestX962SHA512,
                    ),
                    (
                        b"kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw\0".as_ref(),
                        SecStringConstant::SecKeyAlgorithmRSASignatureDigestPKCS1v15Raw,
                    ),
                    (
                        b"kSecKeyAlgorithmRSASignatureDigestPSSSHA1\0".as_ref(),
                        SecStringConstant::SecKeyAlgorithmRSASignatureDigestPSSSHA1,
                    ),
                    (
                        b"kSecKeyAlgorithmRSASignatureDigestPSSSHA256\0".as_ref(),
                        SecStringConstant::SecKeyAlgorithmRSASignatureDigestPSSSHA256,
                    ),
                    (
                        b"kSecKeyAlgorithmRSASignatureDigestPSSSHA384\0".as_ref(),
                        SecStringConstant::SecKeyAlgorithmRSASignatureDigestPSSSHA384,
                    ),
                    (
                        b"kSecKeyAlgorithmRSASignatureDigestPSSSHA512\0".as_ref(),
                        SecStringConstant::SecKeyAlgorithmRSASignatureDigestPSSSHA512,
                    ),
                    (
                        b"kSecAttrKeyTypeECSECPrimeRandom\0".as_ref(),
                        SecStringConstant::SecAttrKeyTypeECSECPrimeRandom,
                    ),
                ];
                for (symbol_name, sec_string_constant) in strings_to_load {
                    let cfstring_symbol =
                        library
                            .get::<*const CFStringRef>(symbol_name)
                            .map_err(|e| {
                                trace_error!(format!(
                                    "couldn't load {:?}: {}",
                                    sec_string_constant, e
                                ))
                            })?;
                    let cfstring = CFString::wrap_under_create_rule(**cfstring_symbol);
                    sec_string_constants.insert(sec_string_constant, cfstring.to_string());
                }
                Ok(SecurityFrameworkFunctions {
                    sec_key_create_signature,
                    sec_key_copy_attributes,
                    sec_key_copy_external_representation,
                    sec_certificate_copy_serial_number_data,
                    sec_certificate_copy_normalized_issuer_sequence,
                    sec_certificate_copy_normalized_subject_sequence,
                    sec_certificate_copy_key,
                    sec_string_constants,
                })
            },
        ) {
            Ok(rental) => SecurityFramework {
                rental: Some(rental),
            },
            Err(e) => {
                error!("loading security framework failed: {}", e.0);
                SecurityFramework { rental: None }
            }
        }
    }

    /// SecKeyCreateSignature is available in macOS 10.12
    fn sec_key_create_signature(
        &self,
        key: &SecKey,
        algorithm: SecKeyAlgorithm,
        data_to_sign: &CFData,
    ) -> Result<CFData, TracingError> {
        match &self.rental {
            Some(rental) => rental.rent(|framework| unsafe {
                let mut error = std::ptr::null_mut();
                let result = (framework.sec_key_create_signature)(
                    key.as_concrete_TypeRef(),
                    algorithm,
                    data_to_sign.as_concrete_TypeRef(),
                    &mut error,
                );
                if result.is_null() {
                    let error = CFError::wrap_under_create_rule(error);
                    return Err(trace_error!(format!(
                        "SecKeyCreateSignature failed: {}",
                        error
                    )));
                }
                Ok(CFData::wrap_under_create_rule(result))
            }),
            None => Err(trace_error!("security framework not loaded?".to_string())),
        }
    }

    /// SecKeyCopyAttributes is available in macOS 10.12
    fn sec_key_copy_attributes<T>(
        &self,
        key: &SecKey,
    ) -> Result<CFDictionary<CFString, T>, TracingError> {
        match &self.rental {
            Some(rental) => rental.rent(|framework| unsafe {
                let result = (framework.sec_key_copy_attributes)(key.as_concrete_TypeRef());
                if result.is_null() {
                    return Err(trace_error!("SecKeyCopyAttributes failed".to_string()));
                }
                Ok(CFDictionary::wrap_under_create_rule(result))
            }),
            None => Err(trace_error!("security framework not loaded?".to_string())),
        }
    }

    /// SecKeyCopyExternalRepresentation is available in macOS 10.12
    fn sec_key_copy_external_representation(&self, key: &SecKey) -> Result<CFData, TracingError> {
        match &self.rental {
            Some(rental) => rental.rent(|framework| unsafe {
                let mut error = std::ptr::null_mut();
                let result = (framework.sec_key_copy_external_representation)(
                    key.as_concrete_TypeRef(),
                    &mut error,
                );
                if result.is_null() {
                    let error = CFError::wrap_under_create_rule(error);
                    return Err(trace_error!(format!(
                        "SecKeyCopyExternalRepresentation failed: {}",
                        error
                    )));
                }
                Ok(CFData::wrap_under_create_rule(result))
            }),
            None => Err(trace_error!("security framework not loaded?".to_string())),
        }
    }

    /// SecCertificateCopySerialNumberData is available in macOS 10.13
    fn sec_certificate_copy_serial_number_data(
        &self,
        certificate: &SecCertificate,
    ) -> Result<CFData, TracingError> {
        match &self.rental {
            Some(rental) => rental.rent(|framework| unsafe {
                let mut error = std::ptr::null_mut();
                let result = (framework.sec_certificate_copy_serial_number_data)(
                    certificate.as_concrete_TypeRef(),
                    &mut error,
                );
                if result.is_null() {
                    let error = CFError::wrap_under_create_rule(error);
                    return Err(trace_error!(format!(
                        "SecCertificateCopySerialNumberData failed: {}",
                        error
                    )));
                }
                Ok(CFData::wrap_under_create_rule(result))
            }),
            None => Err(trace_error!("security framework not loaded?".to_string())),
        }
    }

    /// SecCertificateCopyNormalizedIssuerSequence is available in macOS 10.12.4
    fn sec_certificate_copy_normalized_issuer_sequence(
        &self,
        certificate: &SecCertificate,
    ) -> Result<CFData, TracingError> {
        match &self.rental {
            Some(rental) => rental.rent(|framework| unsafe {
                let result = (framework.sec_certificate_copy_normalized_issuer_sequence)(
                    certificate.as_concrete_TypeRef(),
                );
                if result.is_null() {
                    return Err(trace_error!(
                        "SecCertificateCopyNormalizedIssuerSequence failed".to_string()
                    ));
                }
                Ok(CFData::wrap_under_create_rule(result))
            }),
            None => Err(trace_error!("security framework not loaded?".to_string())),
        }
    }

    /// SecCertificateCopyNormalizedSubjectSequence is available in macOS 10.12.4
    fn sec_certificate_copy_normalized_subject_sequence(
        &self,
        certificate: &SecCertificate,
    ) -> Result<CFData, TracingError> {
        match &self.rental {
            Some(rental) => rental.rent(|framework| unsafe {
                let result = (framework.sec_certificate_copy_normalized_subject_sequence)(
                    certificate.as_concrete_TypeRef(),
                );
                if result.is_null() {
                    return Err(trace_error!(
                        "SecCertificateCopyNormalizedSubjectSequence failed".to_string()
                    ));
                }
                Ok(CFData::wrap_under_create_rule(result))
            }),
            None => Err(trace_error!("security framework not loaded?".to_string())),
        }
    }

    /// SecCertificateCopyKey is available in macOS 10.14
    fn sec_certificate_copy_key(
        &self,
        certificate: &SecCertificate,
    ) -> Result<SecKey, TracingError> {
        match &self.rental {
            Some(rental) => rental.rent(|framework| unsafe {
                let result =
                    (framework.sec_certificate_copy_key)(certificate.as_concrete_TypeRef());
                if result.is_null() {
                    return Err(trace_error!("SecCertificateCopyKey failed".to_string()));
                }
                Ok(SecKey::wrap_under_create_rule(result))
            }),
            None => Err(trace_error!("security framework not loaded?".to_string())),
        }
    }

    fn get_sec_string_constant(
        &self,
        sec_string_constant: SecStringConstant,
    ) -> Result<CFString, TracingError> {
        match &self.rental {
            Some(rental) => rental.rent(|framework| {
                match framework.sec_string_constants.get(&sec_string_constant) {
                    Some(string) => Ok(CFString::new(string)),
                    None => Err(trace_error!(format!(
                        "string constant '{:?}' not present?",
                        sec_string_constant
                    ))),
                }
            }),
            None => Err(trace_error!("security framework not loaded?".to_string())),
        }
    }
}

lazy_static! {
    static ref SECURITY_FRAMEWORK: SecurityFramework = SecurityFramework::new();
}

fn sec_identity_copy_certificate(identity: &SecIdentity) -> Result<SecCertificate, TracingError> {
    let mut certificate = std::ptr::null();
    let status =
        unsafe { SecIdentityCopyCertificate(identity.as_concrete_TypeRef(), &mut certificate) };
    if status != errSecSuccess {
        return Err(trace_error!(format!(
            "SecIdentityCopyCertificate failed: {}",
            status
        )));
    }
    if certificate.is_null() {
        return Err(trace_error!(
            "couldn't get certificate from identity?".to_string()
        ));
    }
    Ok(unsafe { SecCertificate::wrap_under_create_rule(certificate) })
}

fn sec_certificate_copy_subject_summary(
    certificate: &SecCertificate,
) -> Result<CFString, TracingError> {
    let result = unsafe { SecCertificateCopySubjectSummary(certificate.as_concrete_TypeRef()) };
    if result.is_null() {
        return Err(trace_error!(
            "SecCertificateCopySubjectSummary failed".to_string()
        ));
    }
    Ok(unsafe { CFString::wrap_under_create_rule(result) })
}

fn sec_certificate_copy_data(certificate: &SecCertificate) -> Result<CFData, TracingError> {
    let result = unsafe { SecCertificateCopyData(certificate.as_concrete_TypeRef()) };
    if result.is_null() {
        return Err(trace_error!("SecCertificateCopyData failed".to_string()));
    }
    Ok(unsafe { CFData::wrap_under_create_rule(result) })
}

fn sec_identity_copy_private_key(identity: &SecIdentity) -> Result<SecKey, TracingError> {
    let mut key = std::ptr::null();
    let status = unsafe { SecIdentityCopyPrivateKey(identity.as_concrete_TypeRef(), &mut key) };
    if status != errSecSuccess {
        return Err(trace_error!(format!(
            "SecIdentityCopyPrivateKey failed: {}",
            status
        )));
    }
    if key.is_null() {
        return Err(trace_error!(format!(
            "SecIdentityCopyPrivateKey didn't set key?"
        )));
    }
    Ok(unsafe { SecKey::wrap_under_create_rule(key) })
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
    fn new(identity: &SecIdentity) -> Result<Cert, TracingError> {
        let certificate =
            sec_identity_copy_certificate(identity).map_err(|e| trace_error_stack!(e))?;
        let label = sec_certificate_copy_subject_summary(&certificate)
            .map_err(|e| trace_error_stack!(e))?;
        let der = sec_certificate_copy_data(&certificate).map_err(|e| trace_error_stack!(e))?;
        let id = Sha256::digest(der.bytes()).to_vec();
        let issuer = SECURITY_FRAMEWORK
            .sec_certificate_copy_normalized_issuer_sequence(&certificate)
            .map_err(|e| trace_error_stack!(e))?;
        let serial_number = SECURITY_FRAMEWORK
            .sec_certificate_copy_serial_number_data(&certificate)
            .map_err(|e| trace_error_stack!(e))?;
        let subject = SECURITY_FRAMEWORK
            .sec_certificate_copy_normalized_subject_sequence(&certificate)
            .map_err(|e| trace_error_stack!(e))?;
        Ok(Cert {
            class: serialize_uint(CKO_CERTIFICATE).map_err(|e| trace_error_stack!(e))?,
            token: serialize_uint(CK_TRUE).map_err(|e| trace_error_stack!(e))?,
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

#[derive(Clone, Copy, Debug)]
pub enum KeyType {
    EC(usize),
    RSA,
}

enum SignParams {
    EC(CFString),
    RSA(CFString),
}

impl SignParams {
    fn new(
        key_type: KeyType,
        data_len: usize,
        params: &Option<CK_RSA_PKCS_PSS_PARAMS>,
    ) -> Result<SignParams, TracingError> {
        match key_type {
            KeyType::EC(_) => SignParams::new_ec_params(data_len),
            KeyType::RSA => SignParams::new_rsa_params(params),
        }
    }

    fn new_ec_params(data_len: usize) -> Result<SignParams, TracingError> {
        let algorithm_id = match data_len {
            20 => SecStringConstant::SecKeyAlgorithmECDSASignatureDigestX962SHA1,
            32 => SecStringConstant::SecKeyAlgorithmECDSASignatureDigestX962SHA256,
            48 => SecStringConstant::SecKeyAlgorithmECDSASignatureDigestX962SHA384,
            64 => SecStringConstant::SecKeyAlgorithmECDSASignatureDigestX962SHA512,
            _ => {
                return Err(trace_error!(format!(
                    "Unexpected digested signature input length for ECDSA: {}",
                    data_len
                )));
            }
        };
        let algorithm = SECURITY_FRAMEWORK
            .get_sec_string_constant(algorithm_id)
            .map_err(|e| trace_error_stack!(e))?;
        Ok(SignParams::EC(algorithm))
    }

    fn new_rsa_params(params: &Option<CK_RSA_PKCS_PSS_PARAMS>) -> Result<SignParams, TracingError> {
        let pss_params = match params {
            Some(pss_params) => pss_params,
            None => {
                return Ok(SignParams::RSA(
                    SECURITY_FRAMEWORK
                        .get_sec_string_constant(
                            SecStringConstant::SecKeyAlgorithmRSASignatureDigestPKCS1v15Raw,
                        )
                        .map_err(|e| trace_error_stack!(e))?,
                ));
            }
        };
        let algorithm = {
            let algorithm_id = match pss_params.hashAlg {
                CKM_SHA_1 => SecStringConstant::SecKeyAlgorithmRSASignatureDigestPSSSHA1,
                CKM_SHA256 => SecStringConstant::SecKeyAlgorithmRSASignatureDigestPSSSHA256,
                CKM_SHA384 => SecStringConstant::SecKeyAlgorithmRSASignatureDigestPSSSHA384,
                CKM_SHA512 => SecStringConstant::SecKeyAlgorithmRSASignatureDigestPSSSHA512,
                _ => {
                    return Err(trace_error!(format!(
                        "unsupported algorithm to use with RSA-PSS: {}",
                        unsafe_packed_field_access!(pss_params.hashAlg)
                    )));
                }
            };
            SECURITY_FRAMEWORK
                .get_sec_string_constant(algorithm_id)
                .map_err(|e| trace_error_stack!(e))?
        };
        Ok(SignParams::RSA(algorithm))
    }

    fn get_algorithm(&self) -> SecKeyAlgorithm {
        match self {
            SignParams::EC(algorithm) => algorithm.as_concrete_TypeRef(),
            SignParams::RSA(algorithm) => algorithm.as_concrete_TypeRef(),
        }
    }
}

pub struct Key {
    identity: SecIdentity,
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
    fn new(identity: &SecIdentity) -> Result<Key, TracingError> {
        let certificate =
            sec_identity_copy_certificate(identity).map_err(|e| trace_error_stack!(e))?;
        let der = sec_certificate_copy_data(&certificate).map_err(|e| trace_error_stack!(e))?;
        let id = Sha256::digest(der.bytes()).to_vec();
        let key = SECURITY_FRAMEWORK
            .sec_certificate_copy_key(&certificate)
            .map_err(|e| trace_error_stack!(e))?;
        let key_type: CFString = get_key_attribute(&key, unsafe { kSecAttrKeyType })
            .map_err(|e| trace_error_stack!(e))?;
        let key_size_in_bits: CFNumber = get_key_attribute(&key, unsafe { kSecAttrKeySizeInBits })
            .map_err(|e| trace_error_stack!(e))?;
        let mut modulus = None;
        let mut ec_params = None;
        let sec_attr_key_type_ec = SECURITY_FRAMEWORK
            .get_sec_string_constant(SecStringConstant::SecAttrKeyTypeECSECPrimeRandom)
            .map_err(|e| trace_error_stack!(e))?;
        let (key_type_enum, key_type_attribute) =
            if key_type.as_concrete_TypeRef() == unsafe { kSecAttrKeyTypeRSA } {
                let public_key = SECURITY_FRAMEWORK
                    .sec_key_copy_external_representation(&key)
                    .map_err(|e| trace_error_stack!(e))?;
                let modulus_value = read_rsa_modulus(public_key.bytes())
                    .map_err(|_| trace_error!("couldn't decode modulus".to_string()))?;
                modulus = Some(modulus_value);
                (KeyType::RSA, CKK_RSA)
            } else if key_type == sec_attr_key_type_ec {
                // Assume all EC keys are secp256r1, secp384r1, or secp521r1. This
                // is wrong, but the API doesn't seem to give us a way to determine
                // which curve this key is on.
                // This might not matter in practice, because it seems all NSS uses
                // this for is to get the signature size.
                let key_size_in_bits = match key_size_in_bits.to_i64() {
                    Some(value) => value,
                    None => return Err(trace_error!("key_size_in_bits not i64?".to_string())),
                };
                match key_size_in_bits {
                    256 => ec_params = Some(OID_BYTES_SECP256R1.to_vec()),
                    384 => ec_params = Some(OID_BYTES_SECP384R1.to_vec()),
                    521 => ec_params = Some(OID_BYTES_SECP521R1.to_vec()),
                    _ => {
                        return Err(trace_error!("unsupported EC key".to_string()));
                    }
                }
                let coordinate_width = (key_size_in_bits as usize + 7) / 8;
                (KeyType::EC(coordinate_width), CKK_EC)
            } else {
                return Err(trace_error!("unsupported key type".to_string()));
            };

        Ok(Key {
            identity: identity.clone(),
            class: serialize_uint(CKO_PRIVATE_KEY).map_err(|e| trace_error_stack!(e))?,
            token: serialize_uint(CK_TRUE).map_err(|e| trace_error_stack!(e))?,
            id,
            private: serialize_uint(CK_TRUE).map_err(|e| trace_error_stack!(e))?,
            key_type: serialize_uint(key_type_attribute).map_err(|e| trace_error_stack!(e))?,
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
    ) -> Result<usize, TracingError> {
        // Unfortunately we don't have a way of getting the length of a signature without creating
        // one.
        let dummy_signature_bytes = self.sign(data, params).map_err(|e| trace_error_stack!(e))?;
        Ok(dummy_signature_bytes.len())
    }

    // The input data is a hash. What algorithm we use depends on the size of the hash.
    pub fn sign(
        &self,
        data: &[u8],
        params: &Option<CK_RSA_PKCS_PSS_PARAMS>,
    ) -> Result<Vec<u8>, TracingError> {
        let key =
            sec_identity_copy_private_key(&self.identity).map_err(|e| trace_error_stack!(e))?;
        let sign_params = SignParams::new(self.key_type_enum, data.len(), params)
            .map_err(|e| trace_error_stack!(e))?;
        let signing_algorithm = sign_params.get_algorithm();
        let data = CFData::from_buffer(data);
        let signature = SECURITY_FRAMEWORK
            .sec_key_create_signature(&key, signing_algorithm, &data)
            .map_err(|e| trace_error_stack!(e))?;
        let signature_value = match self.key_type_enum {
            KeyType::EC(coordinate_width) => {
                // We need to convert the DER Ecdsa-Sig-Value to the
                // concatenation of r and s, the coordinates of the point on
                // the curve. r and s must be 0-padded to be coordinate_width
                // total bytes.
                let (r, s) = match read_ec_sig_point(signature.bytes()) {
                    Ok((r, s)) => (r, s),
                    Err(()) => {
                        return Err(trace_error!(format!(
                            "failed to decode EC point '{:?}'",
                            signature.bytes()
                        )))
                    }
                };
                if r.len() > coordinate_width || s.len() > coordinate_width {
                    return Err(trace_error!(format!(
                        "bad EC point '{:?}'",
                        signature.bytes()
                    )));
                }
                let mut signature_value = Vec::with_capacity(2 * coordinate_width);
                let r_padding = vec![0; coordinate_width - r.len()];
                signature_value.extend(r_padding);
                signature_value.extend_from_slice(r);
                let s_padding = vec![0; coordinate_width - s.len()];
                signature_value.extend(s_padding);
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

pub const SUPPORTED_ATTRIBUTES: &[CK_ATTRIBUTE_TYPE] = &[
    CKA_CLASS,
    CKA_TOKEN,
    CKA_LABEL,
    CKA_ID,
    CKA_VALUE,
    CKA_ISSUER,
    CKA_SERIAL_NUMBER,
    CKA_SUBJECT,
    CKA_PRIVATE,
    CKA_KEY_TYPE,
    CKA_MODULUS,
    CKA_EC_PARAMS,
];

pub fn list_objects() -> Result<Vec<Object>, TracingError> {
    let mut objects = Vec::new();
    match list_identities() {
        Ok(identities) => {
            for (cert, key) in identities {
                objects.push(Object::Cert(cert));
                objects.push(Object::Key(key));
            }
            Ok(objects)
        }
        Err(e) => Err(trace_error_stack!(e)),
    }
}

fn get_key_attribute<T: TCFType + Clone>(
    key: &SecKey,
    attr: CFStringRef,
) -> Result<T, TracingError> {
    if attr.is_null() {
        return Err(trace_error!(
            "get_key_attribute given null attr?".to_string()
        ));
    }
    let attributes: CFDictionary<CFString, T> = SECURITY_FRAMEWORK
        .sec_key_copy_attributes(&key)
        .map_err(|e| trace_error_stack!(e))?;
    match attributes.find(attr as *const _) {
        Some(value) => Ok((*value).clone()),
        None => {
            let attr_as_string = unsafe { CFString::wrap_under_get_rule(attr) }.to_string();
            Err(trace_error!(format!(
                "couldn't get key attribute {}",
                attr_as_string
            )))
        }
    }
}

fn list_identities() -> Result<Vec<(Cert, Key)>, TracingError> {
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
            return Err(trace_error!(format!("SecItemCopyMatching failed: {}", status)));
        }
        if result.is_null() {
            info!("SecItemCopyMatching returned null result");
            return Ok(Vec::new());
        }
        CFArray::<SecIdentityRef>::wrap_under_create_rule(result as CFArrayRef)
    };
    let mut identities_out = Vec::with_capacity(identities.len() as usize);
    for identity in identities.get_all_values().iter() {
        let identity = unsafe { SecIdentity::wrap_under_get_rule(*identity as SecIdentityRef) };
        let cert = match Cert::new(&identity) {
            Ok(cert) => cert,
            Err(e) => {
                error!("Cert::new failed: {}", e);
                continue;
            }
        };
        let key = match Key::new(&identity) {
            Ok(key) => key,
            Err(e) => {
                error!("Key::new failed: {}", e);
                continue;
            }
        };
        identities_out.push((cert, key));
    }
    Ok(identities_out)
}
