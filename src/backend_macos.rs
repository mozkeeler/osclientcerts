#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_variables)]
#![allow(dead_code)]

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

use crate::der::*;
use crate::types::*;

#[repr(C)]
pub struct __SecIdentity(c_void);
pub type SecIdentityRef = *const __SecIdentity;
declare_TCFType!(SecIdentity, SecIdentityRef);
impl_TCFType!(SecIdentity, SecIdentityRef, SecIdentityGetTypeID);

// The APIs we're using are thread-safe and we're serializing use of the
// Manager, so this should be safe.
pub struct SecIdentityHolder(SecIdentity);
unsafe impl Send for SecIdentityHolder {}
unsafe impl Sync for SecIdentityHolder {}

#[derive(Eq, PartialEq)]
pub struct CFStringRefHolder(CFStringRef);
unsafe impl Send for CFStringRefHolder {}
unsafe impl Sync for CFStringRefHolder {}

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
    fn new(identity: &SecIdentity, id: usize) -> Result<Cert, ()> {
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
        let issuer = unsafe {
            CFData::wrap_under_create_rule(SecCertificateCopyNormalizedIssuerSequence(
                certificate.as_concrete_TypeRef(),
            ))
        };
        let serial_number = unsafe {
            CFData::wrap_under_create_rule(SecCertificateCopySerialNumberData(
                certificate.as_concrete_TypeRef(),
                std::ptr::null_mut(),
            ))
        };
        let subject = unsafe {
            CFData::wrap_under_create_rule(SecCertificateCopyNormalizedSubjectSequence(
                certificate.as_concrete_TypeRef(),
            ))
        };

        Ok(Cert {
            class: serialize_uint(CKO_CERTIFICATE),
            token: serialize_uint(CK_TRUE),
            id: format!("{:x}", id).into_bytes(),
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

#[derive(Debug)]
pub enum KeyType {
    EC,
    RSA,
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
    fn new(identity: &SecIdentity, id: usize) -> Result<Key, ()> {
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
        let key = unsafe { SecCertificateCopyKey(certificate.as_concrete_TypeRef()) };
        if key.is_null() {
            error!("couldn't get key from certificate?");
            return Err(());
        }
        let key = unsafe { SecKey::wrap_under_create_rule(key) };
        let key_type: CFString = get_key_attribute(&key, unsafe { kSecAttrKeyType })?;
        let key_size_in_bits: CFNumber = get_key_attribute(&key, unsafe { kSecAttrKeySizeInBits })?;
        let mut modulus = None;
        let mut ec_params = None;
        let (key_type_enum, key_type_attribute) =
            if key_type.as_concrete_TypeRef() == unsafe { kSecAttrKeyTypeRSA } {
                // TODO: presumably this is fallible and we should check it before wrapping
                let public_key = unsafe {
                    CFData::wrap_under_create_rule(SecKeyCopyExternalRepresentation(
                        key.as_concrete_TypeRef(),
                        std::ptr::null_mut(),
                    ))
                };
                // RSAPublicKey ::= SEQUENCE {
                //     modulus           INTEGER,  -- n
                //     publicExponent    INTEGER   -- e
                // }
                let mut sequence = Sequence::new(public_key.bytes())?;
                let modulus_value = sequence.read_unsigned_integer()?;
                let exponent = sequence.read_unsigned_integer()?;
                if !sequence.at_end() {
                    return Err(());
                }
                modulus = Some(modulus_value.to_vec());
                (KeyType::RSA, CKK_RSA)
            } else if key_type.as_concrete_TypeRef() == unsafe { kSecAttrKeyTypeECSECPrimeRandom } {
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
            class: serialize_uint(CKO_PRIVATE_KEY),
            token: serialize_uint(CK_TRUE),
            id: format!("{:x}", id).into_bytes(),
            private: serialize_uint(CK_TRUE),
            key_type: serialize_uint(key_type_attribute),
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

    fn id(&self) -> &[u8] {
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
                CKA_MODULUS if self.modulus().is_some() => {
                    self.modulus().expect("modulus not Some?")
                }
                CKA_EC_PARAMS if self.ec_params().is_some() => {
                    self.ec_params().expect("ec_params not Some?")
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
        let result = match attribute {
            CKA_CLASS => self.class(),
            CKA_TOKEN => self.token(),
            CKA_ID => self.id(),
            CKA_PRIVATE => self.private(),
            CKA_KEY_TYPE => self.key_type(),
            CKA_MODULUS if self.modulus.is_some() => self.modulus().expect("modulus not Some?"),
            CKA_EC_PARAMS if self.ec_params.is_some() => {
                self.ec_params().expect("ec_params not Some?")
            }
            _ => return None,
        };
        Some(result)
    }

    // The input data is a hash. What algorithm we use depends on the size of the hash.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, ()> {
        let data = match self.key_type_enum {
            KeyType::EC => data,
            KeyType::RSA => {
                // In this case, `data` will be:
                // SEQUENCE {
                //   SEQUENCE {
                //     OID (hash)
                //     params (null?)
                //   }
                //   OCTET STRING (the hash to sign)
                // }
                let mut sequence = Sequence::new(data)?;
                let hash_algorithm = sequence.read_sequence()?; // TODO: actually inspect/validate this?
                let hash = sequence.read_octet_string()?;
                if !sequence.at_end() {
                    return Err(());
                }
                hash
            }
        };
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
        let signing_algorithm = match (&self.key_type_enum, data.len()) {
            (&KeyType::EC, 32) => unsafe { kSecKeyAlgorithmECDSASignatureDigestX962SHA256 },
            (&KeyType::RSA, 32) => unsafe { kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256 },
            (typ, len) => {
                error!("unsupported key type/hash combo: {:?} {}", typ, len);
                return Err(());
            }
        };
        let data = CFData::from_buffer(data);
        let signature = unsafe {
            let mut error = std::ptr::null_mut();
            let result = SecKeyCreateSignature(
                key.as_concrete_TypeRef(),
                signing_algorithm,
                data.as_concrete_TypeRef(),
                &mut error,
            );
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
                //   Ecdsa-Sig-Value  ::=  SEQUENCE  {
                //        r     INTEGER,
                //        s     INTEGER  }
                // We need to return the integers r and s
                let mut sequence = Sequence::new(signature.bytes())?;
                let r = sequence.read_unsigned_integer()?;
                let s = sequence.read_unsigned_integer()?;
                if !sequence.at_end() {
                    return Err(());
                }
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
        CFDictionary::wrap_under_create_rule(SecKeyCopyAttributes(key.as_concrete_TypeRef()))
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
    for (id, identity) in identities.get_all_values().iter().enumerate() {
        let identity = unsafe { SecIdentity::wrap_under_get_rule(*identity as SecIdentityRef) };
        let cert = Cert::new(&identity, id);
        let key = Key::new(&identity, id);
        if let (Ok(cert), Ok(key)) = (cert, key) {
            identities_out.push((cert, key));
        }
    }
    Some(identities_out)
}
