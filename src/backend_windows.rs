include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::ffi::{CStr, CString};
use std::ops::Deref;
use std::slice;
use winapi::shared::bcrypt::*;
use winapi::um::ncrypt::*;
use winapi::um::wincrypt::*;

use crate::der::*;
use crate::types::*;

fn get_cert_subject_dn(cert_info: &CERT_INFO) -> Result<Vec<u8>, ()> {
    let mut cert_info_subject = cert_info.Subject;
    let subject_dn_len = unsafe {
        CertNameToStrA(
            X509_ASN_ENCODING,
            &mut cert_info_subject,
            CERT_SIMPLE_NAME_STR,
            std::ptr::null_mut(),
            0,
        )
    };
    let mut subject_dn_string_bytes: Vec<u8> = vec![0; subject_dn_len as usize];
    let subject_dn_len = unsafe {
        CertNameToStrA(
            X509_ASN_ENCODING,
            &mut cert_info_subject,
            CERT_SIMPLE_NAME_STR,
            subject_dn_string_bytes.as_mut_ptr() as *mut i8,
            subject_dn_string_bytes.len().try_into().map_err(|_| ())?,
        )
    };
    if subject_dn_len as usize != subject_dn_string_bytes.len() {
        return Err(());
    }
    Ok(subject_dn_string_bytes)
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
    fn new(cert: PCCERT_CONTEXT) -> Result<Cert, ()> {
        let cert = unsafe { &*cert };
        let cert_info = unsafe { &*cert.pCertInfo };
        let value =
            unsafe { slice::from_raw_parts(cert.pbCertEncoded, cert.cbCertEncoded as usize) };
        let value = value.to_vec();
        let id = Sha256::digest(&value).to_vec();
        let label = get_cert_subject_dn(&cert_info)?;
        let issuer = unsafe {
            slice::from_raw_parts(cert_info.Issuer.pbData, cert_info.Issuer.cbData as usize)
        };
        let issuer = issuer.to_vec();
        let serial_number = unsafe {
            slice::from_raw_parts(
                cert_info.SerialNumber.pbData,
                cert_info.SerialNumber.cbData as usize,
            )
        };
        let serial_number = serial_number.to_vec();
        let subject = unsafe {
            slice::from_raw_parts(cert_info.Subject.pbData, cert_info.Subject.cbData as usize)
        };
        let subject = subject.to_vec();
        Ok(Cert {
            class: serialize_uint(CKO_CERTIFICATE),
            token: serialize_uint(CK_TRUE),
            id,
            label,
            value,
            issuer,
            serial_number,
            subject,
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

struct CertContext(PCCERT_CONTEXT);

// TODO: CERT_CONTEXT may not be thread-safe (unclear) (but in any case we're protected by the mutex
// on the manager, so this should be ok?)
unsafe impl Send for CertContext {}
unsafe impl Sync for CertContext {}

impl CertContext {
    fn new(cert: PCCERT_CONTEXT) -> CertContext {
        CertContext(unsafe { CertDuplicateCertificateContext(cert) })
    }
}

impl Drop for CertContext {
    fn drop(&mut self) {
        unsafe {
            CertFreeCertificateContext(self.0);
        }
    }
}

impl Deref for CertContext {
    type Target = PCCERT_CONTEXT;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

struct NCryptKeyHandle(NCRYPT_KEY_HANDLE);

impl NCryptKeyHandle {
    fn from_cert(cert: &CertContext) -> Result<NCryptKeyHandle, ()> {
        let mut key_handle = 0;
        let mut key_spec = 0;
        let mut must_free = 0;
        unsafe {
            if CryptAcquireCertificatePrivateKey(
                **cert,
                CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, // currently we only support CNG
                std::ptr::null_mut(),
                &mut key_handle,
                &mut key_spec,
                &mut must_free,
            ) != 1
            {
                return Err(());
            }
        }
        assert!(key_spec == CERT_NCRYPT_KEY_SPEC);
        assert!(must_free != 0);
        Ok(NCryptKeyHandle(key_handle as NCRYPT_KEY_HANDLE))
    }
}

impl Drop for NCryptKeyHandle {
    fn drop(&mut self) {
        unsafe {
            NCryptFreeObject(self.0 as NCRYPT_HANDLE);
        }
    }
}

impl Deref for NCryptKeyHandle {
    type Target = NCRYPT_KEY_HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
pub enum KeyType {
    EC,
    RSA,
}

pub struct Key {
    cert: CertContext,
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
    fn new(cert_context: PCCERT_CONTEXT) -> Result<Key, ()> {
        let cert = unsafe { *cert_context };
        let cert_der =
            unsafe { slice::from_raw_parts(cert.pbCertEncoded, cert.cbCertEncoded as usize) };
        let id = Sha256::digest(cert_der).to_vec();
        let id = id.to_vec();
        let cert_info = unsafe { &*cert.pCertInfo };
        let mut modulus = None;
        let mut ec_params = None;
        let spki = &cert_info.SubjectPublicKeyInfo;
        let algorithm_oid = unsafe { CStr::from_ptr(spki.Algorithm.pszObjId) }
            .to_str()
            .map_err(|_| ())?;
        let (key_type_enum, key_type_attribute) = if algorithm_oid == szOID_RSA_RSA {
            if spki.PublicKey.cUnusedBits != 0 {
                return Err(());
            }
            let public_key_bytes = unsafe {
                std::slice::from_raw_parts(spki.PublicKey.pbData, spki.PublicKey.cbData as usize)
            };
            let modulus_value = read_rsa_modulus(public_key_bytes)?;
            modulus = Some(modulus_value);
            (KeyType::RSA, CKK_RSA)
        } else if algorithm_oid == szOID_ECC_PUBLIC_KEY {
            let params = &spki.Algorithm.Parameters;
            ec_params = Some(
                unsafe { std::slice::from_raw_parts(params.pbData, params.cbData as usize) }
                    .to_vec(),
            );
            (KeyType::EC, CKK_EC)
        } else {
            return Err(());
        };
        Ok(Key {
            cert: CertContext::new(cert_context),
            class: serialize_uint(CKO_PRIVATE_KEY),
            token: serialize_uint(CK_TRUE),
            id,
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

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, ()> {
        let key = NCryptKeyHandle::from_cert(&self.cert)?;
        let mut data = data.to_vec();
        let (params, flags) = match self.key_type_enum {
            KeyType::EC => (None, 0),
            KeyType::RSA => (
                Some(BCRYPT_PKCS1_PADDING_INFO {
                    // Because the hash algorithm is encoded in `data`, we don't have to (and don't
                    // want to) specify a particular algorithm here.
                    pszAlgId: std::ptr::null(),
                }),
                NCRYPT_PAD_PKCS1_FLAG,
            ),
        };
        let params_ptr = if let Some(mut params) = params {
            (&mut params as *mut BCRYPT_PKCS1_PADDING_INFO) as *mut std::os::raw::c_void
        } else {
            std::ptr::null_mut()
        };
        let mut signature_len = 0;
        let status = unsafe {
            NCryptSignHash(
                *key,
                params_ptr,
                data.as_mut_ptr(),
                data.len().try_into().map_err(|_| ())?,
                std::ptr::null_mut(),
                0,
                &mut signature_len,
                flags,
            )
        };
        // 0 is "ERROR_SUCCESS" (but "ERROR_SUCCESS" is unsigned, whereas SECURITY_STATUS is signed)
        if status != 0 {
            error!("NCryptSignHash failed (first time), {}", status);
            // TODO: stringify/log error?
            return Err(());
        }
        debug!("signature_len is {}", signature_len);
        let mut signature = vec![0; signature_len as usize];
        let mut final_signature_len = signature_len;
        let status = unsafe {
            NCryptSignHash(
                *key,
                params_ptr,
                data.as_mut_ptr(),
                data.len().try_into().map_err(|_| ())?,
                signature.as_mut_ptr(),
                signature_len,
                &mut final_signature_len,
                flags,
            )
        };
        if status != 0 {
            error!("NCryptSignHash failed (second time) {}", status);
            // TODO: stringify/log error?
            return Err(());
        }
        assert!(final_signature_len == signature_len);
        Ok(signature)
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

struct CertStore {
    handle: HCERTSTORE,
}

impl Drop for CertStore {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                CertCloseStore(self.handle, 0);
            }
        }
    }
}

impl Deref for CertStore {
    type Target = HCERTSTORE;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl CertStore {
    fn new(handle: HCERTSTORE) -> CertStore {
        CertStore { handle }
    }
}

pub fn list_objects() -> Vec<Object> {
    let mut objects = Vec::new();
    let location_flags = CERT_SYSTEM_STORE_CURRENT_USER // TODO: loop over multiple locations
        | CERT_STORE_OPEN_EXISTING_FLAG
        | CERT_STORE_READONLY_FLAG;
    let store_name = CString::new("My").expect("CString::new failed");
    let store = CertStore::new(unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_REGISTRY_A,
            0,
            0,
            location_flags,
            store_name.as_ptr() as *const winapi::ctypes::c_void,
        )
    });
    if store.is_null() {
        warn!("CertOpenStore failed");
        return objects;
    }
    let mut cert_context: PCCERT_CONTEXT = std::ptr::null_mut();
    loop {
        cert_context = unsafe {
            CertFindCertificateInStore(
                *store,
                X509_ASN_ENCODING,
                CERT_FIND_HAS_PRIVATE_KEY,
                CERT_FIND_ANY,
                std::ptr::null_mut(),
                cert_context,
            )
        };
        if cert_context.is_null() {
            break;
        }
        let cert = match Cert::new(cert_context) {
            Ok(cert) => cert,
            Err(()) => continue,
        };
        let key = match Key::new(cert_context) {
            Ok(key) => key,
            Err(()) => continue,
        };
        objects.push(Object::Cert(cert));
        objects.push(Object::Key(key));
    }
    objects
}
