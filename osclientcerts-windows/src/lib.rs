#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_variables)]
#![allow(dead_code)]

extern crate byteorder;
#[macro_use]
extern crate log;
extern crate osclientcerts_der;
extern crate osclientcerts_types;
extern crate sha2;
extern crate winapi;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use byteorder::{NativeEndian, WriteBytesExt};
use osclientcerts_der::*;
use osclientcerts_types::*;
use sha2::{Digest, Sha256};
use std::ffi::{CStr, CString};
use std::ops::Deref;
use std::os::raw::c_void;
use std::slice;
use winapi::shared::bcrypt::*;
use winapi::um::ncrypt::*;
use winapi::um::wincrypt::*;

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

#[derive(Debug)]
pub enum KeyType {
    EC,
    RSA,
}

pub struct Key {
    handle: NCRYPT_KEY_HANDLE, // TODO: scope this?
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
            (&mut params as *mut BCRYPT_PKCS1_PADDING_INFO) as *mut c_void
        } else {
            std::ptr::null_mut()
        };
        let mut signature_len = 0;
        // TODO: len conversion safety
        let status = unsafe {
            NCryptSignHash(
                self.handle,
                params_ptr,
                data.as_mut_ptr(),
                data.len() as u32,
                std::ptr::null_mut(),
                0,
                &mut signature_len,
                flags,
            )
        };
        // 0 is "ERROR_SUCCESS" (but "ERROR_SUCCESS" is unsigned, whereas SECURITY_STATUS is signed)
        if status != 0 {
            debug!("NCryptSignHash failed (first time), {}", status);
            // TODO: stringify/log error?
            return Err(());
        }
        debug!("signature_len is {}", signature_len);
        let mut signature = vec![0; signature_len as usize];
        let mut final_signature_len = signature_len;
        let status = unsafe {
            NCryptSignHash(
                self.handle,
                params_ptr,
                data.as_mut_ptr(),
                data.len() as u32,
                signature.as_mut_ptr(),
                signature_len,
                &mut final_signature_len,
                flags,
            )
        };
        if status != 0 {
            debug!("NCryptSignHash failed (second time) {}", status);
            // TODO: stringify/log error?
            return Err(());
        }
        assert!(final_signature_len == signature_len);
        eprintln!("signature? {:x?}", signature);
        Ok(signature)
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            NCryptFreeObject(self.handle as NCRYPT_HANDLE);
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

fn cert_from_cert_context(context: &CERT_CONTEXT) -> Cert {
    let cert_info = unsafe { &*context.pCertInfo };
    let value =
        unsafe { slice::from_raw_parts(context.pbCertEncoded, context.cbCertEncoded as usize) };
    let value = value.to_vec();
    let id = Sha256::digest(&value).to_vec();
    eprintln!("cert with id {:?}", id);
    let label = id.clone(); // TODO
    let issuer =
        unsafe { slice::from_raw_parts(cert_info.Issuer.pbData, cert_info.Issuer.cbData as usize) };
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
    Cert {
        class: serialize_uint(CKO_CERTIFICATE),
        token: serialize_uint(CK_TRUE),
        id,
        label,
        value,
        issuer,
        serial_number,
        subject,
    }
}

fn key_from_cert_context_and_key_handle(
    cert_context: &CERT_CONTEXT,
    key_handle: NCRYPT_KEY_HANDLE,
) -> Result<Key, ()> {
    let cert_der = unsafe {
        slice::from_raw_parts(
            cert_context.pbCertEncoded,
            cert_context.cbCertEncoded as usize,
        )
    };
    let id = Sha256::digest(cert_der).to_vec();
    let id = id.to_vec();
    eprintln!("key with id {:?}", id);
    let cert_info = unsafe { &*cert_context.pCertInfo };
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
        // TODO: this is shared with the MacOS implementation - refactor to der module?
        // RSAPublicKey ::= SEQUENCE {
        //     modulus           INTEGER,  -- n
        //     publicExponent    INTEGER   -- e
        // }
        let mut sequence = Sequence::new(public_key_bytes)?;
        let modulus_value = sequence.read_unsigned_integer()?;
        let exponent = sequence.read_unsigned_integer()?;
        if !sequence.at_end() {
            return Err(());
        }
        modulus = Some(modulus_value.to_vec());
        (KeyType::RSA, CKK_RSA)
    } else if algorithm_oid == szOID_ECC_PUBLIC_KEY {
        let params = &spki.Algorithm.Parameters;
        ec_params = Some(
            unsafe { std::slice::from_raw_parts(params.pbData, params.cbData as usize) }.to_vec(),
        );
        (KeyType::EC, CKK_EC)
    } else {
        return Err(());
    };
    Ok(Key {
        handle: key_handle, // TODO
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
    unsafe {
        //let location_flags = CERT_SYSTEM_STORE_LOCAL_MACHINE
        let location_flags = CERT_SYSTEM_STORE_CURRENT_USER // TODO: loop over multiple locations
            | CERT_STORE_OPEN_EXISTING_FLAG
            | CERT_STORE_READONLY_FLAG;
        let store_name = CString::new("My").expect("CString::new failed?"); // TODO: more locations?
                                                                            // TODO: raii types
                                                                            // TODO: one of these 0s is supposed to be X509_ASN_ENCODING I think
        let store = CertStore::new(CertOpenStore(
            CERT_STORE_PROV_SYSTEM_REGISTRY_A,
            0,
            0,
            location_flags,
            store_name.into_raw() as *const std::ffi::c_void,
        ));
        if store.is_null() {
            warn!("CertOpenStore failed");
            return objects;
        }
        let mut cert_context: PCCERT_CONTEXT = std::ptr::null_mut();
        cert_context = CertFindCertificateInStore(
            *store,
            X509_ASN_ENCODING,
            CERT_FIND_HAS_PRIVATE_KEY,
            CERT_FIND_ANY,
            std::ptr::null_mut(),
            cert_context,
        );
        while !cert_context.is_null() {
            // TODO: I think I'm using the skid as the PKCS#11 object ID, which might not be good if
            // there are multiple certs with the same skid. Switch to hash of cert DER?
            // TODO: refactor common code?
            let mut key_handle = 0;
            let mut key_spec = 0;
            let mut must_free = 0;
            // TODO: CRYPT_ACQUIRE_SILENT_FLAG may be helpful here.
            if CryptAcquireCertificatePrivateKey(
                cert_context,
                CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, // TODO: currently we only support CNG
                std::ptr::null_mut(),
                &mut key_handle,
                &mut key_spec,
                &mut must_free,
            ) == 1
            {
                assert!(key_spec == CERT_NCRYPT_KEY_SPEC);
                assert!(must_free != 0);
                if let Ok(key) =
                    key_from_cert_context_and_key_handle(&*cert_context, key_handle as u64)
                {
                    objects.push(Object::Cert(cert_from_cert_context(&*cert_context)));
                    objects.push(Object::Key(key));
                }
            }

            cert_context = CertFindCertificateInStore(
                *store,
                X509_ASN_ENCODING,
                CERT_FIND_HAS_PRIVATE_KEY,
                CERT_FIND_ANY,
                std::ptr::null_mut(),
                cert_context,
            );
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
