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

pub struct Cert {
    handle: SecIdentity,
}

impl Cert {
    fn new(handle: SecIdentity) -> Cert {
        Cert { handle }
    }
}

pub fn list_certs() -> Vec<Cert> {
    let mut certs = Vec::new();
    if let Some(identities) = list_identities() {
        for identity in identities.iter() {
            certs.push(Cert::new(identity.clone()));
        }
    }
    certs
}

// Really what we have to do is return persistent references (kSecReturnPersistentRef) so that our
// manager can hold on to them safely across threads. When we do anything with them, we'll have to
// get them back with SecItemCopyMatching({ kSecMatchItemList: [id] }).
// https://developer.apple.com/documentation/security/keychain_services/keychain_items/item_return_result_keys
pub fn list_identities() -> Option<CFArray<SecIdentity>> {
    unsafe {
        let status = SecKeychainUnlock(std::ptr::null_mut(), 0, std::ptr::null(), 0);
        if status != errSecSuccess {
            eprintln!("SecKeychainUnlock failed: {}", status);
            return None;
        }
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
            eprintln!("SecItemCopyMatching failed: {}", status);
            return None;
        }
        if result.is_null() {
            eprintln!("no client certs?");
            return None;
        }
        let result: CFArray<SecIdentity> = CFArray::wrap_under_get_rule(result as CFArrayRef);
        eprintln!("{}", result.len());
        Some(result)
    }
}
