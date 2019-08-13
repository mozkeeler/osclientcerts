#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_variables)]

extern crate byteorder;
extern crate env_logger;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[cfg(target_os = "macos")]
extern crate osclientcerts_macos as osclientcerts_platform;
extern crate osclientcerts_types;
#[cfg(target_os = "windows")]
extern crate osclientcerts_windows as osclientcerts_platform;

use osclientcerts_types::*;
use std::sync::Mutex;

mod manager;
use manager::Manager;

lazy_static! {
    static ref IMPL: Mutex<Manager> = {
        env_logger::init();
        Mutex::new(Manager::new())
    };
}

extern "C" fn C_Initialize(pInitArgs: CK_C_INITIALIZE_ARGS_PTR) -> CK_RV {
    eprintln!("C_Initialize");
    // Getting the manager initializes our logging, so do it first.
    let manager = IMPL.lock().unwrap();
    debug!("C_Initialize: CKR_OK");
    CKR_OK
}

extern "C" fn C_Finalize(pReserved: CK_VOID_PTR) -> CK_RV {
    debug!("C_Finalize: CKR_OK");
    CKR_OK
}

extern "C" fn C_GetInfo(pInfo: CK_INFO_PTR) -> CK_RV {
    debug!("C_GetInfo: CKR_OK");
    let mut info = CK_INFO::default();
    info.cryptokiVersion.major = 2;
    info.cryptokiVersion.minor = 2;
    info.manufacturerID = *b"Mozilla Corporation\0\0\0\0\0\0\0\0\0\0\0\0\0";
    info.libraryDescription = *b"OS Client Cert Module\0\0\0\0\0\0\0\0\0\0\0";
    unsafe {
        *pInfo = info;
    }
    CKR_OK
}

// We only have one slot. Its ID is 1.
const SLOT_ID: CK_SLOT_ID = 1;

extern "C" fn C_GetSlotList(
    tokenPresent: CK_BBOOL,
    pSlotList: CK_SLOT_ID_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    if pulCount.is_null() {
        debug!("C_GetSlotList: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    if pSlotList.is_null() {
        unsafe {
            *pulCount = 1;
        }
    } else {
        let slotCount = unsafe { *pulCount };
        if slotCount < 1 {
            debug!("C_GetSlotList: CKR_BUFFER_TOO_SMALL");
            return CKR_BUFFER_TOO_SMALL;
        }
        unsafe {
            *pSlotList = SLOT_ID;
        }
    };
    debug!("C_GetSlotList: CKR_OK");
    CKR_OK
}

extern "C" fn C_GetSlotInfo(slotID: CK_SLOT_ID, pInfo: CK_SLOT_INFO_PTR) -> CK_RV {
    if slotID != SLOT_ID || pInfo.is_null() {
        debug!("C_GetSlotInfo: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    let mut slot_info = CK_SLOT_INFO::default();
    slot_info.slotDescription1 = *b"OS Client Cert Slot\0\0\0\0\0\0\0\0\0\0\0\0\0";
    slot_info.manufacturerID = *b"Mozilla Corporation\0\0\0\0\0\0\0\0\0\0\0\0\0";
    slot_info.flags = CKF_TOKEN_PRESENT;
    unsafe {
        *pInfo = slot_info;
    }
    debug!("C_GetSlotInfo: CKR_OK");
    CKR_OK
}

extern "C" fn C_GetTokenInfo(slotID: CK_SLOT_ID, pInfo: CK_TOKEN_INFO_PTR) -> CK_RV {
    if slotID != SLOT_ID || pInfo.is_null() {
        debug!("C_GetTokenInfo: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    let mut token_info = CK_TOKEN_INFO::default();
    token_info.label = *b"OS Client Cert Token\0\0\0\0\0\0\0\0\0\0\0\0";
    token_info.manufacturerID = *b"Mozilla Corporation\0\0\0\0\0\0\0\0\0\0\0\0\0";
    token_info.model = *b"libosclientcerts";
    unsafe {
        *pInfo = token_info;
    }
    debug!("C_GetTokenInfo: CKR_OK");
    CKR_OK
}

extern "C" fn C_GetMechanismList(
    slotID: CK_SLOT_ID,
    pMechanismList: CK_MECHANISM_TYPE_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    if slotID != SLOT_ID || pulCount.is_null() {
        debug!("C_GetMechanismList: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    if pMechanismList.is_null() {
        unsafe {
            *pulCount = 0;
        }
    }
    debug!("C_GetMechanismList: CKR_OK");
    CKR_OK
}

extern "C" fn C_GetMechanismInfo(
    slotID: CK_SLOT_ID,
    type_: CK_MECHANISM_TYPE,
    pInfo: CK_MECHANISM_INFO_PTR,
) -> CK_RV {
    debug!("C_GetMechanismInfo: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_InitToken(
    slotID: CK_SLOT_ID,
    pPin: CK_UTF8CHAR_PTR,
    ulPinLen: CK_ULONG,
    pLabel: CK_UTF8CHAR_PTR,
) -> CK_RV {
    debug!("C_InitToken: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_InitPIN(
    hSession: CK_SESSION_HANDLE,
    pPin: CK_UTF8CHAR_PTR,
    ulPinLen: CK_ULONG,
) -> CK_RV {
    debug!("C_InitPIN: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_SetPIN(
    hSession: CK_SESSION_HANDLE,
    pOldPin: CK_UTF8CHAR_PTR,
    ulOldLen: CK_ULONG,
    pNewPin: CK_UTF8CHAR_PTR,
    ulNewLen: CK_ULONG,
) -> CK_RV {
    debug!("C_SetPIN: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_OpenSession(
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    pApplication: CK_VOID_PTR,
    Notify: CK_NOTIFY,
    phSession: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    if slotID != SLOT_ID || phSession.is_null() {
        debug!("C_OpenSession: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    let mut manager = IMPL.lock().unwrap();
    let session_handle = manager.open_session();
    unsafe {
        *phSession = session_handle;
    }
    debug!("C_OpenSession: CKR_OK");
    CKR_OK
}

extern "C" fn C_CloseSession(hSession: CK_SESSION_HANDLE) -> CK_RV {
    debug!("C_CloseSession: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_CloseAllSessions(slotID: CK_SLOT_ID) -> CK_RV {
    if slotID != SLOT_ID {
        debug!("C_CloseAllSessions: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    let mut manager = IMPL.lock().unwrap();
    manager.close_all_sessions();
    debug!("C_CloseAllSessions: CKR_OK");
    CKR_OK
}

extern "C" fn C_GetSessionInfo(hSession: CK_SESSION_HANDLE, pInfo: CK_SESSION_INFO_PTR) -> CK_RV {
    debug!("C_GetSessionInfo: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_GetOperationState(
    hSession: CK_SESSION_HANDLE,
    pOperationState: CK_BYTE_PTR,
    pulOperationStateLen: CK_ULONG_PTR,
) -> CK_RV {
    debug!("C_GetOperationState: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_SetOperationState(
    hSession: CK_SESSION_HANDLE,
    pOperationState: CK_BYTE_PTR,
    ulOperationStateLen: CK_ULONG,
    hEncryptionKey: CK_OBJECT_HANDLE,
    hAuthenticationKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    debug!("C_SetOperationState: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_Login(
    hSession: CK_SESSION_HANDLE,
    userType: CK_USER_TYPE,
    pPin: CK_UTF8CHAR_PTR,
    ulPinLen: CK_ULONG,
) -> CK_RV {
    debug!("C_Login: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_Logout(hSession: CK_SESSION_HANDLE) -> CK_RV {
    debug!("C_Logout: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_CreateObject(
    hSession: CK_SESSION_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
    phObject: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    debug!("C_CreateObject: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_CopyObject(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
    phNewObject: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    debug!("C_CopyObject: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_DestroyObject(hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE) -> CK_RV {
    debug!("C_DestroyObject: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_GetObjectSize(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pulSize: CK_ULONG_PTR,
) -> CK_RV {
    debug!("C_GetObjectSize: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_GetAttributeValue(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV {
    if pTemplate.is_null() {
        debug!("C_GetAttributeValue: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    // TODO: check hSession
    let mut manager = IMPL.lock().unwrap();
    let object = match manager.get_object(hObject) {
        Ok(object) => object,
        Err(()) => {
            debug!("C_GetAttributeValue: CKR_ARGUMENTS_BAD");
            return CKR_ARGUMENTS_BAD;
        }
    };
    for i in 0..ulCount {
        let mut attr = unsafe { &mut *pTemplate.offset(i as isize) };
        if let Some(attr_value) = object.get_attribute(attr.type_) {
            if attr.pValue.is_null() {
                attr.ulValueLen = attr_value.len() as CK_ULONG;
            } else {
                unsafe {
                    let ptr: *mut u8 = attr.pValue as *mut u8;
                    // TODO: length check attr_value
                    std::ptr::copy_nonoverlapping(
                        attr_value.as_ptr(),
                        ptr,
                        attr.ulValueLen as usize,
                    );
                }
            }
        } else {
            attr.ulValueLen = (0 - 1) as CK_ULONG;
        }
    }
    debug!("C_GetAttributeValue: CKR_OK");
    CKR_OK
}

extern "C" fn C_SetAttributeValue(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV {
    debug!("C_SetAttributeValue: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_FindObjectsInit(
    hSession: CK_SESSION_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV {
    if pTemplate.is_null() {
        debug!("C_FindObjectsInit: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    let mut attrs = Vec::new();
    for i in 0..ulCount {
        let attr = unsafe { &*pTemplate.offset(i as isize) };
        debug!("  {}", attr);
        let slice = unsafe {
            std::slice::from_raw_parts(attr.pValue as *const u8, attr.ulValueLen as usize)
        };
        attrs.push((attr.type_, slice.to_owned()));
    }
    let mut manager = IMPL.lock().unwrap();
    match manager.start_search(hSession, &attrs) {
        Ok(()) => {}
        Err(()) => {
            debug!("C_FindObjectsInit: CKR_ARGUMENTS_BAD");
            return CKR_ARGUMENTS_BAD;
        }
    }
    debug!("C_FindObjectsInit: CKR_OK");
    CKR_OK
}

extern "C" fn C_FindObjects(
    hSession: CK_SESSION_HANDLE,
    phObject: CK_OBJECT_HANDLE_PTR,
    ulMaxObjectCount: CK_ULONG,
    pulObjectCount: CK_ULONG_PTR,
) -> CK_RV {
    if phObject.is_null() || pulObjectCount.is_null() {
        debug!("C_FindObjects: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    let manager = IMPL.lock().unwrap();
    let handles = match manager.search(hSession) {
        Ok(handles) => handles,
        Err(()) => {
            debug!("C_FindObjects: CKR_ARGUMENTS_BAD");
            return CKR_ARGUMENTS_BAD;
        }
    };
    debug!("C_FindObjects: found handles {:?}", handles);
    // TODO: not quite sure what the right semantics are re. if we have more handles than ulMaxObjectCount
    unsafe {
        *pulObjectCount = handles.len() as CK_ULONG;
    }
    for (index, handle) in handles.iter().enumerate() {
        if index < ulMaxObjectCount as usize {
            unsafe {
                *(phObject.add(index)) = *handle;
            }
        }
    }
    debug!("C_FindObjects: CKR_OK");
    CKR_OK
}

extern "C" fn C_FindObjectsFinal(hSession: CK_SESSION_HANDLE) -> CK_RV {
    let mut manager = IMPL.lock().unwrap();
    manager.clear_search(hSession); // TODO: return error if there was no search?
    debug!("C_FindObjectsFinal: CKR_OK");
    CKR_OK
}

extern "C" fn C_EncryptInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    debug!("C_EncryptInit: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_Encrypt(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pEncryptedData: CK_BYTE_PTR,
    pulEncryptedDataLen: CK_ULONG_PTR,
) -> CK_RV {
    debug!("C_Encrypt: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_EncryptUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
    pEncryptedPart: CK_BYTE_PTR,
    pulEncryptedPartLen: CK_ULONG_PTR,
) -> CK_RV {
    debug!("C_EncryptUpdate: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_EncryptFinal(
    hSession: CK_SESSION_HANDLE,
    pLastEncryptedPart: CK_BYTE_PTR,
    pulLastEncryptedPartLen: CK_ULONG_PTR,
) -> CK_RV {
    debug!("C_EncryptFinal: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_DecryptInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    debug!("C_DecryptInit: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_Decrypt(
    hSession: CK_SESSION_HANDLE,
    pEncryptedData: CK_BYTE_PTR,
    ulEncryptedDataLen: CK_ULONG,
    pData: CK_BYTE_PTR,
    pulDataLen: CK_ULONG_PTR,
) -> CK_RV {
    debug!("C_Decrypt: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_DecryptUpdate(
    hSession: CK_SESSION_HANDLE,
    pEncryptedPart: CK_BYTE_PTR,
    ulEncryptedPartLen: CK_ULONG,
    pPart: CK_BYTE_PTR,
    pulPartLen: CK_ULONG_PTR,
) -> CK_RV {
    debug!("C_DecryptUpdate: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_DecryptFinal(
    hSession: CK_SESSION_HANDLE,
    pLastPart: CK_BYTE_PTR,
    pulLastPartLen: CK_ULONG_PTR,
) -> CK_RV {
    debug!("C_DecryptFinal: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_DigestInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR) -> CK_RV {
    debug!("C_DigestInit: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_Digest(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pDigest: CK_BYTE_PTR,
    pulDigestLen: CK_ULONG_PTR,
) -> CK_RV {
    debug!("C_Digest: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_DigestUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
) -> CK_RV {
    debug!("C_DigestUpdate: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_DigestKey(hSession: CK_SESSION_HANDLE, hKey: CK_OBJECT_HANDLE) -> CK_RV {
    debug!("C_DigestKey: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_DigestFinal(
    hSession: CK_SESSION_HANDLE,
    pDigest: CK_BYTE_PTR,
    pulDigestLen: CK_ULONG_PTR,
) -> CK_RV {
    debug!("C_DigestFinal: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_SignInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    if pMechanism.is_null() {
        debug!("C_SignInit: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    // pMechanism generally appears to be empty.
    let mut manager = IMPL.lock().unwrap();
    match manager.start_sign(hSession, hKey) {
        Ok(()) => {}
        Err(()) => {
            debug!("C_SignInit: CKR_GENERAL_ERROR");
            return CKR_GENERAL_ERROR;
        }
    };
    debug!("C_SignInit: CKR_OK");
    CKR_OK
}

extern "C" fn C_Sign(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR,
) -> CK_RV {
    // TODO: we seem to always pass in allocated memory - do we need to handle
    // the case where we're called to see what the length will be first?
    if pData.is_null() || pSignature.is_null() || pulSignatureLen.is_null() {
        debug!("C_Sign: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    let manager = IMPL.lock().unwrap();
    let data = unsafe { std::slice::from_raw_parts(pData, ulDataLen as usize) };
    match manager.sign(hSession, data) {
        Ok(signature) => {
            let signature_capacity = unsafe { *pulSignatureLen } as usize;
            if signature_capacity < signature.len() {
                debug!("C_Sign: CKR_ARGUMENTS_BAD");
                return CKR_ARGUMENTS_BAD;
            }
            let ptr: *mut u8 = pSignature as *mut u8;
            unsafe {
                std::ptr::copy_nonoverlapping(signature.as_ptr(), ptr, signature.len());
            }
        }
        Err(()) => {
            debug!("C_Sign: CKR_GENERAL_ERROR");
            return CKR_GENERAL_ERROR;
        }
    };
    debug!("C_Sign: CKR_OK");
    CKR_OK
}

extern "C" fn C_SignUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
) -> CK_RV {
    debug!("C_SignUpdate: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_SignFinal(
    hSession: CK_SESSION_HANDLE,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR,
) -> CK_RV {
    debug!("C_SignFinal: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_SignRecoverInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    debug!("C_SignRecoverInit: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_SignRecover(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR,
) -> CK_RV {
    debug!("C_SignRecover: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_VerifyInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    debug!("C_VerifyInit: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_Verify(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    ulSignatureLen: CK_ULONG,
) -> CK_RV {
    debug!("C_Verify: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_VerifyUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
) -> CK_RV {
    debug!("C_VerifyUpdate: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_VerifyFinal(
    hSession: CK_SESSION_HANDLE,
    pSignature: CK_BYTE_PTR,
    ulSignatureLen: CK_ULONG,
) -> CK_RV {
    debug!("C_VerifyFinal: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_VerifyRecoverInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    debug!("C_VerifyRecoverInit: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_VerifyRecover(
    hSession: CK_SESSION_HANDLE,
    pSignature: CK_BYTE_PTR,
    ulSignatureLen: CK_ULONG,
    pData: CK_BYTE_PTR,
    pulDataLen: CK_ULONG_PTR,
) -> CK_RV {
    debug!("C_VerifyRecover: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_DigestEncryptUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
    pEncryptedPart: CK_BYTE_PTR,
    pulEncryptedPartLen: CK_ULONG_PTR,
) -> CK_RV {
    debug!("C_DigestEncryptUpdate: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_DecryptDigestUpdate(
    hSession: CK_SESSION_HANDLE,
    pEncryptedPart: CK_BYTE_PTR,
    ulEncryptedPartLen: CK_ULONG,
    pPart: CK_BYTE_PTR,
    pulPartLen: CK_ULONG_PTR,
) -> CK_RV {
    debug!("C_DecryptDigestUpdate: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_SignEncryptUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
    pEncryptedPart: CK_BYTE_PTR,
    pulEncryptedPartLen: CK_ULONG_PTR,
) -> CK_RV {
    debug!("C_SignEncryptUpdate: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_DecryptVerifyUpdate(
    hSession: CK_SESSION_HANDLE,
    pEncryptedPart: CK_BYTE_PTR,
    ulEncryptedPartLen: CK_ULONG,
    pPart: CK_BYTE_PTR,
    pulPartLen: CK_ULONG_PTR,
) -> CK_RV {
    debug!("C_DecryptVerifyUpdate: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_GenerateKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    debug!("C_GenerateKey: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_GenerateKeyPair(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    pPublicKeyTemplate: CK_ATTRIBUTE_PTR,
    ulPublicKeyAttributeCount: CK_ULONG,
    pPrivateKeyTemplate: CK_ATTRIBUTE_PTR,
    ulPrivateKeyAttributeCount: CK_ULONG,
    phPublicKey: CK_OBJECT_HANDLE_PTR,
    phPrivateKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    debug!("C_GenerateKeyPair: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_WrapKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hWrappingKey: CK_OBJECT_HANDLE,
    hKey: CK_OBJECT_HANDLE,
    pWrappedKey: CK_BYTE_PTR,
    pulWrappedKeyLen: CK_ULONG_PTR,
) -> CK_RV {
    debug!("C_WrapKey: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_UnwrapKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hUnwrappingKey: CK_OBJECT_HANDLE,
    pWrappedKey: CK_BYTE_PTR,
    ulWrappedKeyLen: CK_ULONG,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulAttributeCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    debug!("C_UnwrapKey: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_DeriveKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hBaseKey: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulAttributeCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    debug!("C_DeriveKey: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_SeedRandom(
    hSession: CK_SESSION_HANDLE,
    pSeed: CK_BYTE_PTR,
    ulSeedLen: CK_ULONG,
) -> CK_RV {
    debug!("C_SeedRandom: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_GenerateRandom(
    hSession: CK_SESSION_HANDLE,
    RandomData: CK_BYTE_PTR,
    ulRandomLen: CK_ULONG,
) -> CK_RV {
    debug!("C_GenerateRandom: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_GetFunctionStatus(hSession: CK_SESSION_HANDLE) -> CK_RV {
    debug!("C_GetFunctionStatus: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_CancelFunction(hSession: CK_SESSION_HANDLE) -> CK_RV {
    debug!("C_CancelFunction: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_WaitForSlotEvent(
    flags: CK_FLAGS,
    pSlot: CK_SLOT_ID_PTR,
    pRserved: CK_VOID_PTR,
) -> CK_RV {
    debug!("C_WaitForSlotEvent: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

static FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION { major: 2, minor: 2 },
    C_Initialize: Some(C_Initialize),
    C_Finalize: Some(C_Finalize),
    C_GetInfo: Some(C_GetInfo),
    C_GetFunctionList: None,
    C_GetSlotList: Some(C_GetSlotList),
    C_GetSlotInfo: Some(C_GetSlotInfo),
    C_GetTokenInfo: Some(C_GetTokenInfo),
    C_GetMechanismList: Some(C_GetMechanismList),
    C_GetMechanismInfo: Some(C_GetMechanismInfo),
    C_InitToken: Some(C_InitToken),
    C_InitPIN: Some(C_InitPIN),
    C_SetPIN: Some(C_SetPIN),
    C_OpenSession: Some(C_OpenSession),
    C_CloseSession: Some(C_CloseSession),
    C_CloseAllSessions: Some(C_CloseAllSessions),
    C_GetSessionInfo: Some(C_GetSessionInfo),
    C_GetOperationState: Some(C_GetOperationState),
    C_SetOperationState: Some(C_SetOperationState),
    C_Login: Some(C_Login),
    C_Logout: Some(C_Logout),
    C_CreateObject: Some(C_CreateObject),
    C_CopyObject: Some(C_CopyObject),
    C_DestroyObject: Some(C_DestroyObject),
    C_GetObjectSize: Some(C_GetObjectSize),
    C_GetAttributeValue: Some(C_GetAttributeValue),
    C_SetAttributeValue: Some(C_SetAttributeValue),
    C_FindObjectsInit: Some(C_FindObjectsInit),
    C_FindObjects: Some(C_FindObjects),
    C_FindObjectsFinal: Some(C_FindObjectsFinal),
    C_EncryptInit: Some(C_EncryptInit),
    C_Encrypt: Some(C_Encrypt),
    C_EncryptUpdate: Some(C_EncryptUpdate),
    C_EncryptFinal: Some(C_EncryptFinal),
    C_DecryptInit: Some(C_DecryptInit),
    C_Decrypt: Some(C_Decrypt),
    C_DecryptUpdate: Some(C_DecryptUpdate),
    C_DecryptFinal: Some(C_DecryptFinal),
    C_DigestInit: Some(C_DigestInit),
    C_Digest: Some(C_Digest),
    C_DigestUpdate: Some(C_DigestUpdate),
    C_DigestKey: Some(C_DigestKey),
    C_DigestFinal: Some(C_DigestFinal),
    C_SignInit: Some(C_SignInit),
    C_Sign: Some(C_Sign),
    C_SignUpdate: Some(C_SignUpdate),
    C_SignFinal: Some(C_SignFinal),
    C_SignRecoverInit: Some(C_SignRecoverInit),
    C_SignRecover: Some(C_SignRecover),
    C_VerifyInit: Some(C_VerifyInit),
    C_Verify: Some(C_Verify),
    C_VerifyUpdate: Some(C_VerifyUpdate),
    C_VerifyFinal: Some(C_VerifyFinal),
    C_VerifyRecoverInit: Some(C_VerifyRecoverInit),
    C_VerifyRecover: Some(C_VerifyRecover),
    C_DigestEncryptUpdate: Some(C_DigestEncryptUpdate),
    C_DecryptDigestUpdate: Some(C_DecryptDigestUpdate),
    C_SignEncryptUpdate: Some(C_SignEncryptUpdate),
    C_DecryptVerifyUpdate: Some(C_DecryptVerifyUpdate),
    C_GenerateKey: Some(C_GenerateKey),
    C_GenerateKeyPair: Some(C_GenerateKeyPair),
    C_WrapKey: Some(C_WrapKey),
    C_UnwrapKey: Some(C_UnwrapKey),
    C_DeriveKey: Some(C_DeriveKey),
    C_SeedRandom: Some(C_SeedRandom),
    C_GenerateRandom: Some(C_GenerateRandom),
    C_GetFunctionStatus: Some(C_GetFunctionStatus),
    C_CancelFunction: Some(C_CancelFunction),
    C_WaitForSlotEvent: Some(C_WaitForSlotEvent),
};

#[no_mangle]
pub extern "C" fn C_GetFunctionList(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    eprintln!("C_GetFunctionList");
    unsafe {
        *ppFunctionList = &FUNCTION_LIST;
    }
    CKR_OK
}